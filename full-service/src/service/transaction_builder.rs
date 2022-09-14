// Copyright (c) 2020-2021 MobileCoin Inc.

//! A builder for transactions from the wallet. Note that we have a
//! TransactionBuilder in the MobileCoin transaction crate, but that is a lower
//! level of building, once you have already obtained all of the materials that
//! go into a transaction.
//!
//! This module, on the other hand, builds a transaction within the context of
//! the wallet.

use crate::{
    db::{
        account::{AccountID, AccountModel},
        assigned_subaddress::AssignedSubaddressModel,
        models::{Account, Txo},
        txo::TxoModel,
        Conn,
    },
    error::WalletTransactionBuilderError,
    service::transaction::TransactionMemo,
};
use mc_account_keys::PublicAddress;
use mc_common::HashSet;
use mc_crypto_ring_signature_signer::OneTimeKeyDeriveData;
use mc_fog_report_validation::FogPubkeyResolver;
use mc_ledger_db::{Ledger, LedgerDB};
use mc_transaction_core::{
    constants::RING_SIZE,
    tokens::Mob,
    tx::{TxOut, TxOutMembershipProof},
    Amount, BlockVersion, Token, TokenId,
};

use mc_transaction_std::{
    DefaultTxOutputsOrdering, InputCredentials, ReservedSubaddresses, TransactionBuilder,
    TransactionSigningData,
};
use mc_util_uri::FogUri;

use rand::{rngs::ThreadRng, Rng};
use std::{collections::BTreeMap, str::FromStr, sync::Arc};

/// Default number of blocks used for calculating transaction tombstone block
/// number.
// TODO support for making this configurable
pub const DEFAULT_NEW_TX_BLOCK_ATTEMPTS: u64 = 10;

/// A builder of transactions constructed from this wallet.
pub struct WalletTransactionBuilder<FPR: FogPubkeyResolver + 'static> {
    /// Account ID (hex-encoded) from which to construct a transaction.
    account_id_hex: String,

    /// The ledger DB.
    ledger_db: LedgerDB,

    /// Optional inputs specified to use to construct the transaction.
    inputs: Vec<Txo>,

    /// Vector of (PublicAddress, Amounts) for the recipients of this
    /// transaction.
    outlays: Vec<(PublicAddress, u64, TokenId)>,

    /// The block after which this transaction is invalid.
    tombstone: u64,

    /// The fee for the transaction.
    fee: Option<(u64, TokenId)>,

    /// The block version for the transaction
    block_version: Option<BlockVersion>,

    /// Fog resolver maker, used when constructing outputs to fog recipients.
    /// This is abstracted because in tests, we don't want to form grpc
    /// connections to fog.
    fog_resolver_factory: Arc<dyn Fn(&[FogUri]) -> Result<FPR, String> + Send + Sync>,
}

impl<FPR: FogPubkeyResolver + 'static> WalletTransactionBuilder<FPR> {
    pub fn new(
        account_id_hex: String,
        ledger_db: LedgerDB,
        fog_resolver_factory: Arc<dyn Fn(&[FogUri]) -> Result<FPR, String> + Send + Sync + 'static>,
    ) -> Self {
        WalletTransactionBuilder {
            account_id_hex,
            ledger_db,
            inputs: vec![],
            outlays: vec![],
            tombstone: 0,
            fee: None,
            block_version: None,
            fog_resolver_factory,
        }
    }

    /// Sets inputs to the txos associated with the given txo_ids. Only unspent
    /// txos are included.
    pub fn set_txos(
        &mut self,
        conn: &Conn,
        input_txo_ids: &[String],
    ) -> Result<(), WalletTransactionBuilderError> {
        let txos = Txo::select_by_id(input_txo_ids, conn)?;

        let unspent: Vec<Txo> = txos
            .iter()
            .filter(|txo| txo.spent_block_index == None)
            .cloned()
            .collect();

        if unspent.iter().map(|t| t.value as u128).sum::<u128>() > u64::MAX as u128 {
            return Err(WalletTransactionBuilderError::OutboundValueTooLarge);
        }

        self.inputs = unspent;

        Ok(())
    }

    /// Selects Txos from the account.
    pub fn select_txos(
        &mut self,
        conn: &Conn,
        max_spendable_value: Option<u64>,
    ) -> Result<(), WalletTransactionBuilderError> {
        let mut outlay_value_sum_map: BTreeMap<TokenId, u128> =
            self.outlays
                .iter()
                .fold(BTreeMap::new(), |mut acc, (_, value, token_id)| {
                    acc.entry(*token_id)
                        .and_modify(|v| *v += *value as u128)
                        .or_insert(*value as u128);
                    acc
                });

        let (fee_value, fee_token_id) = self.fee.unwrap_or((Mob::MINIMUM_FEE, Mob::ID));
        outlay_value_sum_map
            .entry(fee_token_id)
            .and_modify(|v| *v += fee_value as u128)
            .or_insert(fee_value as u128);

        for (token_id, target_value) in outlay_value_sum_map {
            if target_value > u64::MAX as u128 {
                return Err(WalletTransactionBuilderError::OutboundValueTooLarge);
            }

            let fee_value = if token_id == fee_token_id {
                fee_value
            } else {
                0
            };

            self.inputs = Txo::select_spendable_txos_for_value(
                &self.account_id_hex,
                target_value as u64,
                max_spendable_value,
                *token_id,
                fee_value,
                conn,
            )?;
        }

        Ok(())
    }

    pub fn add_recipient(
        &mut self,
        recipient: PublicAddress,
        value: u64,
        token_id: TokenId,
    ) -> Result<(), WalletTransactionBuilderError> {
        // Verify that the maximum output value of this transaction remains under
        // u64::MAX for the given Token Id
        let cur_sum = self
            .outlays
            .iter()
            .filter_map(|(_r, v, t)| {
                if *t == token_id {
                    Some(*v as u128)
                } else {
                    None
                }
            })
            .sum::<u128>();
        if cur_sum > u64::MAX as u128 {
            return Err(WalletTransactionBuilderError::OutboundValueTooLarge);
        }
        self.outlays.push((recipient, value, token_id));
        Ok(())
    }

    pub fn set_fee(
        &mut self,
        fee: u64,
        token_id: TokenId,
    ) -> Result<(), WalletTransactionBuilderError> {
        if fee < 1 {
            return Err(WalletTransactionBuilderError::InsufficientFee(
                "1".to_string(),
            ));
        }
        self.fee = Some((fee, token_id));
        Ok(())
    }

    pub fn set_block_version(&mut self, block_version: BlockVersion) {
        self.block_version = Some(block_version);
    }

    pub fn set_tombstone(&mut self, tombstone: u64) -> Result<(), WalletTransactionBuilderError> {
        let tombstone_block = if tombstone > 0 {
            tombstone
        } else {
            let num_blocks_in_ledger = self.ledger_db.num_blocks()?;
            num_blocks_in_ledger + DEFAULT_NEW_TX_BLOCK_ATTEMPTS
        };
        self.tombstone = tombstone_block;
        Ok(())
    }

    pub fn get_fog_resolver(&self, conn: &Conn) -> Result<FPR, WalletTransactionBuilderError> {
        let account = Account::get(&AccountID(self.account_id_hex.clone()), conn)?;
        let change_subaddress = account.change_subaddress(conn)?;
        let change_public_address = change_subaddress.public_address()?;

        let fog_resolver = {
            let fog_uris = core::slice::from_ref(&change_public_address)
                .iter()
                .chain(self.outlays.iter().map(|(receiver, _, _)| receiver))
                .filter_map(|x| extract_fog_uri(x).transpose())
                .collect::<Result<Vec<_>, _>>()?;
            (self.fog_resolver_factory)(&fog_uris)
                .map_err(WalletTransactionBuilderError::FogPubkeyResolver)?
        };

        Ok(fog_resolver)
    }

    pub fn build(
        &self,
        memo: TransactionMemo,
        conn: &Conn,
    ) -> Result<TransactionSigningData, WalletTransactionBuilderError> {
        let mut rng = rand::thread_rng();
        let account = Account::get(&AccountID(self.account_id_hex.clone()), conn)?;

        let view_account_key = account.view_account_key()?;
        let view_private_key = account.view_private_key()?;
        let reserved_subaddresses = ReservedSubaddresses::from(&view_account_key);

        let block_version = self.block_version.unwrap_or(BlockVersion::MAX);
        let (fee, fee_token_id) = self.fee.unwrap_or((Mob::MINIMUM_FEE, Mob::ID));
        let fee_amount = Amount::new(fee, fee_token_id);
        let fog_resolver = self.get_fog_resolver(conn)?;
        let memo_builder = memo.memo_builder(account.account_key()?)?;

        let mut transaction_builder = TransactionBuilder::new_with_box(
            block_version,
            fee_amount,
            fog_resolver,
            memo_builder,
        )?;

        transaction_builder.set_tombstone_block(self.tombstone);

        if self.tombstone == 0 {
            return Err(WalletTransactionBuilderError::TombstoneNotSet);
        }

        if self.inputs.is_empty() {
            return Err(WalletTransactionBuilderError::NoInputs);
        }

        // Get membership proofs for our inputs
        let indexes = self
            .inputs
            .iter()
            .map(|utxo| {
                let txo: TxOut = mc_util_serial::decode(&utxo.txo)?;
                self.ledger_db.get_tx_out_index_by_hash(&txo.hash())
            })
            .collect::<Result<Vec<u64>, mc_ledger_db::Error>>()?;
        let proofs = self.ledger_db.get_tx_out_proof_of_memberships(&indexes)?;

        let inputs_and_proofs: Vec<(Txo, TxOutMembershipProof)> = self
            .inputs
            .clone()
            .into_iter()
            .zip(proofs.into_iter())
            .collect();

        let excluded_tx_out_indices: Vec<u64> = inputs_and_proofs
            .iter()
            .map(|(utxo, _membership_proof)| {
                let txo: TxOut = mc_util_serial::decode(&utxo.txo)?;
                self.ledger_db
                    .get_tx_out_index_by_hash(&txo.hash())
                    .map_err(WalletTransactionBuilderError::LedgerDB)
            })
            .collect::<Result<Vec<u64>, WalletTransactionBuilderError>>()?;

        let rings = self.get_rings(inputs_and_proofs.len(), &excluded_tx_out_indices)?;

        if rings.len() != inputs_and_proofs.len() {
            return Err(WalletTransactionBuilderError::RingSizeMismatch);
        }

        if self.outlays.is_empty() {
            return Err(WalletTransactionBuilderError::NoRecipient);
        }

        // Unzip each vec of tuples into a tuple of vecs.
        let mut rings_and_proofs: Vec<(Vec<TxOut>, Vec<TxOutMembershipProof>)> = rings
            .into_iter()
            .map(|tuples| tuples.into_iter().unzip())
            .collect();

        for (utxo, proof) in inputs_and_proofs.iter() {
            let db_tx_out: TxOut = mc_util_serial::decode(&utxo.txo)?;
            let (mut ring, mut membership_proofs) = rings_and_proofs
                .pop()
                .ok_or(WalletTransactionBuilderError::RingsAndProofsEmpty)?;
            if ring.len() != membership_proofs.len() {
                return Err(WalletTransactionBuilderError::RingSizeMismatch);
            }

            // Add the input to the ring.
            let position_opt = ring.iter().position(|txo| *txo == db_tx_out);
            let real_index = match position_opt {
                Some(position) => {
                    // The input is already present in the ring.
                    // This could happen if ring elements are sampled
                    // randomly from the ledger.
                    position
                }
                None => {
                    // The input is not already in the ring.
                    if ring.is_empty() {
                        // Append the input and its proof of membership.
                        ring.push(db_tx_out.clone());
                        membership_proofs.push(proof.clone());
                    } else {
                        // Replace the first element of the ring.
                        ring[0] = db_tx_out.clone();
                        membership_proofs[0] = proof.clone();
                    }
                    // The real input is always the first element. This is
                    // safe because TransactionBuilder sorts each ring.
                    0
                }
            };

            if ring.len() != membership_proofs.len() {
                return Err(WalletTransactionBuilderError::RingSizeMismatch);
            }

            let onetime_key_derive_data = OneTimeKeyDeriveData::SubaddressIndex(
                utxo.subaddress_index.unwrap_or_default() as u64,
            );
            let input_credentials = InputCredentials::new(
                ring,
                membership_proofs,
                real_index,
                onetime_key_derive_data,
                view_private_key,
            )?;

            transaction_builder.add_input(input_credentials);
        }

        let mut total_value_per_token = BTreeMap::new();
        total_value_per_token.insert(fee_token_id, fee);

        for (receiver, amount, token_id) in self.outlays.clone().into_iter() {
            total_value_per_token
                .entry(token_id)
                .and_modify(|value| *value += amount)
                .or_insert(amount);

            let amount = Amount::new(amount, token_id);
            transaction_builder.add_output(amount, &receiver, &mut rng)?;
        }

        let input_value_per_token =
            inputs_and_proofs
                .iter()
                .fold(BTreeMap::new(), |mut acc, (utxo, _proof)| {
                    acc.entry(TokenId::from(utxo.token_id as u64))
                        .and_modify(|value| *value += utxo.value as u64)
                        .or_insert(utxo.value as u64);
                    acc
                });

        for (token_id, input_value) in input_value_per_token {
            let total_value = total_value_per_token.get(&token_id).ok_or_else(|| {
                WalletTransactionBuilderError::MissingInputsForTokenId(token_id.to_string())
            })?;

            println!("total_value: {}", total_value);
            println!("input_value: {}", input_value);
            let change_value = input_value - *total_value;
            println!("change_value: {}", change_value);
            let change_amount = Amount::new(change_value, token_id);
            transaction_builder.add_change_output(
                change_amount,
                &reserved_subaddresses,
                &mut rng,
            )?;
        }

        Ok(
            transaction_builder
                .get_signing_data::<ThreadRng, DefaultTxOutputsOrdering>(&mut rng)?,
        )
    }

    /// Get rings.
    fn get_rings(
        &self,
        num_rings: usize,
        excluded_tx_out_indices: &[u64],
    ) -> Result<Vec<Vec<(TxOut, TxOutMembershipProof)>>, WalletTransactionBuilderError> {
        let num_requested = RING_SIZE * num_rings;
        let num_txos = self.ledger_db.num_txos()?;

        // Check that the ledger contains enough tx outs.
        if excluded_tx_out_indices.len() as u64 > num_txos {
            return Err(WalletTransactionBuilderError::InvalidArgument(
                "excluded_tx_out_indices exceeds amount of tx outs in ledger".to_string(),
            ));
        }

        if num_requested > (num_txos as usize - excluded_tx_out_indices.len()) {
            return Err(WalletTransactionBuilderError::InsufficientTxOuts);
        }

        // Randomly sample `num_requested` TxOuts, without replacement and convert into
        // a Vec<u64>
        let mut rng = rand::thread_rng();
        let mut sampled_indices: HashSet<u64> = HashSet::default();
        while sampled_indices.len() < num_requested {
            let index = rng.gen_range(0..num_txos);
            if excluded_tx_out_indices.contains(&index) {
                continue;
            }
            sampled_indices.insert(index);
        }
        let sampled_indices_vec: Vec<u64> = sampled_indices.into_iter().collect();

        // Get proofs for all of those indexes.
        let proofs = self
            .ledger_db
            .get_tx_out_proof_of_memberships(&sampled_indices_vec)?;

        // Create an iterator that returns (index, proof) elements.
        let mut indexes_and_proofs_iterator =
            sampled_indices_vec.into_iter().zip(proofs.into_iter());

        // Convert that into a Vec<Vec<TxOut, TxOutMembershipProof>>
        let mut rings_with_proofs = Vec::new();

        for _ in 0..num_rings {
            let mut ring = Vec::new();
            for _ in 0..RING_SIZE {
                let (index, proof) = indexes_and_proofs_iterator.next().unwrap();
                let tx_out = self.ledger_db.get_tx_out_by_index(index)?;

                ring.push((tx_out, proof));
            }
            rings_with_proofs.push(ring);
        }

        Ok(rings_with_proofs)
    }
}

// Helper which extracts FogUri from PublicAddress or returns None, or returns
// an error
fn extract_fog_uri(addr: &PublicAddress) -> Result<Option<FogUri>, WalletTransactionBuilderError> {
    if let Some(string) = addr.fog_report_url() {
        Ok(Some(FogUri::from_str(string)?))
    } else {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        db::WalletDbError,
        service::{models::tx_proposal::TxProposal, sync::SyncThread},
        test_utils::{
            builder_for_random_recipient, get_test_ledger, random_account_with_seed_values,
            WalletDbTestContext, MOB,
        },
    };
    use mc_account_keys::AccountKey;
    use mc_common::logger::{test_with_logger, Logger};
    use mc_crypto_ring_signature_signer::LocalRingSigner;
    use rand::{rngs::StdRng, SeedableRng};

    #[test_with_logger]
    fn test_build_with_utxos(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([20u8; 32]);

        let db_test_context = WalletDbTestContext::default();
        let wallet_db = db_test_context.get_db_instance(logger.clone());
        let known_recipients: Vec<PublicAddress> = Vec::new();
        let mut ledger_db = get_test_ledger(5, &known_recipients, 12, &mut rng);

        // Start sync thread
        let _sync_thread = SyncThread::start(ledger_db.clone(), wallet_db.clone(), logger.clone());

        let account_key = random_account_with_seed_values(
            &wallet_db,
            &mut ledger_db,
            &vec![11 * MOB, 11 * MOB, 11 * MOB, 111111 * MOB],
            &mut rng,
            &logger,
        );

        // Construct a transaction
        let conn = wallet_db.get_conn().unwrap();
        let (recipient, mut builder) =
            builder_for_random_recipient(&account_key, &ledger_db, &mut rng);

        // Send value specifically for your smallest Txo size. Should take 2 inputs
        // and also make change.
        let value = 11 * MOB;
        builder
            .add_recipient(recipient.clone(), value, Mob::ID)
            .unwrap();

        // Select the txos for the recipient
        builder.select_txos(&conn, None).unwrap();
        builder.set_tombstone(0).unwrap();

        let signing_data = builder.build(TransactionMemo::RTH, &conn).unwrap();
        let signer = LocalRingSigner::from(&account_key);
        let tx = signing_data.sign(&signer, &mut rng).unwrap();
        let proposal = TxProposal::new(tx, signing_data);
        assert_eq!(proposal.payload_txos.len(), 1);
        assert_eq!(proposal.payload_txos[0].recipient_public_address, recipient);
        assert_eq!(proposal.payload_txos[0].amount.value, value);
        assert_eq!(proposal.tx.prefix.inputs.len(), 2);
        assert_eq!(proposal.tx.prefix.fee, Mob::MINIMUM_FEE);
        assert_eq!(proposal.tx.prefix.outputs.len(), 2);
    }

    // Test that large values are handled correctly.
    #[test_with_logger]
    fn test_big_values(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([20u8; 32]);

        let db_test_context = WalletDbTestContext::default();
        let wallet_db = db_test_context.get_db_instance(logger.clone());
        let known_recipients: Vec<PublicAddress> = Vec::new();
        let mut ledger_db = get_test_ledger(5, &known_recipients, 12, &mut rng);

        // Start sync thread
        let _sync_thread = SyncThread::start(ledger_db.clone(), wallet_db.clone(), logger.clone());

        // Give ourselves enough MOB that we have more than u64::MAX, 18_446_745 MOB
        let account_key = random_account_with_seed_values(
            &wallet_db,
            &mut ledger_db,
            &vec![7_000_000 * MOB, 7_000_000 * MOB, 7_000_000 * MOB],
            &mut rng,
            &logger,
        );

        // Check balance
        let unspent = Txo::list_unspent(
            Some(&AccountID::from(&account_key).to_string()),
            None,
            Some(0),
            None,
            None,
            None,
            None,
            &wallet_db.get_conn().unwrap(),
        )
        .unwrap();
        let balance: u128 = unspent.iter().map(|t| t.value as u128).sum::<u128>();
        assert_eq!(balance, 21_000_000 * MOB as u128);

        // Now try to send a transaction with a value > u64::MAX
        let conn = wallet_db.get_conn().unwrap();
        let (recipient, mut builder) =
            builder_for_random_recipient(&account_key, &ledger_db, &mut rng);

        let value = u64::MAX;
        builder
            .add_recipient(recipient.clone(), value, Mob::ID)
            .unwrap();

        // Select the txos for the recipient - should error because > u64::MAX
        match builder.select_txos(&conn, None) {
            Ok(_) => panic!("Should not be allowed to construct outbound values > u64::MAX"),
            Err(WalletTransactionBuilderError::OutboundValueTooLarge) => {}
            Err(e) => panic!("Unexpected error {:?}", e),
        }
    }

    // Users should be able to set the txos specifically that they want to send
    #[test_with_logger]
    fn test_setting_txos(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([20u8; 32]);

        let db_test_context = WalletDbTestContext::default();
        let wallet_db = db_test_context.get_db_instance(logger.clone());
        let known_recipients: Vec<PublicAddress> = Vec::new();
        let mut ledger_db = get_test_ledger(5, &known_recipients, 12, &mut rng);

        // Start sync thread
        let _sync_thread = SyncThread::start(ledger_db.clone(), wallet_db.clone(), logger.clone());

        let account_key = random_account_with_seed_values(
            &wallet_db,
            &mut ledger_db,
            &vec![70 * MOB, 80 * MOB, 90 * MOB],
            &mut rng,
            &logger,
        );

        // Get our TXO list
        let txos: Vec<Txo> = Txo::list_for_account(
            &AccountID::from(&account_key).to_string(),
            None,
            None,
            None,
            None,
            None,
            Some(0),
            &wallet_db.get_conn().unwrap(),
        )
        .unwrap();

        let conn = wallet_db.get_conn().unwrap();
        let (recipient, mut builder) =
            builder_for_random_recipient(&account_key, &ledger_db, &mut rng);

        // Setting value to exactly the input will fail because you need funds for fee
        builder
            .add_recipient(recipient.clone(), txos[0].value as u64, Mob::ID)
            .unwrap();

        builder.set_txos(&conn, &vec![txos[0].id.clone()]).unwrap();
        builder.set_tombstone(0).unwrap();
        match builder.build(TransactionMemo::RTH, &conn) {
            Ok(_) => {
                panic!("Should not be able to construct Tx with > inputs value as output value")
            }
            Err(WalletTransactionBuilderError::InsufficientInputFunds(_)) => {}
            Err(e) => panic!("Unexpected error {:?}", e),
        }

        // Now build, setting to multiple TXOs
        let (recipient, mut builder) =
            builder_for_random_recipient(&account_key, &ledger_db, &mut rng);

        // Set value to just slightly more than what fits in the one TXO
        builder
            .add_recipient(recipient.clone(), txos[0].value as u64 + 10, Mob::ID)
            .unwrap();

        builder
            .set_txos(&conn, &vec![txos[0].id.clone(), txos[1].id.clone()])
            .unwrap();
        builder.set_tombstone(0).unwrap();
        let signing_data = builder.build(TransactionMemo::RTH, &conn).unwrap();
        let signer = LocalRingSigner::from(&account_key);
        let tx = signing_data.sign(&signer, &mut rng).unwrap();
        let proposal = TxProposal::new(tx, signing_data);
        assert_eq!(proposal.payload_txos.len(), 1);
        assert_eq!(proposal.payload_txos[0].recipient_public_address, recipient);
        assert_eq!(
            proposal.payload_txos[0].amount.value,
            txos[0].value as u64 + 10
        );
        assert_eq!(proposal.tx.prefix.inputs.len(), 2); // need one more for fee
        assert_eq!(proposal.tx.prefix.fee, Mob::MINIMUM_FEE);
        assert_eq!(proposal.tx.prefix.outputs.len(), 2); // self and change
    }

    // Test max_spendable correctly filters out txos above max_spendable
    #[test_with_logger]
    fn test_max_spendable(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([20u8; 32]);

        let db_test_context = WalletDbTestContext::default();
        let wallet_db = db_test_context.get_db_instance(logger.clone());
        let known_recipients: Vec<PublicAddress> = Vec::new();
        let mut ledger_db = get_test_ledger(5, &known_recipients, 12, &mut rng);

        // Start sync thread
        let _sync_thread = SyncThread::start(ledger_db.clone(), wallet_db.clone(), logger.clone());

        let account_key = random_account_with_seed_values(
            &wallet_db,
            &mut ledger_db,
            &vec![70 * MOB, 80 * MOB, 90 * MOB],
            &mut rng,
            &logger,
        );

        let conn = wallet_db.get_conn().unwrap();
        let (recipient, mut builder) =
            builder_for_random_recipient(&account_key, &ledger_db, &mut rng);

        // Setting value to exactly the input will fail because you need funds for fee
        builder
            .add_recipient(recipient.clone(), 80 * MOB, Mob::ID)
            .unwrap();

        // Test that selecting Txos with max_spendable < all our txo values fails
        match builder.select_txos(&conn, Some(10)) {
            Ok(_) => panic!("Should not be able to construct tx when max_spendable < all txos"),
            Err(WalletTransactionBuilderError::WalletDb(WalletDbError::NoSpendableTxos)) => {}
            Err(e) => panic!("Unexpected error {:?}", e),
        }

        // We should be able to try again, with max_spendable at 70, but will not hit
        // our outlay target (80 * MOB)
        match builder.select_txos(&conn, Some(70 * MOB)) {
            Ok(_) => panic!("Should not be able to construct tx when max_spendable < all txos"),
            Err(WalletTransactionBuilderError::WalletDb(
                WalletDbError::InsufficientFundsUnderMaxSpendable(_),
            )) => {}
            Err(e) => panic!("Unexpected error {:?}", e),
        }

        // Now, we should succeed if we set max_spendable = 80 * MOB, because we will
        // pick up both 70 and 80
        builder.select_txos(&conn, Some(80 * MOB)).unwrap();
        builder.set_tombstone(0).unwrap();
        let signing_data = builder.build(TransactionMemo::RTH, &conn).unwrap();
        let signer = LocalRingSigner::from(&account_key);
        let tx = signing_data.sign(&signer, &mut rng).unwrap();
        let proposal = TxProposal::new(tx, signing_data);
        assert_eq!(proposal.payload_txos.len(), 1);
        assert_eq!(proposal.payload_txos[0].recipient_public_address, recipient);
        assert_eq!(proposal.payload_txos[0].amount.value, 80 * MOB);
        assert_eq!(proposal.tx.prefix.inputs.len(), 2); // uses both 70 and 80
        assert_eq!(proposal.tx.prefix.fee, Mob::MINIMUM_FEE);
        assert_eq!(proposal.tx.prefix.outputs.len(), 2); // self and change
    }

    // Test setting and not setting tombstone block
    #[test_with_logger]
    fn test_tombstone(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([20u8; 32]);

        let db_test_context = WalletDbTestContext::default();
        let wallet_db = db_test_context.get_db_instance(logger.clone());
        let known_recipients: Vec<PublicAddress> = Vec::new();
        let mut ledger_db = get_test_ledger(5, &known_recipients, 12, &mut rng);
        let conn = wallet_db.get_conn().unwrap();

        // Start sync thread
        let _sync_thread = SyncThread::start(ledger_db.clone(), wallet_db.clone(), logger.clone());

        let account_key = random_account_with_seed_values(
            &wallet_db,
            &mut ledger_db,
            &vec![70 * MOB],
            &mut rng,
            &logger,
        );

        let (recipient, mut builder) =
            builder_for_random_recipient(&account_key, &ledger_db, &mut rng);

        builder
            .add_recipient(recipient.clone(), 10 * MOB, Mob::ID)
            .unwrap();
        builder.select_txos(&conn, None).unwrap();

        // Sanity check that our ledger is the height we think it is
        assert_eq!(ledger_db.num_blocks().unwrap(), 13);

        // We must set tombstone block before building
        match builder.build(TransactionMemo::RTH, &conn) {
            Ok(_) => panic!("Expected TombstoneNotSet error"),
            Err(WalletTransactionBuilderError::TombstoneNotSet) => {}
            Err(e) => panic!("Unexpected error {:?}", e),
        }

        let (recipient, mut builder) =
            builder_for_random_recipient(&account_key, &ledger_db, &mut rng);

        builder
            .add_recipient(recipient.clone(), 10 * MOB, Mob::ID)
            .unwrap();
        builder.select_txos(&conn, None).unwrap();

        // Set to default
        builder.set_tombstone(0).unwrap();

        // Not setting the tombstone results in tombstone = 0. This is an acceptable
        // value,
        let signing_data = builder.build(TransactionMemo::RTH, &conn).unwrap();
        let signer = LocalRingSigner::from(&account_key);
        let tx = signing_data.sign(&signer, &mut rng).unwrap();
        let proposal = TxProposal::new(tx, signing_data);
        assert_eq!(proposal.tx.prefix.tombstone_block, 23);

        // Build a transaction and explicitly set tombstone
        let (recipient, mut builder) =
            builder_for_random_recipient(&account_key, &ledger_db, &mut rng);

        builder
            .add_recipient(recipient.clone(), 10 * MOB, Mob::ID)
            .unwrap();
        builder.select_txos(&conn, None).unwrap();

        // Set to default
        builder.set_tombstone(20).unwrap();

        // Not setting the tombstone results in tombstone = 0. This is an acceptable
        // value,
        let signing_data = builder.build(TransactionMemo::RTH, &conn).unwrap();
        let signer = LocalRingSigner::from(&account_key);
        let tx = signing_data.sign(&signer, &mut rng).unwrap();
        let proposal = TxProposal::new(tx, signing_data);
        assert_eq!(proposal.tx.prefix.tombstone_block, 20);
    }

    // Test setting and not setting the fee
    #[test_with_logger]
    fn test_fee(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([20u8; 32]);

        let db_test_context = WalletDbTestContext::default();
        let wallet_db = db_test_context.get_db_instance(logger.clone());
        let known_recipients: Vec<PublicAddress> = Vec::new();
        let mut ledger_db = get_test_ledger(5, &known_recipients, 12, &mut rng);

        // Start sync thread
        let _sync_thread = SyncThread::start(ledger_db.clone(), wallet_db.clone(), logger.clone());

        let account_key = random_account_with_seed_values(
            &wallet_db,
            &mut ledger_db,
            &vec![70 * MOB],
            &mut rng,
            &logger,
        );

        let conn = wallet_db.get_conn().unwrap();
        let (recipient, mut builder) =
            builder_for_random_recipient(&account_key, &ledger_db, &mut rng);

        builder
            .add_recipient(recipient.clone(), 10 * MOB, Mob::ID)
            .unwrap();
        builder.select_txos(&conn, None).unwrap();
        builder.set_tombstone(0).unwrap();

        // Verify that not setting fee results in default fee
        let signing_data = builder.build(TransactionMemo::RTH, &conn).unwrap();
        let signer = LocalRingSigner::from(&account_key);
        let tx = signing_data.sign(&signer, &mut rng).unwrap();
        let proposal = TxProposal::new(tx, signing_data);
        assert_eq!(proposal.tx.prefix.fee, Mob::MINIMUM_FEE);

        // You cannot set fee to 0
        let (recipient, mut builder) =
            builder_for_random_recipient(&account_key, &ledger_db, &mut rng);

        builder
            .add_recipient(recipient.clone(), 10 * MOB, Mob::ID)
            .unwrap();
        builder.select_txos(&conn, None).unwrap();
        builder.set_tombstone(0).unwrap();
        match builder.set_fee(0, Mob::ID) {
            Ok(_) => panic!("Should not be able to set fee to 0"),
            Err(WalletTransactionBuilderError::InsufficientFee(_)) => {}
            Err(e) => panic!("Unexpected error {:?}", e),
        }

        // Verify that not setting fee results in default fee
        let signing_data = builder.build(TransactionMemo::RTH, &conn).unwrap();
        let signer = LocalRingSigner::from(&account_key);
        let tx = signing_data.sign(&signer, &mut rng).unwrap();
        let proposal = TxProposal::new(tx, signing_data);
        assert_eq!(proposal.tx.prefix.fee, Mob::MINIMUM_FEE);

        // Setting fee less than minimum fee should fail
        let (recipient, mut builder) =
            builder_for_random_recipient(&account_key, &ledger_db, &mut rng);

        builder
            .add_recipient(recipient.clone(), 10 * MOB, Mob::ID)
            .unwrap();
        builder.select_txos(&conn, None).unwrap();
        builder.set_tombstone(0).unwrap();
        match builder.set_fee(0, Mob::ID) {
            Ok(_) => panic!("Should not be able to set fee to 0"),
            Err(WalletTransactionBuilderError::InsufficientFee(_)) => {}
            Err(e) => panic!("Unexpected error {:?}", e),
        }

        // Setting fee greater than MINIMUM_FEE works
        let (recipient, mut builder) =
            builder_for_random_recipient(&account_key, &ledger_db, &mut rng);

        builder
            .add_recipient(recipient.clone(), 10 * MOB, Mob::ID)
            .unwrap();
        builder.select_txos(&conn, None).unwrap();
        builder.set_tombstone(0).unwrap();
        builder.set_fee(Mob::MINIMUM_FEE * 10, Mob::ID).unwrap();
        let signing_data = builder.build(TransactionMemo::RTH, &conn).unwrap();
        let signer = LocalRingSigner::from(&account_key);
        let tx = signing_data.sign(&signer, &mut rng).unwrap();
        let proposal = TxProposal::new(tx, signing_data);
        assert_eq!(proposal.tx.prefix.fee, Mob::MINIMUM_FEE * 10);
    }

    // Even if change is zero, we should still have a change output
    #[test_with_logger]
    fn test_change_zero_mob(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([20u8; 32]);

        let db_test_context = WalletDbTestContext::default();
        let wallet_db = db_test_context.get_db_instance(logger.clone());
        let known_recipients: Vec<PublicAddress> = Vec::new();
        let mut ledger_db = get_test_ledger(5, &known_recipients, 12, &mut rng);

        // Start sync thread
        let _sync_thread = SyncThread::start(ledger_db.clone(), wallet_db.clone(), logger.clone());

        let account_key = random_account_with_seed_values(
            &wallet_db,
            &mut ledger_db,
            &vec![70 * MOB],
            &mut rng,
            &logger,
        );

        let conn = wallet_db.get_conn().unwrap();
        let (recipient, mut builder) =
            builder_for_random_recipient(&account_key, &ledger_db, &mut rng);

        // Set value to consume the whole TXO and not produce change
        let value = 70 * MOB - Mob::MINIMUM_FEE;
        builder
            .add_recipient(recipient.clone(), value, Mob::ID)
            .unwrap();
        builder.select_txos(&conn, None).unwrap();
        builder.set_tombstone(0).unwrap();

        // Verify that not setting fee results in default fee
        let signing_data = builder.build(TransactionMemo::RTH, &conn).unwrap();
        let signer = LocalRingSigner::from(&account_key);
        let tx = signing_data.sign(&signer, &mut rng).unwrap();
        let proposal = TxProposal::new(tx, signing_data);

        assert_eq!(proposal.tx.prefix.fee, Mob::MINIMUM_FEE);
        assert_eq!(proposal.payload_txos.len(), 1);
        assert_eq!(proposal.payload_txos[0].recipient_public_address, recipient);
        assert_eq!(proposal.payload_txos[0].amount.value, value);
        assert_eq!(proposal.tx.prefix.inputs.len(), 1); // uses just one input
        assert_eq!(proposal.tx.prefix.outputs.len(), 2); // two outputs to
                                                         // self
    }

    // We should be able to add multiple TxOuts to the same recipient, not to
    // multiple
    #[test_with_logger]
    fn test_add_multiple_outputs_to_same_recipient(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([20u8; 32]);

        let db_test_context = WalletDbTestContext::default();
        let wallet_db = db_test_context.get_db_instance(logger.clone());
        let known_recipients: Vec<PublicAddress> = Vec::new();
        let mut ledger_db = get_test_ledger(5, &known_recipients, 12, &mut rng);

        // Start sync thread
        let _sync_thread = SyncThread::start(ledger_db.clone(), wallet_db.clone(), logger.clone());

        let account_key = random_account_with_seed_values(
            &wallet_db,
            &mut ledger_db,
            &vec![70 * MOB, 80 * MOB, 90 * MOB],
            &mut rng,
            &logger,
        );

        let conn = wallet_db.get_conn().unwrap();
        let (recipient, mut builder) =
            builder_for_random_recipient(&account_key, &ledger_db, &mut rng);

        builder
            .add_recipient(recipient.clone(), 10 * MOB, Mob::ID)
            .unwrap();
        builder
            .add_recipient(recipient.clone(), 20 * MOB, Mob::ID)
            .unwrap();
        builder
            .add_recipient(recipient.clone(), 30 * MOB, Mob::ID)
            .unwrap();
        builder
            .add_recipient(recipient.clone(), 40 * MOB, Mob::ID)
            .unwrap();

        builder.select_txos(&conn, None).unwrap();
        builder.set_tombstone(0).unwrap();

        let signing_data = builder.build(TransactionMemo::RTH, &conn).unwrap();
        let signer = LocalRingSigner::from(&account_key);
        let tx = signing_data.sign(&signer, &mut rng).unwrap();
        let proposal = TxProposal::new(tx, signing_data);

        assert_eq!(proposal.tx.prefix.fee, Mob::MINIMUM_FEE);
        assert_eq!(proposal.payload_txos.len(), 4);
        assert_eq!(proposal.payload_txos[0].recipient_public_address, recipient);
        assert_eq!(proposal.payload_txos[0].amount.value, 10 * MOB);
        assert_eq!(proposal.payload_txos[1].recipient_public_address, recipient);
        assert_eq!(proposal.payload_txos[1].amount.value, 20 * MOB);
        assert_eq!(proposal.payload_txos[2].recipient_public_address, recipient);
        assert_eq!(proposal.payload_txos[2].amount.value, 30 * MOB);
        assert_eq!(proposal.payload_txos[3].recipient_public_address, recipient);
        assert_eq!(proposal.payload_txos[3].amount.value, 40 * MOB);
        assert_eq!(proposal.tx.prefix.inputs.len(), 2);
        assert_eq!(proposal.tx.prefix.outputs.len(), 5); // outlays + change
    }

    // Adding multiple values that exceed u64::MAX should fail
    #[test_with_logger]
    fn test_add_multiple_outputs_integer_overflow(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([20u8; 32]);

        let db_test_context = WalletDbTestContext::default();
        let wallet_db = db_test_context.get_db_instance(logger.clone());
        let known_recipients: Vec<PublicAddress> = Vec::new();
        let mut ledger_db = get_test_ledger(5, &known_recipients, 12, &mut rng);

        // Start sync thread
        let _sync_thread = SyncThread::start(ledger_db.clone(), wallet_db.clone(), logger.clone());

        let account_key = random_account_with_seed_values(
            &wallet_db,
            &mut ledger_db,
            &vec![
                7_000_000 * MOB,
                7_000_000 * MOB,
                7_000_000 * MOB,
                7_000_000 * MOB,
            ],
            &mut rng,
            &logger,
        );

        let (recipient, mut builder) =
            builder_for_random_recipient(&account_key, &ledger_db, &mut rng);

        builder
            .add_recipient(recipient.clone(), 7_000_000 * MOB, Mob::ID)
            .unwrap();
        builder
            .add_recipient(recipient.clone(), 7_000_000 * MOB, Mob::ID)
            .unwrap();
        builder
            .add_recipient(recipient.clone(), 7_000_000 * MOB, Mob::ID)
            .unwrap();

        match builder.select_txos(&wallet_db.get_conn().unwrap(), None) {
            Ok(_) => panic!("Should not be able to select txos with > u64::MAX output value"),
            Err(WalletTransactionBuilderError::OutboundValueTooLarge) => {}
            Err(e) => panic!("Unexpected error {:?}", e),
        }
    }

    // We should be able to add multiple TxOuts to multiple recipients.
    #[test_with_logger]
    fn test_add_multiple_recipients(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([20u8; 32]);

        let db_test_context = WalletDbTestContext::default();
        let wallet_db = db_test_context.get_db_instance(logger.clone());
        let known_recipients: Vec<PublicAddress> = Vec::new();
        let mut ledger_db = get_test_ledger(5, &known_recipients, 12, &mut rng);

        // Start sync thread
        let _sync_thread = SyncThread::start(ledger_db.clone(), wallet_db.clone(), logger.clone());

        let account_key = random_account_with_seed_values(
            &wallet_db,
            &mut ledger_db,
            &vec![70 * MOB, 80 * MOB, 90 * MOB],
            &mut rng,
            &logger,
        );

        let (recipient, mut builder) =
            builder_for_random_recipient(&account_key, &ledger_db, &mut rng);

        builder
            .add_recipient(recipient.clone(), 10 * MOB, Mob::ID)
            .unwrap();

        // Create a new recipient
        let second_recipient = AccountKey::random(&mut rng).subaddress(0);
        builder
            .add_recipient(second_recipient.clone(), 40 * MOB, Mob::ID)
            .unwrap();
    }
}
