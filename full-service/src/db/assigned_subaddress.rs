// Copyright (c) 2020-2021 MobileCoin Inc.

//! A subaddress assigned to a particular contact for the purpose of tracking
//! funds received from that contact.

use crate::{
    db::{
        account::{AccountID, AccountModel},
        models::{Account, AssignedSubaddress, NewAssignedSubaddress, Txo},
        txo::TxoModel,
    },
    util::b58::b58_decode_public_address,
};

use crate::util::b58::b58_encode_public_address;

use mc_transaction_core::{
    onetime_keys::{recover_onetime_private_key, recover_public_subaddress_spend_key},
    ring_signature::KeyImage,
};

use mc_account_keys::{AccountKey, PublicAddress, ViewAccountKey};
use mc_crypto_keys::{CompressedRistrettoPublic, RistrettoPublic};
use mc_ledger_db::{Ledger, LedgerDB};

use crate::db::{Conn, WalletDbError};
use diesel::prelude::*;

pub trait AssignedSubaddressModel {
    /// Assign a subaddress to a contact.
    ///
    /// Inserts an AssignedSubaddress to the DB.
    ///
    /// # Arguments
    /// * `account_key` - An account's private keys.
    /// * `address_book_entry` -
    /// * `subaddress_index` -
    /// * `comment` -
    /// * `conn` -
    ///
    /// # Returns
    /// * public_address_b58
    fn create(
        account_key: &AccountKey,
        subaddress_index: u64,
        comment: &str,
        conn: &Conn,
    ) -> Result<String, WalletDbError>;

    fn create_for_view_only_account(
        account_key: &ViewAccountKey,
        subaddress_index: u64,
        comment: &str,
        conn: &Conn,
    ) -> Result<String, WalletDbError>;

    /// Create the next subaddress for a given account.
    ///
    /// Returns:
    /// * (public_address_b58, subaddress_index)
    fn create_next_for_account(
        account_id_hex: &str,
        comment: &str,
        ledger_db: &LedgerDB,
        conn: &Conn,
    ) -> Result<(String, i64), WalletDbError>;

    /// Get the AssignedSubaddress for a given public_address_b58
    fn get(public_address_b58: &str, conn: &Conn) -> Result<AssignedSubaddress, WalletDbError>;

    /// Get the Assigned Subaddress for a given index in an account, if it
    /// exists
    fn get_for_account_by_index(
        account_id_hex: &str,
        index: i64,
        conn: &Conn,
    ) -> Result<AssignedSubaddress, WalletDbError>;

    /// Find an AssignedSubaddress by the subaddress spend public key
    ///
    /// Returns:
    /// * (subaddress_index, public_address_b58)
    fn find_by_subaddress_spend_public_key(
        subaddress_spend_public_key: &RistrettoPublic,
        conn: &Conn,
    ) -> Result<(i64, String), WalletDbError>;

    /// List all AssignedSubaddresses for a given account.
    fn list_all(
        account_id: Option<String>,
        offset: Option<u64>,
        limit: Option<u64>,
        conn: &Conn,
    ) -> Result<Vec<AssignedSubaddress>, WalletDbError>;

    /// Delete all AssignedSubaddresses for a given account.
    fn delete_all(account_id_hex: &str, conn: &Conn) -> Result<(), WalletDbError>;

    /// Helper to get the public address out of the assigned subaddress
    fn public_address(self) -> Result<PublicAddress, WalletDbError>;
}

impl AssignedSubaddressModel for AssignedSubaddress {
    fn create(
        account_key: &AccountKey,
        subaddress_index: u64,
        comment: &str,
        conn: &Conn,
    ) -> Result<String, WalletDbError> {
        use crate::db::schema::assigned_subaddresses;

        let account_id = AccountID::from(account_key);

        let subaddress = account_key.subaddress(subaddress_index as u64);

        let subaddress_b58 = b58_encode_public_address(&subaddress)?;
        let subaddress_entry = NewAssignedSubaddress {
            public_address_b58: &subaddress_b58,
            account_id: &account_id.to_string(),
            subaddress_index: subaddress_index as i64,
            comment,
            spend_public_key: &subaddress.spend_public_key().to_bytes(),
        };

        diesel::insert_into(assigned_subaddresses::table)
            .values(&subaddress_entry)
            .execute(conn)?;

        Ok(subaddress_b58)
    }

    fn create_for_view_only_account(
        account_key: &ViewAccountKey,
        subaddress_index: u64,
        comment: &str,
        conn: &Conn,
    ) -> Result<String, WalletDbError> {
        use crate::db::schema::assigned_subaddresses;

        let account_id = AccountID::from(account_key);

        let subaddress = account_key.subaddress(subaddress_index);
        let public_address_b58 = b58_encode_public_address(&subaddress)?;

        let subaddress_entry = NewAssignedSubaddress {
            public_address_b58: &public_address_b58,
            account_id: &account_id.to_string(),
            subaddress_index: subaddress_index as i64,
            comment,
            spend_public_key: &subaddress.spend_public_key().to_bytes(),
        };

        diesel::insert_into(assigned_subaddresses::table)
            .values(&subaddress_entry)
            .execute(conn)?;

        Ok(public_address_b58)
    }

    fn create_next_for_account(
        account_id_hex: &str,
        comment: &str,
        ledger_db: &LedgerDB,
        conn: &Conn,
    ) -> Result<(String, i64), WalletDbError> {
        let account = Account::get(&AccountID(account_id_hex.to_string()), conn)?;

        if account.fog_enabled {
            return Err(WalletDbError::SubaddressesNotSupportedForFOGEnabledAccounts);
        }

        let (subaddress_b58, next_subaddress_index) = if account.view_only {
            let view_account_key: ViewAccountKey = mc_util_serial::decode(&account.account_key)?;
            let next_subaddress_index = account.next_subaddress_index(conn)?;
            let subaddress_b58 = AssignedSubaddress::create_for_view_only_account(
                &view_account_key,
                next_subaddress_index,
                comment,
                conn,
            )?;

            let subaddress = view_account_key.subaddress(next_subaddress_index);

            // Find and repair orphaned txos at this subaddress.
            let orphaned_txos =
                Txo::list_orphaned(Some(account_id_hex), None, None, None, None, None, conn)?;

            for orphaned_txo in orphaned_txos.iter() {
                let tx_out_target_key: RistrettoPublic =
                    mc_util_serial::decode(&orphaned_txo.target_key)?;
                let tx_public_key: RistrettoPublic =
                    mc_util_serial::decode(&orphaned_txo.public_key)?;

                let txo_subaddress_spk: RistrettoPublic = recover_public_subaddress_spend_key(
                    view_account_key.view_private_key(),
                    &tx_out_target_key,
                    &tx_public_key,
                );

                if txo_subaddress_spk == *subaddress.spend_public_key() {
                    // Update the account status mapping.
                    diesel::update(orphaned_txo)
                        .set((crate::db::schema::txos::subaddress_index
                            .eq(next_subaddress_index as i64),))
                        .execute(conn)?;
                }
            }

            (subaddress_b58, next_subaddress_index)
        } else {
            let account_key: AccountKey = mc_util_serial::decode(&account.account_key)?;
            let next_subaddress_index = account.next_subaddress_index(conn)?;
            let subaddress_b58 =
                AssignedSubaddress::create(&account_key, next_subaddress_index, comment, conn)?;

            let subaddress = account_key.subaddress(next_subaddress_index);

            // Find and repair orphaned txos at this subaddress.
            let orphaned_txos =
                Txo::list_orphaned(Some(account_id_hex), None, None, None, None, None, conn)?;

            for orphaned_txo in orphaned_txos.iter() {
                let tx_out_target_key: RistrettoPublic =
                    mc_util_serial::decode(&orphaned_txo.target_key)?;
                let tx_public_key: RistrettoPublic =
                    mc_util_serial::decode(&orphaned_txo.public_key)?;
                let txo_public_key = CompressedRistrettoPublic::from(tx_public_key);

                let txo_subaddress_spk: RistrettoPublic = recover_public_subaddress_spend_key(
                    account_key.view_private_key(),
                    &tx_out_target_key,
                    &tx_public_key,
                );

                if txo_subaddress_spk == *subaddress.spend_public_key() {
                    let onetime_private_key = recover_onetime_private_key(
                        &tx_public_key,
                        account_key.view_private_key(),
                        &account_key.subaddress_spend_private(next_subaddress_index),
                    );

                    let key_image = KeyImage::from(&onetime_private_key);

                    if ledger_db.contains_key_image(&key_image)? {
                        let txo_index =
                            ledger_db.get_tx_out_index_by_public_key(&txo_public_key)?;
                        let block_index = ledger_db.get_block_index_by_tx_out_index(txo_index)?;
                        diesel::update(orphaned_txo)
                            .set(
                                crate::db::schema::txos::spent_block_index
                                    .eq(Some(block_index as i64)),
                            )
                            .execute(conn)?;
                    }

                    let key_image_bytes = mc_util_serial::encode(&key_image);

                    // Update the account status mapping.
                    diesel::update(orphaned_txo)
                        .set((
                            crate::db::schema::txos::subaddress_index
                                .eq(next_subaddress_index as i64),
                            crate::db::schema::txos::key_image.eq(key_image_bytes),
                        ))
                        .execute(conn)?;
                }
            }

            (subaddress_b58, next_subaddress_index)
        };

        Ok((subaddress_b58, next_subaddress_index as i64))
    }

    fn get(public_address_b58: &str, conn: &Conn) -> Result<AssignedSubaddress, WalletDbError> {
        use crate::db::schema::assigned_subaddresses;

        let assigned_subaddress: AssignedSubaddress = match assigned_subaddresses::table
            .filter(assigned_subaddresses::public_address_b58.eq(&public_address_b58))
            .get_result::<AssignedSubaddress>(conn)
        {
            Ok(t) => t,
            // Match on NotFound to get a more informative NotFound Error
            Err(diesel::result::Error::NotFound) => {
                return Err(WalletDbError::AssignedSubaddressNotFound(
                    public_address_b58.to_string(),
                ));
            }
            Err(e) => {
                return Err(e.into());
            }
        };
        Ok(assigned_subaddress)
    }

    fn get_for_account_by_index(
        account_id_hex: &str,
        index: i64,
        conn: &Conn,
    ) -> Result<AssignedSubaddress, WalletDbError> {
        use crate::db::schema::assigned_subaddresses;

        Ok(assigned_subaddresses::table
            .filter(assigned_subaddresses::account_id.eq(account_id_hex))
            .filter(assigned_subaddresses::subaddress_index.eq(index))
            .first(conn)?)
    }

    fn find_by_subaddress_spend_public_key(
        subaddress_spend_public_key: &RistrettoPublic,
        conn: &Conn,
    ) -> Result<(i64, String), WalletDbError> {
        use crate::db::schema::assigned_subaddresses;

        let matches = assigned_subaddresses::table
            .select((
                assigned_subaddresses::subaddress_index,
                assigned_subaddresses::account_id,
            ))
            .filter(
                assigned_subaddresses::spend_public_key
                    .eq(subaddress_spend_public_key.to_bytes().to_vec()),
            )
            .load::<(i64, String)>(conn)?;

        if matches.is_empty() {
            Err(WalletDbError::AssignedSubaddressNotFound(format!(
                "{:?}",
                subaddress_spend_public_key
            )))
        } else if matches.len() > 1 {
            Err(WalletDbError::DuplicateEntries(format!(
                "{:?}",
                subaddress_spend_public_key
            )))
        } else {
            Ok(matches[0].clone())
        }
    }

    fn list_all(
        account_id: Option<String>,
        offset: Option<u64>,
        limit: Option<u64>,
        conn: &Conn,
    ) -> Result<Vec<AssignedSubaddress>, WalletDbError> {
        use crate::db::schema::assigned_subaddresses;

        let mut addresses_query = assigned_subaddresses::table.into_boxed();

        if let Some(account_id) = account_id {
            addresses_query =
                addresses_query.filter(assigned_subaddresses::account_id.eq(account_id));
        }

        if let (Some(offset), Some(limit)) = (offset, limit) {
            addresses_query = addresses_query.offset(offset as i64).limit(limit as i64);
        }

        Ok(addresses_query.load(conn)?)
    }

    fn delete_all(account_id_hex: &str, conn: &Conn) -> Result<(), WalletDbError> {
        use crate::db::schema::assigned_subaddresses;

        diesel::delete(
            assigned_subaddresses::table
                .filter(assigned_subaddresses::account_id.eq(account_id_hex)),
        )
        .execute(conn)?;
        Ok(())
    }

    fn public_address(self) -> Result<PublicAddress, WalletDbError> {
        let public_address = b58_decode_public_address(&self.public_address_b58)?;
        Ok(public_address)
    }
}
