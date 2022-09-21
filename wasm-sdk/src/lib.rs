use std::convert::TryFrom;
use std::convert::TryInto;

use mc_account_keys::{AccountKey, PublicAddress, RootIdentity};
use mc_crypto_keys::RistrettoPublic;
use mc_transaction_core::CompressedCommitment;
use mc_transaction_core::ring_ct::{SignatureRctBulletproofs, SigningData};
use mc_transaction_core::ring_signature::{ReducedTxOut, RingMLSAG};
use mc_transaction_core::tx::Tx;
use mc_transaction_core::validation::validate_signature;
use mc_util_from_random::FromRandom;
use serde_derive::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

use crate::data_types::tx_proposal::{InputTxo, TxProposal, UnsignedTxProposal};
use crate::data_types::tx_proposal_json::{TxProposalJSON, UnsignedTxProposalJSON};
use crate::util::encoding_helpers::{hex_to_ristretto, hex_to_ristretto_public,
                                    ristretto_public_to_hex, ristretto_to_hex,
                                    vec_to_hex};

pub mod data_types;
pub mod util;

#[wasm_bindgen]
pub struct Transaction {
    unsigned_tx_proposal: UnsignedTxProposal,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Serialize)]
pub struct SingleKey {
    pub view_private: String,
    pub spend_private: String,
    pub spend_public: String,

    pub sub_view_public: String,
    pub sub_spend_public: String,
}

#[wasm_bindgen(js_name = "getAddress")]
pub fn get_address(view_public_key: &str, spend_public_key: &str) -> Result<String, JsValue> {
    let view_public = hex_to_ristretto_public(view_public_key)
        .map_err(|err| format!("Failed to parse view_public_key: {:?}", err))?;

    let spend_public = hex_to_ristretto_public(spend_public_key)
        .map_err(|err| format!("Failed to parse spend_public_key: {:?}", err))?;

    let public_address = PublicAddress::new(
        &spend_public,
        &view_public,
    );

    let mut wrapper = mc_api::printable::PrintableWrapper::new();
    wrapper.set_public_address((&public_address).into());

    let address = wrapper
        .b58_encode()
        .map_err(|err| format!("Failed to encode address: {:?}", err))?;

    Ok(address)
}

#[wasm_bindgen(js_name = "verifySignature")]
pub fn verify_signature(
    message_js: &str,
    signature_js: JsValue,
    ring_js: JsValue,
    output_commitment_str: &str,
) -> Result<bool, JsValue> {
    let message: &[u8] = &*hex::decode(message_js)
        .map_err(|err| format!("Failed to parse message_js: {:?}", err))?;

    let signature: RingMLSAG = signature_js
        .into_serde()
        .map_err(|e| JsValue::from(format!("Failed to parse signature_js: {:?}", e)))?;

    let ring: Vec<ReducedTxOut> = ring_js
        .into_serde()
        .map_err(|e| JsValue::from(format!("Failed to parse ring_js: {:?}", e)))?;

    let o: Box<[u8; 32]> = hex::decode(output_commitment_str)
        .map_err(|err| format!("Failed to parse output_commitment_str: {:?}", err))?
        .into_boxed_slice()
        .try_into()
        .unwrap();

    let output_commitment = CompressedCommitment::from(&*o);

    Ok(signature.verify(message, &ring, &output_commitment).is_ok())
}

#[wasm_bindgen(js_name = "generateWallet")]
pub fn generate_wallet() -> Result<JsValue, JsValue> {
    let mut rng = rand::thread_rng();
    let root_id = RootIdentity::from_random(&mut rng);

    let account_key = AccountKey::from(&root_id);

    let subaddress = account_key.subaddress(0);
    let sub_view_public = subaddress.view_public_key();
    let sub_spend_public = subaddress.spend_public_key();

    let spend_public = RistrettoPublic::from(account_key.spend_private_key());

    let key = SingleKey {
        view_private: ristretto_to_hex(account_key.view_private_key()),
        spend_private: ristretto_to_hex(account_key.spend_private_key()),
        spend_public: ristretto_public_to_hex(&spend_public),
        sub_view_public: ristretto_public_to_hex(sub_view_public),
        sub_spend_public: ristretto_public_to_hex(sub_spend_public),
    };

    let result = JsValue::from_serde(&key)
        .map_err(|err| {
            JsValue::from(format!("Error converting key to json: {:?}", err))
        })?;

    Ok(result)
}

#[wasm_bindgen(js_name = "getPublicKeyFromPrivate")]
pub fn get_public_key_from_private(private_key: &str) -> Result<String, JsValue> {
    let private = hex_to_ristretto(private_key)
        .map_err(|err| format!("Failed to parse private_key: {:?}", err))?;

    let public = RistrettoPublic::from(&private);

    Ok(ristretto_public_to_hex(&public))
}

#[wasm_bindgen]
impl Transaction {
    #[wasm_bindgen(constructor)]
    pub fn new(unsigned_tx_proposal_json: JsValue) -> Result<Transaction, JsValue> {
        let json: UnsignedTxProposalJSON = unsigned_tx_proposal_json
            .into_serde()
            .map_err(|err| {
                JsValue::from(format!("Failed to parse unsigned_tx_proposal_json: {:?}", err))
            })?;

        let unsigned_tx_proposal: UnsignedTxProposal = json.try_into().unwrap();

        Ok(Self {
            unsigned_tx_proposal,
        })
    }

    #[wasm_bindgen(js_name = "getRings")]
    pub fn get_rings(&self) -> Result<JsValue, JsValue> {
        let result = JsValue::from_serde(&self.unsigned_tx_proposal.unsigned_tx.rings)
            .map_err(|err| {
                JsValue::from(format!("Error converting rings to json: {:?}", err))
            })?;

        Ok(result)
    }

    #[wasm_bindgen(js_name = "getSigningData")]
    pub fn get_signing_data(&self) -> Result<JsValue, JsValue> {
        let mut rng = rand::thread_rng();

        let sign_data = self.unsigned_tx_proposal.unsigned_tx.get_signing_data(&mut rng)
            .map_err(|err| format!("Error on get_signing_data: {:?}", err))?;

        let result = JsValue::from_serde(&sign_data)
            .map_err(|err| {
                JsValue::from(format!(
                    "Error converting get_signing_data to json: {:?}",
                    err
                ))
            })?;

        Ok(result)
    }

    #[wasm_bindgen(js_name = "getPayloadTxosPublicKeys")]
    pub fn get_payload_txos_public_keys(&self) -> Result<JsValue, JsValue> {
        let public_keys: Vec<String> = self.unsigned_tx_proposal.payload_txos
            .iter()
            .map(|txo| vec_to_hex(txo.tx_out.public_key.as_bytes()))
            .collect();

        let result = JsValue::from_serde(&public_keys)
            .map_err(|err| {
                JsValue::from(format!(
                    "Error converting public_keys to json: {:?}",
                    err
                ))
            })?;

        Ok(result)
    }

    #[wasm_bindgen(js_name = "buildSignedTransaction")]
    pub fn build_signed_transaction(
        &self,
        ring_signatures_json: JsValue,
        signing_data_json: JsValue,
    ) -> Result<JsValue, JsValue> {
        let signing_data: SigningData = signing_data_json
            .into_serde()
            .map_err(|err| {
                JsValue::from(format!("Failed to parse signing_data_json: {:?}", err))
            })?;

        let ring_signatures: Vec<RingMLSAG> = ring_signatures_json
            .into_serde()
            .map_err(|err| {
                JsValue::from(format!("Failed to parse ring_signatures_json: {:?}", err))
            })?;

        // put key image from signature to inputs
        let input_txos = self
            .unsigned_tx_proposal.unsigned_input_txos
            .iter()
            .enumerate()
            .map(|(index, txo)| {
                let key_image = ring_signatures.get(index)
                    .ok_or("Could not find key image in signatures")?;

                Ok(InputTxo {
                    tx_out: txo.tx_out.clone(),
                    subaddress_index: txo.subaddress_index,
                    key_image: key_image.key_image.clone(),
                    amount: txo.amount,
                })
            })
            .collect::<Result<Vec<InputTxo>, String>>()?;

        let signature = SignatureRctBulletproofs {
            ring_signatures,
            pseudo_output_commitments: signing_data.pseudo_output_commitments,
            range_proof_bytes: signing_data.range_proof_bytes,
            range_proofs: signing_data.range_proofs,
            pseudo_output_token_ids: signing_data.pseudo_output_token_ids,
            output_token_ids: signing_data.output_token_ids,
        };

        let tx = Tx {
            prefix: self.unsigned_tx_proposal.unsigned_tx.tx_prefix.clone(),
            signature,
        };

        let mut rng = rand::thread_rng();

        validate_signature(
            self.unsigned_tx_proposal.unsigned_tx.block_version.clone(),
            &tx,
            &mut rng)
            .map_err(|err| format!("Failed to validate tx: {:?}", err))?;

        let tx_proposal = TxProposal {
            tx,
            payload_txos: self.unsigned_tx_proposal.payload_txos.clone(),
            change_txos: self.unsigned_tx_proposal.change_txos.clone(),
            input_txos: input_txos,
        };

        let tx_proposal_json = TxProposalJSON::try_from(&tx_proposal).unwrap();

        let result = JsValue::from_serde(&tx_proposal_json).map_err(|err| {
            JsValue::from(format!(
                "Error converting tx_proposal_json to json: {:?}",
                err
            ))
        })?;

        Ok(result)
    }

    #[wasm_bindgen(js_name = "sign")]
    pub fn sign(&self, view_private_key: &str, spend_private_key: &str) -> Result<JsValue, JsValue> {
        let spend_private_key = hex_to_ristretto(spend_private_key)
            .map_err(|err| format!("Failed to parse spend_private_key: {:?}", err))?;

        let view_private_key = hex_to_ristretto(view_private_key)
            .map_err(|err| format!("Failed to parse view_private_key: {:?}", err))?;

        let account = AccountKey::new(&spend_private_key, &view_private_key);

        let tx_proposal = self.unsigned_tx_proposal.clone().sign(
            &account,
        ).map_err(|err| format!("Error on sign transaction: {:?}", err))?;

        let tx_proposal_json = TxProposalJSON::try_from(&tx_proposal).unwrap();

        let result = JsValue::from_serde(&tx_proposal_json).map_err(|err| {
            JsValue::from(format!(
                "Error converting tx_proposal_json to json: {:?}",
                err
            ))
        })?;

        Ok(result)
    }
}
