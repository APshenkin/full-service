use std::convert::TryFrom;
use std::convert::TryInto;
use mc_util_from_random::FromRandom;

pub mod data_types;

use mc_account_keys::{AccountKey, PublicAddress, RootIdentity, ViewAccountKey};
use mc_crypto_keys::{CompressedRistrettoPublic, RistrettoPublic};
use mc_transaction_core::{BlockVersion, CompressedCommitment};
use mc_transaction_core::ring_signature::{CurveScalar, KeyImage, ReducedTxOut, RingMLSAG};
use mc_transaction_core::tx::Tx;
use mc_transaction_core::validation::validate_signature;
use wasm_bindgen::prelude::*;

use mc_full_service_core::fog_resolver::FullServiceFogResolver;
use mc_full_service_core::unsigned_tx::UnsignedTx;
use mc_full_service_core::util::encoding_helpers::{hex_to_ristretto, hex_to_ristretto_public, ristretto_public_to_hex, ristretto_to_hex};

use crate::data_types::tx_signing_data_json::{RingMemberJSON, TxSigningDataJSON, VerifySignatureJSON};
use crate::data_types::tx_proposal_json::TxProposalJSON;

use serde_derive::{Deserialize, Serialize};

#[wasm_bindgen]
pub struct Transaction {
    request: String,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Serialize)]
pub struct SingleKey {
    pub view_private: String,
    pub spend_private: String,
    pub spend_public: String,

    pub sub_view_public: String,
    pub sub_spend_public: String,
}

// #[wasm_bindgen(js_name = verify_transaction)]
// pub fn verify_transaction(verify_js: JsValue) -> Result<bool, JsValue> {
//     let json_tx: JsonTx = verify_js
//         .into_serde()
//         .map_err(|e| JsValue::from(format!("Error parsing parameters: {:?}", e)))?;
//
//     let proto = mc_api::external::Tx::try_from(&json_tx)
//         .map_err(|err| format!("Failed to parse tx: {:?}", err))?;
//
//     let tx: Tx = Tx::try_from(&proto)
//         .map_err(|err| format!("Failed to parse tx: {:?}", err))?;
//
//     let mut rng = rand::thread_rng();
//
//     let block_version: BlockVersion = BlockVersion::try_from(json_tx.block_version)
//         .map_err(|err| format!("Failed to parse block version {:?}", err))?;
//
//     validate_signature(block_version, &tx, &mut rng)
//         .map_err(|err| format!("Failed to validate tx: {:?}", err))?;
//
//     Ok(true)
// }

#[wasm_bindgen]
pub fn get_address(view_public_key: &str, spend_public_key: &str) -> Result<String, JsValue> {
    let view_public = hex_to_ristretto_public(view_public_key)
        .map_err(|err| format!("Failed to parse spend_public_key: {:?}", err))?;

    let spend_public = hex_to_ristretto_public(spend_public_key)
        .map_err(|err| format!("Failed to parse spend_public_key: {:?}", err))?;

    let public_address = PublicAddress::new(&spend_public, &view_public);

    let mut wrapper = mc_api::printable::PrintableWrapper::new();
    wrapper.set_public_address((&public_address).into());

    let address = wrapper
        .b58_encode()
        .map_err(|err| format!("Failed to encode address: {}", err))?;

    Ok(address)
}

// #[wasm_bindgen]
// pub fn verify_signature(verify_js: JsValue) -> Result<bool, JsValue> {
//     let verify: VerifySignatureJSON = verify_js
//         .into_serde()
//         .map_err(|e| JsValue::from(format!("Error parsing parameters: {}", e)))?;
//
//     let message: &[u8] = &*hex::decode(verify.message)
//         .map_err(|err| format!("Failed to parse message: {}", err))?;
//
//     let ring: Vec<ReducedTxOut> = verify.ring.iter()
//         .map(|ring| {
//             let tx_out: &RingMemberJSON = ring.members.get(ring.real_input_index)
//                 .ok_or(|err| format!("Failed to parse message: {}", err))?;
//
//             let c: Box<[u8; 32]> = hex::decode(tx_out.compressed_commitment.clone())?.into_boxed_slice().try_into()?;
//
//             Ok(ReducedTxOut {
//                 public_key: CompressedRistrettoPublic::try_from(&*hex::decode(tx_out.compressed_ristretto_public.clone())?)?,
//                 target_key: CompressedRistrettoPublic::try_from(&*hex::decode(tx_out.compressed_ristretto_target.clone())?)?,
//                 commitment: CompressedCommitment::from(&*c),
//             })
//         })
//         .collect::<Result<Vec<ReducedTxOut>, String>>()
//         .map_err(|_| "Error".to_string())?;
//
//     let o: Box<[u8; 32]> = hex::decode(verify.output_commitment)
//         .map_err(|err| format!("Failed to parse output_commitment: {}", err))?.into_boxed_slice().try_into()?;
//     let output_commitment = CompressedCommitment::from(&*o);
//
//     let c: Box<[u8; 32]> = hex::decode(verify.c_zero)
//         .map_err(|err| format!("Failed to parse c_zero: {}", err))?.into_boxed_slice().try_into()?;
//     let c_zero = CurveScalar::from(&*c);
//
//     let responses = verify.responses.iter()
//         .map(|r| {
//             let res: Box<[u8; 32]> = hex::decode(r.clone())?.into_boxed_slice().try_into()?;
//             CurveScalar::from(&*res)
//         })
//         .collect();
//
//     let k: Box<[u8; 32]> = hex::decode(verify.key_image)
//         .map_err(|err| format!("Failed to parse key_image: {}", err))?.into_boxed_slice().try_into()?;
//
//     let key_image = KeyImage::from(*k);
//
//     let signature = RingMLSAG {
//         c_zero,
//         responses,
//         key_image,
//     };
//
//     Ok(signature.verify(message, &ring, &output_commitment).is_ok())
// }

#[wasm_bindgen]
pub fn generate_default_address() -> Result<JsValue, JsValue> {
    let mut rng = rand::thread_rng();
    let root_id = RootIdentity::from_random(&mut rng);

    let account_key = AccountKey::from(&root_id);

    let subaddress = account_key.subaddress(0);
    let sub_view_public = subaddress.view_public_key();
    let sub_spend_public = subaddress.spend_public_key();

    let spend_public = RistrettoPublic::from(account_key.spend_private_key());

    let params = SingleKey {
        view_private: ristretto_to_hex(account_key.view_private_key()),
        spend_private: ristretto_to_hex(account_key.spend_private_key()),
        spend_public: ristretto_public_to_hex(&spend_public),
        sub_view_public: ristretto_public_to_hex(sub_view_public),
        sub_spend_public: ristretto_public_to_hex(sub_spend_public),
    };

    let params_value = JsValue::from_serde(&params).map_err(|e| {
        JsValue::from(format!(
            "Error converting constructor parameters to json object: {}",
            e
        ))
    })?;

    Ok(params_value)
}

#[wasm_bindgen]
pub fn get_public_address(private_key: &str) -> Result<String, JsValue> {
    let private = hex_to_ristretto(private_key)
        .map_err(|err| format!("Failed to parse private key: {:?}", err))?;

    let public = RistrettoPublic::from(&private);

    Ok(ristretto_public_to_hex(&public))
}

#[wasm_bindgen]
impl Transaction {
    #[wasm_bindgen(constructor)]
    pub fn new(unsigned_tx_js: &str) -> Result<Transaction, JsValue> {
        Ok(Self {
            request: unsigned_tx_js.parse().unwrap(),
        })
    }

    fn get_requests(&self) -> Result<(UnsignedTx, FullServiceFogResolver), String> {
        let request_json: serde_json::Value =
            serde_json::from_str(&*self.request).expect("Malformed generate signing request.");

        let unsigned_tx: UnsignedTx = serde_json::from_value(
            request_json
                .get("unsigned_tx")
                .expect("Could not find \"unsigned_tx\".")
                .clone(),
        ).map_err(|err| format!("Failed to parse unsigned_tx {:?}", err))?;

        let fog_resolver: FullServiceFogResolver = serde_json::from_value(
            request_json
                .get("fog_resolver")
                .expect("Could not find \"fog_resolver\".")
                .clone(),
        ).map_err(|err| "Failed to parse fog_resolver")?;

        Ok((unsigned_tx, fog_resolver))
    }

    #[wasm_bindgen(js_name = "get_signing_data")]
    pub fn get_signing_data(&self, view_private_key: &str, spend_public_key: &str) -> Result<JsValue, JsValue> {
        let view_key = hex_to_ristretto(view_private_key)?;

        let spend_key = hex_to_ristretto_public(spend_public_key)?;

        let view_account = ViewAccountKey::new(
            view_key,
            spend_key
        );

        let (unsigned_tx, fog_resolver) = self.get_requests()?;

        let sign_data = unsigned_tx.get_signing_data(None, Some(&view_account), Some(0), fog_resolver)
            .map_err(|err| format!("Error on get signing data: {:?}", err))
            .map(|data| TxSigningDataJSON::try_from(data))?;

        let result = JsValue::from_serde(&sign_data).map_err(|e| {
            JsValue::from(format!(
                "Error converting constructor parameters to json object: {}",
                e
            ))
        })?;

        Ok(result)
    }

    #[wasm_bindgen(js_name = "sign")]
    pub fn sign(&self, view_private_key: &str, spend_private_key: &str) -> Result<JsValue, JsValue> {
        let spend_private_key = hex_to_ristretto(spend_private_key)
            .map_err(|err| format!("Failed to decode spend private key: {}", err))?;

        let view_private_key = hex_to_ristretto(view_private_key)
            .map_err(|err| format!("Failed to decode view private key:: {:?}", err))?;

        let account = AccountKey::new(&spend_private_key, &view_private_key);

        let (unsigned_tx, fog_resolver) = self.get_requests()?;

        let signed = unsigned_tx.sign(
            &account,
            fog_resolver
        ).map_err(|err| format!("Error on sign transaction: {:?}", err))?;

        let tx_proposal_json = TxProposalJSON::try_from(&signed)?;

        let result = JsValue::from_serde(&tx_proposal_json).map_err(|e| {
            JsValue::from(format!(
                "Error converting constructor parameters to json object: {}",
                e
            ))
        })?;

        Ok(result)
    }
}
