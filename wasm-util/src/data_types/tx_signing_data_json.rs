use std::convert::TryFrom;

use mc_transaction_core::ring_ct::InputRing::Signable;
use serde_derive::{Deserialize, Serialize};

use mc_full_service_core::models::tx_proposal::{InputTxo, OutputTxo};
use mc_full_service_core::models::tx_signing_data::TxSigningData;
use mc_full_service_core::util::b58::{b58_encode_public_address, B58Error};

use crate::data_types::amount_json::AmountJSON;

#[derive(Deserialize, Serialize, Default, Debug)]
pub struct InputTxoJSON {
    pub tx_out_proto: String,
    pub amount: AmountJSON,
    pub subaddress_index: String,
    pub key_image: String,
}

impl From<InputTxo> for InputTxoJSON {
    fn from(src: InputTxo) -> Self {
        Self {
            tx_out_proto: hex::encode(mc_util_serial::encode(&src.tx_out)),
            amount: AmountJSON::from(&src.amount),
            subaddress_index: src.subaddress_index.to_string(),
            key_image: hex::encode(&src.key_image.as_bytes()),
        }
    }
}


#[derive(Deserialize, Serialize, Default, Debug)]
pub struct OutputTxoJSON {
    pub tx_out_proto: String,
    pub amount: AmountJSON,
    pub recipient_public_address_b58: String,
    pub confirmation_number: String,
}

impl TryFrom<OutputTxo> for OutputTxoJSON {
    type Error = String;

    fn try_from(src: OutputTxo) -> Result<Self, String> {
        Ok(Self {
            tx_out_proto: hex::encode(mc_util_serial::encode(&src.tx_out)),
            amount: AmountJSON::from(&src.amount),
            recipient_public_address_b58: b58_encode_public_address(
                &src.recipient_public_address,
            ).map_err(|_| "Error".to_string())?,
            confirmation_number: hex::encode(src.confirmation_number.as_ref()),
        })
    }
}

#[derive(Deserialize, Serialize, Default, Debug)]
pub struct TxSigningDataJSON {
    pub tx_prefix: String,
    pub rings: Vec<RingJSON>,
    pub signing_data: SigningDataJSON,
    pub input_txos: Vec<InputTxoJSON>,
    pub payload_txos: Vec<OutputTxoJSON>,
    pub change_txos: Vec<OutputTxoJSON>,
}

#[derive(Deserialize, Serialize, Default, Debug)]
pub struct SigningDataJSON {
    pub extended_message: String,
    pub pseudo_output_blindings: Vec<String>,
    pub pseudo_output_commitments: Vec<String>,
    pub range_proof_bytes: String,
    pub range_proofs: Vec<String>,
    pub pseudo_output_token_ids: Vec<u64>,
    pub output_token_ids: Vec<u64>,
}

#[derive(Deserialize, Serialize, Default, Debug)]
pub struct VerifySignatureJSON {
    pub message: String,
    pub ring: Vec<RingJSON>,
    pub output_commitment: String,
    pub c_zero: String,
    pub responses: Vec<String>,
    pub key_image: String,
}

#[derive(Deserialize, Serialize, Default, Debug)]
pub struct RingJSON {
    pub members: Vec<RingMemberJSON>,
    pub real_input_index: u64,
    pub input_secret: RingInputSecretJSON,
}

#[derive(Deserialize, Serialize, Default, Debug)]
pub struct RingMemberJSON {
    pub compressed_ristretto_public: String,
    pub compressed_ristretto_target: String,
    pub compressed_commitment: String,
}

#[derive(Deserialize, Serialize, Default, Debug)]
pub struct RingInputSecretJSON {
    value: RingAmountJSON,
    blinding: String,
}

#[derive(Deserialize, Serialize, Default, Debug)]
pub struct RingAmountJSON {
    value: String,
    token_id: String,
}

impl TryFrom<TxSigningData> for TxSigningDataJSON {
    type Error = String;

    fn try_from(src: TxSigningData) -> Result<Self, String> {
        let rings = src.rings
            .iter()
            .map(|ring|
                match ring {
                    Signable(r) => Ok(RingJSON {
                        members: r.members
                            .iter()
                            .map(|m| RingMemberJSON {
                                compressed_ristretto_target: hex::encode(m.target_key.as_bytes()),
                                compressed_ristretto_public: hex::encode(m.public_key.as_bytes()),
                                compressed_commitment: hex::encode(m.commitment.point.to_bytes()),
                            })
                            .collect(),
                        real_input_index: r.real_input_index as u64,
                        input_secret: RingInputSecretJSON {
                            value: RingAmountJSON {
                                value: r.input_secret.amount.value.to_string(),
                                token_id: r.input_secret.amount.token_id.to_string(),
                            },
                            blinding: hex::encode(r.input_secret.blinding.to_bytes()),
                        },
                    }),

                    _ => Err("foo".to_string())
                }
            )
            .collect::<Result<Vec<RingJSON>, String>>()
            .map_err(|_| "Error".to_string())?;

        let pseudo_output_blindings = src.signing_data.pseudo_output_blindings
            .iter()
            .map(|output| hex::encode(output.to_bytes()))
            .collect();

        let pseudo_output_commitments = src.signing_data.pseudo_output_commitments
            .iter()
            .map(|x| hex::encode(x.point.to_bytes()))
            .collect();

        let range_proof_bytes = hex::encode(src.signing_data.range_proof_bytes);

        let range_proofs = src.signing_data.range_proofs
            .iter()
            .map(|proof| hex::encode(proof))
            .collect();

        let input_txos = src
            .input_txos
            .iter()
            .map(|input_txo| InputTxoJSON::from(input_txo.clone()))
            .collect();

        let payload_txos = src
            .payload_txos
            .iter()
            .map(|output_txo| {
                OutputTxoJSON::try_from(output_txo.clone())
            })
            .collect::<Result<Vec<OutputTxoJSON>, String>>()
            .map_err(|_| "Error".to_string())?;

        let change_txos = src
            .change_txos
            .iter()
            .map(|output_txo| {
                OutputTxoJSON::try_from(output_txo.clone())
            })
            .collect::<Result<Vec<OutputTxoJSON>, String>>()
            .map_err(|_| "Error".to_string())?;

        Ok(Self {
            tx_prefix: hex::encode(mc_util_serial::encode(&src.tx_prefix)),
            rings,
            signing_data: SigningDataJSON {
                extended_message: hex::encode(src.signing_data.extended_message),
                pseudo_output_blindings,
                pseudo_output_commitments,
                range_proof_bytes,
                range_proofs,
                pseudo_output_token_ids: src.signing_data.pseudo_output_token_ids,
                output_token_ids: src.signing_data.output_token_ids,
            },
            input_txos,
            change_txos,
            payload_txos,
        })
    }
}
