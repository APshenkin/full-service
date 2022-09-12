// Copyright (c) 2020-2021 MobileCoin Inc.

//! API definition for the TxProposal object.

use serde_derive::{Deserialize, Serialize};
use std::convert::TryFrom;
use mc_full_service_core::util::b58::{b58_encode_public_address, B58Error};
use crate::data_types::amount_json::AmountJSON;
use crate::data_types::tx_signing_data_json::{InputTxoJSON, OutputTxoJSON};

#[derive(Deserialize, Serialize, Default, Debug)]
pub struct TxProposalJSON {
    pub input_txos: Vec<InputTxoJSON>,
    pub payload_txos: Vec<OutputTxoJSON>,
    pub change_txos: Vec<OutputTxoJSON>,
    pub fee_amount: AmountJSON,
    pub tombstone_block_index: String,
    pub tx_proto: String,
}

impl TryFrom<&mc_full_service_core::models::tx_proposal::TxProposal> for TxProposalJSON {
    type Error = String;

    fn try_from(src: &mc_full_service_core::models::tx_proposal::TxProposal) -> Result<Self, String> {
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
            input_txos,
            payload_txos,
            change_txos,
            tx_proto: hex::encode(mc_util_serial::encode(&src.tx)),
            fee_amount: AmountJSON::new(src.tx.prefix.fee, src.tx.prefix.fee_token_id.into()),
            tombstone_block_index: src.tx.prefix.tombstone_block.to_string(),
        })
    }
}
