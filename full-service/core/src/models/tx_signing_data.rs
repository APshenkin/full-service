use mc_transaction_core::ring_ct::{InputRing, SigningData};
use mc_transaction_core::tx::TxPrefix;
use crate::models::tx_proposal::{InputTxo, OutputTxo};


#[derive(Clone, Debug)]
pub struct TxSigningData {
    pub tx_prefix: TxPrefix,
    pub rings: Vec<InputRing>,
    pub signing_data: SigningData,
    pub input_txos: Vec<InputTxo>,
    pub payload_txos: Vec<OutputTxo>,
    pub change_txos: Vec<OutputTxo>,
}
