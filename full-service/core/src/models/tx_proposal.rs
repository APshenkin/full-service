use mc_account_keys::PublicAddress;
use mc_transaction_core::{
    ring_signature::KeyImage,
    tx::{Tx, TxOut, TxOutConfirmationNumber},
    Amount,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InputTxo {
    pub tx_out: TxOut,
    pub subaddress_index: u64,
    pub key_image: KeyImage,
    pub amount: Amount,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OutputTxo {
    pub tx_out: TxOut,
    pub recipient_public_address: PublicAddress,
    pub confirmation_number: TxOutConfirmationNumber,
    pub amount: Amount,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TxProposal {
    pub tx: Tx,
    pub input_txos: Vec<InputTxo>,
    pub payload_txos: Vec<OutputTxo>,
    pub change_txos: Vec<OutputTxo>,
}
