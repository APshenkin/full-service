// Copyright (c) 2020-2021 MobileCoin Inc.

//! Errors for the wallet service.

use crate::{
    util::b58::B58Error,
};
use displaydoc::Display;

#[derive(Display, Debug)]
#[allow(clippy::large_enum_variant)]
pub enum WalletTransactionBuilderError {
    /// Insufficient Funds: {0}
    InsufficientFunds(String),

    /// Insufficient Funds in inputs to construct transaction: {0}
    InsufficientInputFunds(String),

    /// Insufficient TxOuts to construct transaction
    InsufficientTxOuts,

    /// Ring size does not match number of inputs
    RingSizeMismatch,

    /// No recipient was specified
    NoRecipient,

    /// Not enough Rings and Proofs
    RingsAndProofsEmpty,

    /// Tx Builder Error: {0}
    TxBuilder(mc_transaction_std::TxBuilderError),

    /// Invalid Argument: {0}
    InvalidArgument(String),

    /// Prost decode failed: {0}
    ProstDecode(mc_util_serial::DecodeError),

    /// Error interacting with fog: {0}
    FogError(String),

    /// Attempting to build a transaction from a TXO without a subaddress: {0}
    NullSubaddress(String),

    /// No inputs selected. Must set or select inputs before building.
    NoInputs,

    /// No masked amount in output.
    NoMaskedAmount,

    /// Outbound value + fee exceeds u64::MAX
    OutboundValueTooLarge,

    /**
     * Must set tombstone before building. Setting to 0 picks reasonable
     * default.
     */
    TombstoneNotSet,

    /// Fee must be at least MINIMUM_FEE: {0}
    InsufficientFee(String),

    /// Error generating FogPubkeyResolver {0}
    FogPubkeyResolver(String),

    /// Error with the b58 util: {0}
    B58(B58Error),

    /// Error passed up from AmountError
    AmountError(mc_transaction_core::AmountError),

    /// Error passed up from KeyError
    KeyError(mc_crypto_keys::KeyError),

    /// Transaction is missing inputs for outputs with token id {0}
    MissingInputsForTokenId(String),

    /// Error decoding the hex string: {0}
    FromHexError(hex::FromHexError),

    /// Burn Redemption Memo must be exactly 128 characters (64 bytes) long.
    InvalidBurnRedemptionMemo(String),
}

impl From<mc_transaction_core::AmountError> for WalletTransactionBuilderError {
    fn from(src: mc_transaction_core::AmountError) -> Self {
        Self::AmountError(src)
    }
}

impl From<mc_crypto_keys::KeyError> for WalletTransactionBuilderError {
    fn from(src: mc_crypto_keys::KeyError) -> Self {
        Self::KeyError(src)
    }
}

impl From<mc_transaction_std::TxBuilderError> for WalletTransactionBuilderError {
    fn from(src: mc_transaction_std::TxBuilderError) -> Self {
        Self::TxBuilder(src)
    }
}

impl From<mc_util_serial::DecodeError> for WalletTransactionBuilderError {
    fn from(src: mc_util_serial::DecodeError) -> Self {
        Self::ProstDecode(src)
    }
}

impl From<B58Error> for WalletTransactionBuilderError {
    fn from(src: B58Error) -> Self {
        Self::B58(src)
    }
}

impl From<hex::FromHexError> for WalletTransactionBuilderError {
    fn from(src: hex::FromHexError) -> Self {
        Self::FromHexError(src)
    }
}
