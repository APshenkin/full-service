// Copyright (c) 2020-2021 MobileCoin Inc.

//! Full Service Wallet.

#![feature(proc_macro_hygiene, decl_macro)]

pub mod check_host;
pub mod config;
mod error;
pub mod db;
pub mod json_rpc;
pub mod service;
mod validator_ledger_sync;

pub use db::WalletDb;
pub use json_rpc::wallet;
pub use service::WalletService;
pub use validator_ledger_sync::ValidatorLedgerSyncThread;

pub use mc_full_service_core::util;
pub use mc_full_service_core::fog_resolver;
pub use mc_full_service_core::unsigned_tx;
pub use mc_full_service_core::transaction_memo;

extern crate alloc;
#[macro_use]
extern crate diesel;
extern crate dotenv;
#[allow(unused_imports)] // Needed for json!
#[macro_use]
extern crate rocket_contrib;
#[allow(unused_imports)] // Needed for embedded_migrations!
#[macro_use]
extern crate diesel_migrations;

#[cfg(any(test, feature = "test_utils"))]
mod test_utils;
