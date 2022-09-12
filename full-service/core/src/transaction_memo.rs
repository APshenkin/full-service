use mc_account_keys::AccountKey;
use mc_transaction_std::{BurnRedemptionMemo, BurnRedemptionMemoBuilder, MemoBuilder, RTHMemoBuilder, SenderMemoCredential};

use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub enum TransactionMemo {
    /// Recoverable Transaction History memo.
    RTH,

    /// Burn Redemption memo, with an optional 64 byte redemption memo hex
    /// string.
    #[serde(with = "BigArray")]
    BurnRedemption([u8; BurnRedemptionMemo::MEMO_DATA_LEN]),
}

impl TransactionMemo {
    pub fn memo_builder(&self, account_key: &AccountKey) -> Box<dyn MemoBuilder + Send + Sync> {
        match self {
            Self::RTH => {
                let mut memo_builder = RTHMemoBuilder::default();
                memo_builder.set_sender_credential(SenderMemoCredential::from(account_key));
                memo_builder.enable_destination_memo();
                Box::new(memo_builder)
            }
            Self::BurnRedemption(memo_data) => {
                let mut memo_builder = BurnRedemptionMemoBuilder::new(*memo_data);
                memo_builder.enable_destination_memo();
                Box::new(memo_builder)
            }
        }
    }
}
