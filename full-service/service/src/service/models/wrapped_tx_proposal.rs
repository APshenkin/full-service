use mc_full_service_core::models::tx_proposal::TxProposal as CoreTxProposal;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WrappedTxProposal(pub(crate) CoreTxProposal);
