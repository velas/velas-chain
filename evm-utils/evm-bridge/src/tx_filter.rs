use evm_rpc::Bytes;
use evm_state::{Address, Transaction, TransactionAction};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub enum TxFilter {
    InputStartsWith(Address, Bytes),
}

impl TxFilter {
    pub fn filter(&self, tx: &Transaction) -> bool {
        match self {
            Self::InputStartsWith(addr, bytes) => {
                matches!(tx.action, TransactionAction::Call(contract) if contract == *addr)
                    && tx.input.starts_with(&bytes.0)
            }
        }
    }
}
