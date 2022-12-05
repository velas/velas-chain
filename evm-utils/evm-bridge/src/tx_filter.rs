use evm_rpc::Bytes;
use evm_state::{Address, Transaction, TransactionAction};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub enum TxFilter {
    InputStartsWith {
        contract: Address,
        input_prefix: Bytes
    },
    ByReceiver {
        contract: Address,
    }
}

impl TxFilter {
    pub fn is_match(&self, tx: &Transaction) -> bool {
        match self {
            Self::InputStartsWith { contract, input_prefix } => {
                matches!(tx.action, TransactionAction::Call(addr) if addr == *contract)
                    && tx.input.starts_with(&input_prefix.0)
            }
            Self::ByReceiver { contract } => {
                matches!(tx.action, TransactionAction::Call(addr) if addr == *contract)
            }
        }
    }
}
