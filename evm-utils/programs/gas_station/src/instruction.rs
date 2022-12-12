use super::*;
use borsh::{BorshDeserialize, BorshSerialize};
use solana_sdk::pubkey::Pubkey;

#[derive(Debug, BorshDeserialize, BorshSerialize, PartialEq)]
pub enum TxFilter {
    InputStartsWith {
        contract: evm_types::Address,
        input_prefix: Vec<u8>,
    },
}

impl TxFilter {
    pub fn is_match(&self, tx: &evm_types::Transaction) -> bool {
        match self {
            Self::InputStartsWith{ contract, input_prefix } => {
                matches!(tx.action, evm_types::TransactionAction::Call(addr) if addr == *contract)
                    && tx.input.starts_with(&input_prefix)
            }
        }
    }
}

#[derive(BorshDeserialize, BorshSerialize)]
pub enum GasStationInstruction {
    /// Register new payer
    RegisterPayer {
        owner: Pubkey,
        transfer_amount: u64,
        whitelist: Vec<TxFilter>,
    },

    /// Execute evm transaction
    ExecuteWithPayer {
        tx: Option<evm_types::Transaction>,
    }
}