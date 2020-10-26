pub mod processor;
pub mod instructions;

solana_sdk::declare_builtin!(
    solana_sdk::evm_loader::ID,
    solana_evm_loader_program,
    solana_evm_loader_program::process_instruction
);

pub use processor::process_instruction;

/// Public API for intermediate eth <-> solana transfers 
pub mod scope {
    pub mod evm {
        pub use evm_state::transactions::*;
        pub use primitive_types::H160 as Address;
        pub use evm_state::*;
    }
    pub mod solana {
        pub use solana_sdk::{transaction::Transaction, pubkey::Pubkey as Address};
    }
}
use scope::*;
use instructions::EvmInstruction;

pub fn evm_tx(
    evm_tx: evm::Transaction
) -> EvmInstruction {
    EvmInstruction::EvmTransaction {
        evm_tx
    }
}