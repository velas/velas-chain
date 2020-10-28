pub mod instructions;
pub mod processor;

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
        pub use evm_state::*;
        pub use primitive_types::H160 as Address;
    }
    pub mod solana {
        pub use solana_sdk::{pubkey::Pubkey as Address, transaction::Transaction};
    }
}
use instructions::EvmInstruction;
use scope::*;

pub fn evm_tx(evm_tx: evm::Transaction) -> EvmInstruction {
    EvmInstruction::EvmTransaction { evm_tx }
}
