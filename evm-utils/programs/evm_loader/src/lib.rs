pub mod processor;

solana_sdk::declare_builtin!(
    solana_sdk::evm_loader::ID,
    solana_evm_loader_program,
    solana_evm_loader_program::process_instruction
);

pub use processor::process_instruction;