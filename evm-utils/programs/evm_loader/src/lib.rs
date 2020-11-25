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

        const LAMPORTS_TO_GWEI_PRICE: u64 = 1_000_000_000; // Lamports is 1/10^9 of SOLs while GWEI is 1/10^18

        pub fn lamports_to_gwei(lamports: u64) -> U256 {
            U256::from(lamports) * U256::from(LAMPORTS_TO_GWEI_PRICE)
        }
    }
    pub mod solana {
        pub use solana_sdk::{
            instruction::Instruction, pubkey::Pubkey as Address, transaction::Transaction,
        };
    }
}
use instructions::EvmInstruction;
use scope::*;
use solana_sdk::instruction::{AccountMeta, Instruction};
use solana_sdk::sysvar;

pub fn evm_tx(evm_tx: evm::Transaction) -> EvmInstruction {
    EvmInstruction::EvmTransaction { evm_tx }
}

pub fn transfer_native_to_eth(
    owner: &solana::Address,
    authority_address: &solana::Address,
    lamports: u64,
    ether_address: evm::Address,
) -> solana::Instruction {
    let account_metas = vec![
        AccountMeta::new(*owner, true),
        AccountMeta::new(*authority_address, false),
    ];

    Instruction::new(
        crate::ID,
        &EvmInstruction::SwapNativeToEther {
            lamports,
            ether_address,
        },
        account_metas,
    )
}

pub fn create_deposit_account(
    signer: &solana::Address,
    authority_address: &solana::Address,
) -> solana::Instruction {
    let account_metas = vec![
        AccountMeta::new(*authority_address, false),
        AccountMeta::new_readonly(sysvar::rent::id(), false),
    ];

    Instruction::new(
        crate::ID,
        &EvmInstruction::CreateDepositAccount { pubkey: *signer },
        account_metas,
    )
}
