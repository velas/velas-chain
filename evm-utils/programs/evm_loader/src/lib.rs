pub mod instructions;
pub mod processor;

pub static ID: solana_sdk::pubkey::Pubkey = solana_sdk::evm_loader::ID;

pub use processor::EvmProcessor;

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
            evm_state, instruction::Instruction, pubkey::Pubkey as Address,
            transaction::Transaction,
        };
    }
}
use instructions::EvmInstruction;
use scope::*;
use solana_sdk::instruction::{AccountMeta, Instruction};

pub fn send_raw_tx(signer: solana::Address, evm_tx: evm::Transaction) -> solana::Instruction {
    let account_metas = vec![
        AccountMeta::new(solana::evm_state::ID, false),
        AccountMeta::new(signer, true),
    ];

    Instruction::new(
        crate::ID,
        &EvmInstruction::EvmTransaction { evm_tx },
        account_metas,
    )
}

pub(crate) fn transfer_native_to_eth(
    owner: solana::Address,
    lamports: u64,
    ether_address: evm::Address,
) -> solana::Instruction {
    let account_metas = vec![
        AccountMeta::new(solana::evm_state::ID, false),
        AccountMeta::new(owner, true),
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

pub(crate) fn free_ownership(owner: solana::Address) -> solana::Instruction {
    let account_metas = vec![
        AccountMeta::new(solana::evm_state::ID, false),
        AccountMeta::new(owner, true),
    ];

    Instruction::new(crate::ID, &EvmInstruction::FreeOwnership {}, account_metas)
}

pub fn transfer_native_to_eth_ixs(
    owner: solana::Address,
    lamports: u64,
    ether_address: evm::Address,
) -> Vec<solana::Instruction> {
    vec![
        solana_sdk::system_instruction::assign(&owner, &crate::ID),
        transfer_native_to_eth(owner, lamports, ether_address),
        free_ownership(owner),
    ]
}

/// Create an account that represent evm locked lamports count.
pub fn create_state_account() -> solana_sdk::account::Account {
    solana_sdk::account::Account {
        lamports: 1,
        owner: crate::ID,
        data: b"Evm state".to_vec(),
        executable: false,
        rent_epoch: 0,
    }
}
