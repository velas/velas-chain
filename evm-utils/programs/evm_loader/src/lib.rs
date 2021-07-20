mod account_structure;
pub mod tx_chunks;

pub mod error;
pub mod instructions;
pub mod precompiles;
pub mod processor;

pub static ID: solana_sdk::pubkey::Pubkey = solana_sdk::evm_loader::ID;

pub use processor::EvmProcessor;

/// Public API for intermediate eth <-> solana transfers
pub mod scope {
    pub mod evm {
        pub use evm_state::transactions::*;
        pub use evm_state::*;
        pub use primitive_types::H160 as Address;

        pub const LAMPORTS_TO_GWEI_PRICE: u64 = 1_000_000_000; // Lamports is 1/10^9 of SOLs while GWEI is 1/10^18

        // Convert lamports to gwei
        pub fn lamports_to_gwei(lamports: u64) -> U256 {
            U256::from(lamports) * U256::from(LAMPORTS_TO_GWEI_PRICE)
        }

        // Convert gweis back to lamports, return change as second element.
        pub fn gweis_to_lamports(gweis: U256) -> (u64, U256) {
            let lamports = gweis / U256::from(LAMPORTS_TO_GWEI_PRICE);
            let gweis = gweis % U256::from(LAMPORTS_TO_GWEI_PRICE);
            (lamports.as_u64(), gweis)
        }
    }
    pub mod solana {
        pub use solana_sdk::{
            evm_state, instruction::Instruction, pubkey::Pubkey as Address,
            transaction::Transaction,
        };
    }
}
use instructions::{EvmBigTransaction, EvmInstruction};
use scope::*;
use solana_sdk::instruction::{AccountMeta, Instruction};

pub fn send_raw_tx(
    signer: solana::Address,
    evm_tx: evm::Transaction,
    gas_collector: Option<solana::Address>,
) -> solana::Instruction {
    let mut account_metas = vec![
        AccountMeta::new(solana::evm_state::ID, false),
        AccountMeta::new(signer, true),
    ];
    if let Some(gas_collector) = gas_collector {
        account_metas.push(AccountMeta::new(gas_collector, false))
    }

    Instruction::new_with_bincode(
        crate::ID,
        &EvmInstruction::EvmTransaction { evm_tx },
        account_metas,
    )
}

pub fn authorized_tx(
    sender: solana::Address,
    unsigned_tx: evm::UnsignedTransaction,
) -> solana::Instruction {
    let account_metas = vec![
        AccountMeta::new(solana::evm_state::ID, false),
        AccountMeta::new(sender, true),
    ];

    let from = evm_address_for_program(sender);
    Instruction::new_with_bincode(
        crate::ID,
        &EvmInstruction::EvmAuthorizedTransaction { from, unsigned_tx },
        account_metas,
    )
}

pub(crate) fn transfer_native_to_eth(
    owner: solana::Address,
    lamports: u64,
    evm_address: evm::Address,
) -> solana::Instruction {
    let account_metas = vec![
        AccountMeta::new(solana::evm_state::ID, false),
        AccountMeta::new(owner, true),
    ];

    Instruction::new_with_bincode(
        crate::ID,
        &EvmInstruction::SwapNativeToEther {
            lamports,
            evm_address,
        },
        account_metas,
    )
}

pub(crate) fn free_ownership(owner: solana::Address) -> solana::Instruction {
    let account_metas = vec![
        AccountMeta::new(solana::evm_state::ID, false),
        AccountMeta::new(owner, true),
    ];

    Instruction::new_with_bincode(crate::ID, &EvmInstruction::FreeOwnership {}, account_metas)
}

pub fn big_tx_allocate(storage: &solana::Address, size: usize) -> solana::Instruction {
    let account_metas = vec![
        AccountMeta::new(solana::evm_state::ID, false),
        AccountMeta::new(*storage, true),
    ];

    let big_tx = EvmBigTransaction::EvmTransactionAllocate { size: size as u64 };

    Instruction::new_with_bincode(
        crate::ID,
        &EvmInstruction::EvmBigTransaction(big_tx),
        account_metas,
    )
}

pub fn big_tx_write(storage: &solana::Address, offset: u64, chunk: Vec<u8>) -> solana::Instruction {
    let account_metas = vec![
        AccountMeta::new(solana::evm_state::ID, false),
        AccountMeta::new(*storage, true),
    ];

    let big_tx = EvmBigTransaction::EvmTransactionWrite {
        offset,
        data: chunk,
    };

    Instruction::new_with_bincode(
        crate::ID,
        &EvmInstruction::EvmBigTransaction(big_tx),
        account_metas,
    )
}

pub fn big_tx_execute(
    storage: &solana::Address,
    gas_collector: Option<&solana::Address>,
) -> solana::Instruction {
    let mut account_metas = vec![
        AccountMeta::new(solana::evm_state::ID, false),
        AccountMeta::new(*storage, true),
    ];

    if let Some(gas_collector) = gas_collector {
        account_metas.push(AccountMeta::new(*gas_collector, false))
    }

    let big_tx = EvmBigTransaction::EvmTransactionExecute {};

    Instruction::new_with_bincode(
        crate::ID,
        &EvmInstruction::EvmBigTransaction(big_tx),
        account_metas,
    )
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
pub fn create_state_account(lamports: u64) -> solana_sdk::account::AccountSharedData {
    solana_sdk::account::AccountSharedData {
        lamports: lamports + 1,
        owner: crate::ID,
        data: b"Evm state".to_vec(),
        executable: false,
        rent_epoch: 0,
    }
}

///
/// Calculate evm::Address for solana::Pubkey, that can be used to call transaction from solana::bpf scope, into evm scope.
/// Native chain address is hashed and prefixed with [0xac, 0xc0] bytes.
///
pub fn evm_address_for_program(program_account: solana::Address) -> evm::Address {
    use primitive_types::{H160, H256};
    use sha3::{Digest, Keccak256};

    const ADDR_PREFIX: &[u8] = &[0xAC, 0xC0]; // ACC prefix for each account

    let addr_hash = Keccak256::digest(&program_account.to_bytes());
    let hash_bytes = H256::from_slice(addr_hash.as_slice());
    let mut short_hash = H160::from(hash_bytes);
    short_hash.as_bytes_mut()[0..2].copy_from_slice(ADDR_PREFIX);

    short_hash
}

pub fn evm_transfer(
    from: evm::SecretKey,
    to: evm::Address,
    nonce: evm::U256,
    value: evm::U256,
    chain_id: Option<u64>,
) -> evm::Transaction {
    let tx = evm::UnsignedTransaction {
        nonce,
        gas_price: 1.into(),
        gas_limit: 30000.into(),
        action: evm::TransactionAction::Call(to),
        value,
        input: vec![],
    };
    tx.sign(&from, chain_id)
}
