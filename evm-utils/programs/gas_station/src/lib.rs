mod error;
mod evm_loader_instructions;
pub mod evm_types;
pub mod instruction;
mod processor;
mod state;

use borsh::BorshSerialize;
use processor::process_instruction;
use solana_program::instruction::{AccountMeta, Instruction};
use solana_program::pubkey::Pubkey;
use solana_program::{entrypoint, system_program};

// Declare and export the program's entrypoint
entrypoint!(process_instruction);

pub fn create_storage_account(
    from_pubkey: &Pubkey,
    to_pubkey: &Pubkey,
    lamports: u64,
    filters: &Vec<instruction::TxFilter>,
    owner: &Pubkey,
) -> Instruction {
    let mut bytes = vec![];
    BorshSerialize::serialize(filters, &mut bytes).unwrap();
    solana_sdk::system_instruction::create_account(
        from_pubkey,
        to_pubkey,
        lamports,
        bytes.len() as u64 + 64,
        owner,
    )
}

pub fn execute_tx_with_payer(
    tx: evm_types::Transaction,
    program_id: Pubkey,
    signer: Pubkey,
    storage: Pubkey,
    payer: Pubkey,
) -> Instruction {
    let account_metas = vec![
        AccountMeta::new(signer, true),
        AccountMeta::new(storage, false),
        AccountMeta::new(payer, false),
        AccountMeta::new_readonly(solana_sdk::evm_loader::ID, false),
        AccountMeta::new(solana_sdk::evm_state::ID, false),
        AccountMeta::new_readonly(system_program::id(), false),
    ];
    Instruction::new_with_borsh(
        program_id,
        &instruction::GasStationInstruction::ExecuteWithPayer { tx: Some(tx) },
        account_metas,
    )
}

pub fn execute_big_tx_with_payer(
    program_id: Pubkey,
    signer: Pubkey,
    storage: Pubkey,
    payer: Pubkey,
    big_tx_storage: Pubkey,
) -> Instruction {
    let account_metas = vec![
        AccountMeta::new(signer, true),
        AccountMeta::new(storage, false),
        AccountMeta::new(payer, false),
        AccountMeta::new_readonly(solana_sdk::evm_loader::ID, false),
        AccountMeta::new(solana_sdk::evm_state::ID, false),
        AccountMeta::new_readonly(system_program::id(), false),
        AccountMeta::new(big_tx_storage, true),
    ];
    Instruction::new_with_borsh(
        program_id,
        &instruction::GasStationInstruction::ExecuteWithPayer { tx: None },
        account_metas,
    )
}
