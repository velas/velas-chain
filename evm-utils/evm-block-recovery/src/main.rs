use evm_state::BlockNum;
use solana_evm_loader_program::instructions::EvmInstruction;
use solana_sdk::{clock::Slot, instruction::CompiledInstruction};
use solana_storage_bigtable::LedgerStorage;
use solana_transaction_status::TransactionWithStatusMeta;

use solana_sdk::evm_loader::ID as STATIC_PROGRAM_ID;

#[tokio::main]
async fn main() {
    dotenv::dotenv().expect("`.env` file expected");
    env_logger::init();

    let bigtable = LedgerStorage::new(false, None)
        .await
        .expect("Failed to connect to storage");

    let mut missing_blocks = Vec::new();

    missing_blocks.extend(
        find_evm_uncommitted_blocks(&bigtable, 15662810, 30)
            .await
            .unwrap(),
    );
    missing_blocks.extend(
        find_evm_uncommitted_blocks(&bigtable, 15880820, 20)
            .await
            .unwrap(),
    );
    missing_blocks.extend(
        find_evm_uncommitted_blocks(&bigtable, 17206780, 10)
            .await
            .unwrap(),
    );

    // println!("Missing blocks: {missing_blocks:?}");

    extract_evm_transactions(&bigtable, 15662812).await.unwrap();
}

async fn find_evm_uncommitted_blocks(
    ledger: &LedgerStorage,
    start_block: BlockNum,
    limit: usize,
) -> Result<Vec<BlockNum>, ()> {
    let mut result = Vec::new();

    let blocks = ledger
        .get_evm_confirmed_blocks(start_block, limit)
        .await
        .map_err(|_| ())?;

    for i in 0..blocks.len() - 1 {
        let previous = blocks[i];
        let current = blocks[i + 1];

        if current - previous != 1 {
            log::info!("Found missing block(s): {previous}, ...missing block(s)..., {current}");
            result.extend(previous + 1..current);
        }
    }

    Ok(result)
}

async fn extract_evm_transactions(ledger: &LedgerStorage, slot: Slot) -> Result<Option<Vec<evm::Transaction>>, ()> {
    // let block = ledger.get_confirmed_block(slot).await.unwrap();
    let evm_header = ledger.get_evm_confirmed_full_block(12).await.unwrap();
    let slot = evm_header.header.native_chain_slot;
    let native_block = ledger.get_confirmed_block(slot).await.unwrap();

    for TransactionWithStatusMeta { transaction, .. } in native_block.transactions {
        for CompiledInstruction { data, program_id_index } in transaction.message.instructions {
            if transaction.message.account_keys[program_id_index] == STATIC_PROGRAM_ID {
                let evm_instruction: EvmInstruction = bincode::deserialize(&data).unwrap();
                match evm_instruction {
                    EvmInstruction::EvmTransaction { evm_tx } => {
                        result.push(evm_tx)
                    },
                    EvmInstruction::SwapNativeToEther { lamports, evm_address } => todo!(),
                    EvmInstruction::FreeOwnership {  } => todo!(),
                    EvmInstruction::EvmBigTransaction(_) => todo!(),
                    EvmInstruction::EvmAuthorizedTransaction { from, unsigned_tx } => todo!(),
                }
                log::info!("Deserialized evm instruction: {evm_instruction:?}");
            }
        }
    }
    // result == evm_header.transactions.map((a,b) b).
    Ok(())
}

// let CompiledInstruction { program_id_index, accounts, data } = instruction;
// let _id = instruction.program_id(&[STATIC_PROGRAM_ID]);