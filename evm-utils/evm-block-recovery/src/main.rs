use evm_state as evm;
use solana_evm_loader_program::instructions::EvmInstruction;
use solana_sdk::instruction::CompiledInstruction;
use solana_storage_bigtable::LedgerStorage;
use solana_transaction_status::{ConfirmedBlock, TransactionWithStatusMeta};

use solana_sdk::evm_loader::ID as STATIC_PROGRAM_ID;

// TODO: better error handling

#[tokio::main]
async fn main() {
    dotenv::dotenv().expect("`.env` file expected");
    env_logger::init();

    let bigtable = LedgerStorage::new(false, None)
        .await
        .expect("Failed to connect to storage");

    // start_block: 15662810, limit: 30
    // start_block: 15880820, limit: 20
    // start_block: 17206780, limit: 10

    let blocks = bigtable
        .get_evm_confirmed_blocks(15662810, 30)
        .await
        .unwrap();

    let missing_blocks = find_evm_uncommitted_blocks(blocks);

    if missing_blocks.is_empty() {
        log::info!("Nothing to recover, exiting...");
        return;
    }

    let recovery_starting_slot = bigtable
        .get_evm_confirmed_full_block(missing_blocks[0] - 1)
        .await
        .unwrap()
        .header
        .native_chain_slot;

    let mut recovered_blocks = Vec::new();

    let mut recovery_slot = recovery_starting_slot;

    while recovered_blocks.len() < missing_blocks.len() {
        let native_block = bigtable.get_confirmed_block(recovery_slot).await.unwrap();

        let evm_txs = extract_evm_transactions(native_block);

        match evm_txs {
            Some(txs) => recovered_blocks.push((recovery_slot, txs)),
            None => (),
        }

        recovery_slot += 1;
    }

    log::info!("Recovered blocks: {:?}", recovered_blocks);
}

fn find_evm_uncommitted_blocks(blocks: Vec<evm::BlockNum>) -> Vec<evm::BlockNum> {
    let mut result = Vec::new();
    for i in 0..blocks.len() - 1 {
        let previous = blocks[i];
        let current = blocks[i + 1];

        if current - previous != 1 {
            log::info!("Found missing block(s): {previous}, ...missing block(s)..., {current}");
            result.extend(previous + 1..current);
        }
    }

    result
}

fn extract_evm_transactions(native_block: ConfirmedBlock) -> Option<Vec<evm::Transaction>> {
    let mut evm_txs = Vec::new();

    for TransactionWithStatusMeta { transaction, .. } in native_block.transactions {
        for CompiledInstruction {
            data,
            program_id_index,
            ..
        } in transaction.message.instructions
        {
            if transaction.message.account_keys[program_id_index as usize] == STATIC_PROGRAM_ID {
                let evm_instruction: EvmInstruction = bincode::deserialize(&data).unwrap();
                match evm_instruction {
                    EvmInstruction::EvmTransaction { evm_tx } => {
                        log::info!("Found EVM transaction: {evm_tx:?}");
                        evm_txs.push(evm_tx);
                    }
                    instr => log::trace!("Skipping parsed instruction: {instr:?}"),
                }
            }
        }
    }

    if evm_txs.len() > 0 {
        Some(evm_txs)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_missing_blocks() {
        let confirmed_blocks = vec![1, 2, 3, 8, 9, 10];
        assert_eq!(
            find_evm_uncommitted_blocks(confirmed_blocks),
            vec![4, 5, 6, 7]
        )
    }

    // should we handle this case properly?
    #[test]
    fn test_find_missing_blocks_multirange() {
        let confirmed_blocks = vec![1, 2, 5, 6, 9, 10];
        assert_eq!(
            find_evm_uncommitted_blocks(confirmed_blocks),
            vec![3, 4, 7, 8]
        );
        assert!(false)
    }

    // TODO: test `extract_evm_transactions` function
}
