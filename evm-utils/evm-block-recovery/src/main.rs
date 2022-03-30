pub mod data;
pub mod routines;

use evm::TransactionInReceipt;
use evm_state as evm;
use solana_storage_bigtable::LedgerStorage;

use crate::data::{EvmBlockRange, EvmContent};

// TODO: better error handling

#[tokio::main]
async fn main() {
    env_logger::init();
    dotenv::dotenv().expect("`.env` file expected");

    let bigtable = LedgerStorage::new(false, None)
        .await
        .expect("Failed to connect to storage");

    let evm_block_header = bigtable
        .get_evm_confirmed_full_block(15662812)
        .await
        .unwrap()
        .header;

    println!("BLOCK HEADER:\n{}\n", serde_json::to_string_pretty(&evm_block_header).unwrap());

    let native_block = bigtable.get_confirmed_block(evm_block_header.native_chain_slot).await.unwrap();
    let evm_content = data::EvmContent::from_native_block(native_block);
    
    let e = evm_content.instructions.into_iter().nth(0).unwrap();
    
    match e {
        solana_evm_loader_program::instructions::EvmInstruction::EvmTransaction { evm_tx } => {
            let tx = evm_rpc::RPCTransaction::from_transaction(TransactionInReceipt::Signed(evm_tx)).unwrap();
            println!("RPCTransaction:\n{}\n", serde_json::to_string_pretty(&tx).unwrap());
        },
        _ => panic!("Unexpected EVM Instruction"),
    }
}

// println!("{:?}", routines::integrity_check(&bigtable, 15_000_042).await);

// let native_block = bigtable.get_confirmed_block(112321).await.unwrap();
// let evm_block = bigtable
//     .get_evm_confirmed_full_block(1232123)
//     .await
//     .unwrap();

async fn print_native_to_csv(ledger: &LedgerStorage) {
    let mut results = String::new();
    results.push_str("Slot,EvmTransaction,SwapNativeToEther,FreeOwnership,EvmBigTransaction,EvmAuthorizedTransaction\n");

    let mut native_blocks = vec![];
    native_blocks.extend(53183621..=53183644);
    native_blocks.extend(53414856..=53414871);
    native_blocks.extend(54832538..=54832540);

    for slot in native_blocks {
        let native_block = ledger.get_confirmed_block(slot as u64).await.unwrap();
        let evm_content = data::EvmContent::from_native_block(native_block);

        results.push_str(&format!(
            "{},{},{},{},{},{}",
            slot,
            evm_content.instr_evm_transaction(),
            evm_content.instr_evm_swap_to_native(),
            evm_content.instr_evm_free_ownership(),
            evm_content.instr_evm_big_transaction(),
            evm_content.instr_evm_authorized_transaction()
        ));
        results.push('\n');

        std::fs::write("/home/maksimv/Desktop/block_result.csv", &results).unwrap();
    }
}

async fn main_recovery(ledger: &LedgerStorage) {
    let blocks = ledger.get_evm_confirmed_blocks(15662810, 30).await.unwrap();

    let missing_blocks = find_evm_uncommitted_blocks(blocks);

    if missing_blocks.is_empty() {
        log::info!("Nothing to recover, exiting...");
        return;
    }

    let recovery_starting_slot = ledger
        .get_evm_confirmed_full_block(missing_blocks[0].first - 1)
        .await
        .unwrap()
        .header
        .native_chain_slot;

    let mut recovered_blocks: Vec<u64> = Vec::new();

    let mut recovery_slot = recovery_starting_slot;

    while recovered_blocks.len() < missing_blocks.len() {
        let native_block = ledger.get_confirmed_block(recovery_slot).await.unwrap();

        let evm_txs = EvmContent::from_native_block(native_block);

        recovery_slot += 1;
    }

    log::info!("Recovered blocks: {:?}", recovered_blocks);
}

fn find_evm_uncommitted_blocks(blocks: Vec<evm::BlockNum>) -> Vec<EvmBlockRange> {
    let mut result = Vec::new();
    for i in 0..blocks.len() - 1 {
        let previous = blocks[i];
        let current = blocks[i + 1];

        if current - previous != 1 {
            log::info!("Found missing block(s): {previous}, ...missing block(s)..., {current}");
            result.push(data::EvmBlockRange::new(previous + 1, current - 1));
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_missing_blocks() {
        let confirmed_blocks = vec![1, 2, 3, 8, 9, 10];
        assert_eq!(
            find_evm_uncommitted_blocks(confirmed_blocks),
            vec![EvmBlockRange { first: 4, last: 7 }]
        )
    }

    #[test]
    fn test_find_missing_blocks_multirange() {
        let confirmed_blocks = vec![1, 2, 5, 6, 10, 11, 13];
        assert_eq!(
            find_evm_uncommitted_blocks(confirmed_blocks),
            vec![
                EvmBlockRange { first: 3, last: 4 },
                EvmBlockRange { first: 7, last: 9 },
                EvmBlockRange {
                    first: 12,
                    last: 12
                }
            ]
        );
    }

    // TODO: test `extract_evm_transactions` function
}
