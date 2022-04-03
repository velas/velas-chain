use evm_state::BlockNum;
use solana_storage_bigtable::LedgerStorage;

use crate::data::{EvmBlockRange, EvmContent};

pub async fn find(ledger: &LedgerStorage, start_block: BlockNum, limit: usize) {
    let blocks = ledger
        .get_evm_confirmed_blocks(start_block, limit)
        .await
        .unwrap();

    let missing_blocks = find_evm_uncommitted_blocks(blocks);

    if missing_blocks.is_empty() {
        log::info!("Nothing to recover...");
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

fn find_evm_uncommitted_blocks(blocks: Vec<BlockNum>) -> Vec<EvmBlockRange> {
    let mut result = Vec::new();
    for i in 0..blocks.len() - 1 {
        let previous = blocks[i];
        let current = blocks[i + 1];

        if current - previous != 1 {
            log::info!("Found missing block(s): {previous}, ...missing block(s)..., {current}");
            result.push(EvmBlockRange::new(previous + 1, current - 1));
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
}
