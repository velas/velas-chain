use anyhow::*;
use evm_state::BlockNum;
use solana_storage_bigtable::LedgerStorage;

#[derive(Debug, PartialEq, Eq)]
pub struct BlockRange {
    pub first: u64,
    pub last: u64,
}

impl BlockRange {
    pub fn new(first: u64, last: u64) -> Self {
        if first > last {
            panic!("The last block ID should be greater or equal to the first block ID")
        }
        Self { first, last }
    }

    pub fn count(&self) -> u64 {
        self.last - self.first + 1
    }
}

pub async fn find(ledger: &LedgerStorage, start_block: BlockNum, limit: usize) -> Result<()> {
    let blocks = ledger
        .get_evm_confirmed_blocks(start_block, limit)
        .await
        .context(format!(
            "Unable to get EVM confirmed block's IDs starting with block {} limiteb by {}",
            start_block, limit
        ))?;

    let missing_blocks = find_evm_uncommitted_blocks(blocks);

    if missing_blocks.is_empty() {
        log::info!("Missing blocks starting from block {start_block} with a limit of {limit} are not found");
    }

    Ok(())
}

fn find_evm_uncommitted_blocks(blocks: Vec<BlockNum>) -> Vec<BlockRange> {
    let mut result = Vec::new();
    for i in 0..blocks.len() - 1 {
        let previous = blocks[i];
        let current = blocks[i + 1];

        if current - previous != 1 {
            let first = previous + 1;
            let last = current - 1;
            let missing_range = BlockRange::new(first, last);
            if missing_range.count() == 1 {
                log::info!("Found missing block: {}", first);
            } else {
                log::info!("Found missing block range: [{}, {}]", first, last);
            }
            result.push(missing_range);
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
            vec![BlockRange { first: 4, last: 7 }]
        )
    }

    #[test]
    fn test_find_missing_blocks_multirange() {
        let confirmed_blocks = vec![1, 2, 5, 6, 10, 11, 13];
        assert_eq!(
            find_evm_uncommitted_blocks(confirmed_blocks),
            vec![
                BlockRange { first: 3, last: 4 },
                BlockRange { first: 7, last: 9 },
                BlockRange {
                    first: 12,
                    last: 12
                }
            ]
        );
    }
}
