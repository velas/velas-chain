use anyhow::*;
use evm_state::BlockNum;
use solana_storage_bigtable::LedgerStorage;

#[derive(Debug, PartialEq, Eq)]
pub struct EvmBlockRange {
    pub first: BlockNum,
    pub last: BlockNum,
}

impl EvmBlockRange {
    pub fn new(first: BlockNum, last: BlockNum) -> Self {
        Self { first, last }
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
