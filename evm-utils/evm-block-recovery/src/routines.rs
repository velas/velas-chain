pub(crate) mod check_evm;
pub(crate) mod check_native;
pub(crate) mod compare;
pub(crate) mod find;
pub(crate) mod repeat;
pub(crate) mod restore_chain;
pub(crate) mod upload;

pub use check_evm::check_evm;
pub use check_native::check_native;
pub use compare::compare_native;
pub use find::{find_evm, find_native};
pub use repeat::{repeat_evm, repeat_native};
pub use restore_chain::restore_chain;
pub use upload::upload;

use anyhow::*;

async fn write_blocks_collection(
    ledger: &solana_storage_bigtable::LedgerStorage,
    blocks: Vec<evm_state::Block>,
) -> Result<()> {
    for block in blocks {
        log::info!(
            "Writing block {} with hash {} to the Ledger...",
            block.header.block_number,
            block.header.hash()
        );

        let block_num = block.header.block_number;

        // TODO: informative message if early-return
        ledger
            .upload_evm_block(block_num, block)
            .await
            .context(format!("Unable to write block {block_num} to bigtable"))?;
    }

    Ok(())
}

fn find_uncommitted_ranges(blocks: Vec<u64>) -> Vec<BlockRange> {
    let mut result = Vec::new();
    for i in 0..blocks.len() - 1 {
        let previous = blocks[i];
        let current = blocks[i + 1];

        if current - previous != 1 {
            let first = previous + 1;
            let last = current - 1;
            let missing_range = BlockRange::new(first, last);
            // log::info!("Found missing {missing_range}");
            result.push(missing_range);
        }
    }

    result
}

#[derive(Debug, PartialEq, Eq, Clone, serde::Serialize)]
pub enum BlockRange {
    SingleBlock(u64),
    InclusiveRange(u64, u64),
}

impl BlockRange {
    pub fn new(first: u64, last: u64) -> Self {
        if first > last {
            panic!("The last block ID should be greater or equal to the first block ID")
        }
        if first == last {
            return Self::SingleBlock(first);
        }
        Self::InclusiveRange(first, last)
    }

    pub fn first(&self) -> u64 {
        match self {
            BlockRange::SingleBlock(single) => *single,
            BlockRange::InclusiveRange(first, _) => *first,
        }
    }

    pub fn last(&self) -> u64 {
        match self {
            BlockRange::SingleBlock(single) => *single,
            BlockRange::InclusiveRange(_, last) => *last,
        }
    }
}

impl std::fmt::Display for BlockRange {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BlockRange::SingleBlock(s) => write!(fmt, "single block: {s}"),
            BlockRange::InclusiveRange(f, l) => write!(fmt, "inclusive range: [{f}; {l}]"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_missing_blocks() {
        let confirmed_blocks = vec![1, 2, 3, 8, 9, 10];
        assert_eq!(
            find_uncommitted_ranges(confirmed_blocks),
            vec![BlockRange::InclusiveRange(4, 7)]
        )
    }

    #[test]
    fn test_find_missing_blocks_multirange() {
        let confirmed_blocks = vec![1, 2, 5, 6, 10, 11, 13];
        assert_eq!(
            find_uncommitted_ranges(confirmed_blocks),
            vec![
                BlockRange::InclusiveRange(3, 4),
                BlockRange::InclusiveRange(7, 9),
                BlockRange::SingleBlock(12)
            ]
        );
    }
}
