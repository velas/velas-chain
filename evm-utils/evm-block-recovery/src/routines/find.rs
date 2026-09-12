use {
    super::find_uncommitted_ranges,
    crate::{
        cli::{FindEvmArgs, FindNativeArgs},
        error::AppError,
        ledger,
        routines::BlockRange,
    },
    std::time::Duration,
};

pub type FindResult = Result<WhatFound, AppError>;

pub enum WhatFound {
    AllGood,
    ThereAreMisses(Vec<BlockRange>),
}

/// Pause calculator for Nth retry
///
/// * `n` - number of retry
fn retry_pause(n: u64) -> Duration {
    let ms = n * n * 1300; // Approx. ~22min total for 15 retries
    Duration::from_millis(ms)
}

pub async fn find_evm(creds: Option<String>, instance: String, args: FindEvmArgs) -> FindResult {
    let FindEvmArgs {
        start_block,
        end_block,
        limit,
        bigtable_limit,
    } = args;

    let end_block = calculate_end_block(start_block, end_block, limit)?;

    log::info!("Looking for missing EVM Blocks");
    log::info!("start_block={start_block}, end_block={end_block}, bigtable_limit={bigtable_limit}");

    let ledger = ledger::with_params(creds, instance).await?;

    let mut start_block = start_block;
    let mut blocks = vec![];

    loop {
        let remaining_blocks = (end_block - start_block) as usize;

        let limit = usize::min(remaining_blocks, bigtable_limit);
        let end_block_to_query = start_block + limit as u64;

        log::trace!("Requesting range #{start_block}..#{end_block_to_query}...");
        let mut chunk = ledger
            .get_evm_confirmed_full_blocks_nums(start_block, limit)
            .await
            .map_err(|source| AppError::GetEvmBlockNums {
                source,
                start_block,
                limit,
            })?;

        let last_in_chunk = if let Some(block) = chunk.last() {
            *block
        } else {
            // we reach the end just after last successfull query
            log::debug!(
                "Bigtable didn't return anything for range #{start_block}..#{end_block_to_query}"
            );
            break;
        };

        if last_in_chunk > end_block {
            chunk.retain(|block| *block <= end_block);
        }

        blocks.extend(chunk.iter());
        start_block = last_in_chunk + 1;
        log::trace!("Block #{last_in_chunk} loaded...");

        // If we reach the end
        // 1. we go outside of requested range
        // 2. we receive less than requested
        if last_in_chunk >= end_block || chunk.len() < limit {
            log::trace!("Reaching the end of chunk...");
            break;
        }
    }

    let missing_blocks = find_uncommitted_ranges(blocks, start_block, end_block);

    if missing_blocks.is_empty() {
        log::info!(
            "Missing EVM Blocks in range: start_block={}, end_block={} are not found",
            start_block,
            end_block
        );
        Ok(WhatFound::AllGood)
    } else {
        log::warn!("Found missing EVM blocks: {:?}", missing_blocks);
        Ok(WhatFound::ThereAreMisses(missing_blocks))
    }
}

pub async fn find_native(
    creds: Option<String>,
    instance: String,
    args: FindNativeArgs,
) -> FindResult {
    let FindNativeArgs {
        start_block,
        end_block,
        limit,
        bigtable_limit,
    } = args;

    let mut start_slot = start_block;

    let end_slot = calculate_end_block(start_block, end_block, limit)?;

    log::info!("Looking for missing Native Blocks");
    log::info!("start_slot={start_slot}, end_slot={end_slot}, bigtable_limit={bigtable_limit}");

    let mut ledger = ledger::with_params(creds, instance).await?;

    let mut slots = vec![];

    loop {
        let total_limit = (end_slot - start_slot + 1) as usize;
        let limit = usize::min(total_limit, bigtable_limit);

        let mut chunk = ledger
            .get_confirmed_blocks(start_slot, limit)
            .await
            .map_err(|source| AppError::GetNativeBlocks {
                source,
                start_block,
                limit,
            })?;

        let last_in_chunk = if let Some(block) = chunk.last() {
            *block
        } else {
            // we reach the end just after last successfull query
            log::debug!("Bigtable didn't return anything for range #{start_slot}..#{end_slot}");
            break;
        };

        if last_in_chunk < end_slot {
            start_slot = last_in_chunk + 1;
            slots.extend(chunk.iter());
            log::trace!("Slot #{last_in_chunk} loaded...");
        } else {
            chunk.retain(|slot| *slot <= end_slot);
            slots.extend(chunk.iter());
            log::info!("All slots loaded.");
            break;
        }
    }

    if slots.len() < 2 {
        return Err(AppError::VectorIsTooShort);
    }

    log::info!(
        "Got {} slot numbers. First slot: {}, last slot: {}",
        slots.len(),
        slots.first().unwrap(),
        slots.last().unwrap()
    );

    if slots[0] > start_slot {
        let missing_ahead = BlockRange::new(start_slot, slots[0] - 1);
        log::warn!("Found possibly missing {missing_ahead}, manual check required");
    }

    let uncommitted_ranges = find_uncommitted_ranges(slots, start_slot, end_slot);
    let mut missing_ranges = vec![];

    log::info!("Found {} possibly missing ranges", uncommitted_ranges.len());

    use ledger::Fetched::*;

    for range in uncommitted_ranges.into_iter() {
        let slot_prev = range.first() - 1;
        let slot_curr = range.last() + 1;

        let block_prev =
            ledger::get_native_block_obsessively(&mut ledger, slot_prev, 15, retry_pause).await?;

        let block_curr =
            ledger::get_native_block_obsessively(&mut ledger, slot_curr, 15, retry_pause).await?;

        match (block_prev, block_curr) {
            (BlockFound(block_prev), BlockFound(block_curr)) => {
                if block_prev.blockhash == block_curr.previous_blockhash {
                    let checked_range = BlockRange::new(slot_prev, slot_curr);
                    log::trace!("{checked_range} passed hash check");
                } else {
                    log::warn!("Found missing {}", range);
                    missing_ranges.push(range.clone())
                }
            }
            (BlockNotFound, _) => {
                log::warn!("Block {slot_prev} not found in table");
                missing_ranges.push(range.clone())
            }
            (_, BlockNotFound) => {
                log::warn!("Block {slot_curr} not found in table");
                missing_ranges.push(range.clone())
            }
        }
    }

    if missing_ranges.is_empty() {
        log::info!("Search complete. No missing ranges are found.");
        Ok(WhatFound::AllGood)
    } else {
        log::warn!(
            "Search complete. Found missing ranges: {:?}",
            &missing_ranges
        );
        Ok(WhatFound::ThereAreMisses(missing_ranges))
    }
}

fn calculate_end_block(
    start_block: u64,
    end_block: Option<u64>,
    limit: Option<u64>,
) -> Result<u64, AppError> {
    if end_block.is_none() && limit.is_none() {
        log::error!("Not enough arguments to calculate `end_block`");
        return Err(AppError::NoLastBlockBoundary);
    }

    if let Some(end_block) = end_block {
        return Ok(end_block);
    }

    if let Some(limit) = limit {
        return Ok(start_block + limit - 1);
    }

    unreachable!()
}
