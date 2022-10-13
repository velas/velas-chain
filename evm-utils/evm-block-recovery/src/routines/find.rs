use anyhow::*;
use evm_state::BlockNum;
use serde_json::json;
use solana_storage_bigtable::LedgerStorage;

use crate::routines::BlockRange;

use super::find_uncommitted_ranges;

pub async fn find_evm(
    ledger: LedgerStorage,
    start_block: BlockNum,
    end_block: BlockNum,
    max_limit: usize,
) -> Result<()> {
    log::info!("Looking for missing EVM Blocks");
    log::info!("start_block={start_block}, end_block={end_block}, bigtable_limit={max_limit}");

    let mut start_block = start_block;
    let mut blocks = vec![];

    loop {
        let total_limit = (end_block - start_block + 1) as usize;
        let limit = usize::max(total_limit, max_limit);
        let end_block_to_query = start_block + limit as u64;
        let mut chunk = ledger
            .get_evm_confirmed_full_blocks_nums(start_block, limit)
            .await
            .context(format!(
                "Unable to get EVM Confirmed Block IDs starting with block {} limit by {}",
                start_block, limit
            ))
            .map_err(err_to_output)?;

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
        // 2. we didn't got all blocks that we requested
        if last_in_chunk >= end_block || end_block_to_query >= last_in_chunk {
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
        print_task_ok()
    } else {
        log::warn!("Found missing EVM blocks: {:?}", missing_blocks);
        print_task_alert()
    }

    Ok(())
}

pub async fn find_native(
    ledger: LedgerStorage,
    start_slot: u64,
    end_slot: u64,
    max_limit: usize,
) -> Result<()> {
    log::info!("Looking for missing Native Blocks");
    log::info!("start_slot={start_slot}, end_slot={end_slot}, bigtable_limit={max_limit}");

    let mut start_slot = start_slot;

    let mut slots = vec![];

    loop {
        let total_limit = (end_slot - start_slot + 1) as usize;
        let limit = usize::min(total_limit, max_limit);

        let mut chunk = ledger
            .get_confirmed_blocks(start_slot, limit)
            .await
            .context(format!(
                "Unable to get Native Confirmed Block IDs starting with slot {} limit by {}",
                start_slot, total_limit
            ))
            .map_err(err_to_output)?;

        let last_in_chunk = *chunk.last().unwrap();

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
        let err = "Vector of ID's is too short, try to increase a limit";
        log::warn!("{err}");
        print_task_error(err);
        bail!(err)
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

    for range in uncommitted_ranges.into_iter() {
        let slot_prev = range.first() - 1;
        let slot_curr = range.last() + 1;

        let block_prev = ledger
            .get_confirmed_block(slot_prev)
            .await
            .context(format!("Unable to get native block {slot_prev}"))
            .map_err(err_to_output)?;

        let block_curr = ledger
            .get_confirmed_block(slot_curr)
            .await
            .context(format!("Unable to get native block {slot_curr}"))
            .map_err(err_to_output)?;

        if block_prev.blockhash == block_curr.previous_blockhash {
            let checked_range = BlockRange::new(slot_prev, slot_curr);
            log::trace!("{checked_range} passed hash check");
        } else {
            log::warn!("Found missing {}", range);
            missing_ranges.push(range.clone())
        }
    }

    log::info!("Search complete");

    match missing_ranges.is_empty() {
        true => print_task_ok(),
        false => print_task_alert(),
    }

    Ok(())
}

pub fn err_to_output(error: Error) -> anyhow::Error {
    print_task_error(&format!("{error:?}"));
    error
}

fn print_task_ok() {
    println!("{}", json!({"status": "ok"}))
}

fn print_task_alert() {
    println!("{}", json!({"status": "alert"}))
}

fn print_task_error(error_kind: &str) {
    println!("{}", json!({"status": "error", "kind": error_kind}))
}
