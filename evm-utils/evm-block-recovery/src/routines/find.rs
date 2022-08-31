use anyhow::*;
use evm_state::BlockNum;
use solana_storage_bigtable::LedgerStorage;

use crate::routines::BlockRange;

use super::find_uncommitted_ranges;

pub async fn find_evm(ledger: LedgerStorage, start_block: BlockNum, limit: usize) -> Result<()> {
    log::info!("Looking for missing EVM Blocks");

    let blocks = ledger
        .get_evm_confirmed_full_blocks_nums(start_block, limit)
        .await
        .context(format!(
            "Unable to get EVM Confirmed Block IDs starting with block {} limit by {}",
            start_block, limit
        ))?;

    let missing_blocks = find_uncommitted_ranges(blocks);

    if missing_blocks.is_empty() {
        log::info!("Missing EVM Blocks starting from block {start_block} with a limit of {limit} are not found");
    }

    Ok(())
}

pub async fn find_native(ledger: LedgerStorage, start_slot: u64, end_slot: u64) -> Result<()> {
    const LOAD_CHUNK_SIZE: usize = 500_000;

    let mut start_slot = start_slot;
    let mut limit = (end_slot - start_slot) as usize;

    let mut slots = vec![];

    log::info!(
        "Looking for missing Native Blocks, start slot: {start_slot}, end slot: {end_slot}."
    );

    loop {
        let size = usize::min(limit, LOAD_CHUNK_SIZE);

        let mut chunk = ledger
            .get_confirmed_blocks(start_slot, size)
            .await
            .context(format!(
                "Unable to get Native Confirmed Block IDs starting with slot {} limit by {}",
                start_slot, limit
            ))?;

        let last_in_chunk = *chunk.last().unwrap();

        if last_in_chunk < end_slot {
            start_slot = last_in_chunk + 1;
            limit = (end_slot - start_slot) as usize;
            slots.extend(chunk.iter());
            log::info!("Slot #{last_in_chunk} loaded...");
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

    let missing_ranges = find_uncommitted_ranges(slots);

    log::info!("Found {} possibly missing ranges", missing_ranges.len());

    for range in missing_ranges.into_iter() {
        let slot_prev = range.first() - 1;
        let slot_curr = range.last() + 1;

        let block_prev = ledger
            .get_confirmed_block(slot_prev)
            .await
            .context(format!("Unable to get native block {slot_prev}"))?;

        let block_curr = ledger
            .get_confirmed_block(slot_curr)
            .await
            .context(format!("Unable to get native block {slot_curr}"))?;

        if block_prev.blockhash == block_curr.previous_blockhash {
            let checked_range = BlockRange::new(slot_prev, slot_curr);
            log::trace!("{checked_range} passed hash check");
        } else {
            log::warn!("Found missing {}", range);
        }
    }

    log::info!("Search complete");

    Ok(())
}
