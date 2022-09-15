use anyhow::*;
use evm_state::BlockNum;
use solana_storage_bigtable::LedgerStorage;

use crate::routines::BlockRange;

use super::find_uncommitted_ranges;

pub async fn find_evm(ledger: LedgerStorage, start_block: BlockNum, end_block: u64) -> Result<()> {
    log::info!("Looking for missing EVM Blocks");
    
    let limit = (end_block - start_block) as usize;

    let mut blocks = ledger
        .get_evm_confirmed_full_blocks_nums(start_block, limit)
        .await
        .context(format!(
            "Unable to get EVM Confirmed Block IDs starting with block {} limit by {}",
            start_block, end_block
        ))?;

    blocks.retain_mut(|block| *block <= end_block);

    let missing_blocks = find_uncommitted_ranges(blocks);

    if missing_blocks.is_empty() {
        log::info!("Missing EVM Blocks in range: start_block:={}, end_block= {} are not found", start_block, end_block);
    }

    Ok(())
}

pub async fn find_native(ledger: LedgerStorage, start_slot: u64, end_slot: u64, max_limit: usize) -> Result<()> {
    let mut start_slot = start_slot;
    let mut total_limit = (end_slot - start_slot) as usize;

    let mut slots = vec![];

    log::info!(
        "Looking for missing Native Blocks, start slot: {start_slot}, end slot: {end_slot}."
    );

    loop {
        let limit = usize::min(total_limit, max_limit);

        let mut chunk = ledger
            .get_confirmed_blocks(start_slot, limit)
            .await
            .context(format!(
                "Unable to get Native Confirmed Block IDs starting with slot {} limit by {}",
                start_slot, total_limit
            ))?;

        let last_in_chunk = *chunk.last().unwrap();

        if last_in_chunk < end_slot {
            start_slot = last_in_chunk + 1;
            total_limit = (end_slot - start_slot) as usize;
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
