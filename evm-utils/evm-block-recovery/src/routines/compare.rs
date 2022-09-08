use std::collections::HashSet;

use anyhow::*;
use solana_storage_bigtable::LedgerStorage;

pub async fn compare_native(
    start_slot: u64,
    limit: usize,
    credible_ledger: LedgerStorage,
    dubious_ledger: LedgerStorage,
) -> Result<()> {
    crate::log(
        log::Level::Info,
        format!("Getting credible blocks set: start_slot={start_slot}, limit={limit}"),
    );

    let credible_blocks = credible_ledger
        .get_confirmed_blocks(start_slot, limit)
        .await
        .context(format!(
            "Unable to get Native Confirmed Block IDs starting with slot {} limit by {}",
            start_slot, limit
        ))?;

    if credible_blocks.len() < 2 {
        bail!("Not enough blocks to calculate difference")
    }
    crate::log(
        log::Level::Info,
        format!(
            "Credible blocks start: {}, end: {}, len: {}",
            credible_blocks.first().unwrap(),
            credible_blocks.last().unwrap(),
            credible_blocks.len()
        ),
    );

    let dubious_blocks = dubious_ledger
        .get_confirmed_blocks(start_slot, limit)
        .await
        .context(format!(
            "Unable to get Native Confirmed Block IDs starting with slot {} limit by {}",
            start_slot, limit
        ))?;

    if credible_blocks.len() < 2 {
        bail!("Not enough blocks to calculate difference")
    }

    crate::log(
        log::Level::Info,
        format!(
            "Dubious blocks start: {}, end: {}, len: {}",
            dubious_blocks.first().unwrap(),
            dubious_blocks.last().unwrap(),
            dubious_blocks.len()
        ),
    );

    let credible_blocks: HashSet<_> = credible_blocks.into_iter().collect();
    let dubious_blocks: HashSet<_> = dubious_blocks.into_iter().collect();

    let diff = credible_blocks.difference(&dubious_blocks);

    crate::log(log::Level::Info, format!("Diff: {:?}", diff));

    Ok(())
}
