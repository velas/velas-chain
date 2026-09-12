use {
    crate::{
        cli::CompareNativeArgs,
        error::{AppError, RoutineResult},
        ledger,
    },
    std::collections::HashSet,
};

pub async fn compare_native(args: CompareNativeArgs) -> RoutineResult {
    let CompareNativeArgs {
        start_slot,
        limit,
        credible_ledger_creds,
        credible_ledger_instance,
        dubious_ledger_creds,
        dubious_ledger_instance,
    } = args;

    let credible_ledger =
        ledger::with_params(Some(credible_ledger_creds), credible_ledger_instance).await?;

    let dubious_ledger =
        ledger::with_params(Some(dubious_ledger_creds), dubious_ledger_instance).await?;

    log::info!("Getting credible blocks set: start_slot={start_slot}, limit={limit}");

    let credible_blocks = credible_ledger
        .get_confirmed_blocks(start_slot, limit)
        .await
        .map_err(|source| AppError::GetNativeBlocks {
            source,
            start_block: start_slot,
            limit,
        })?;

    if credible_blocks.len() < 2 {
        return Err(AppError::NotEnoughBlocksToCompare);
    }

    log::info!(
        "Credible blocks start: {}, end: {}, len: {}",
        credible_blocks.first().unwrap(),
        credible_blocks.last().unwrap(),
        credible_blocks.len()
    );

    let dubious_blocks = dubious_ledger
        .get_confirmed_blocks(start_slot, limit)
        .await
        .map_err(|source| AppError::GetNativeBlocks {
            source,
            start_block: start_slot,
            limit,
        })?;

    if credible_blocks.len() < 2 {
        return Err(AppError::NotEnoughBlocksToCompare);
    }

    log::info!(
        "Dubious blocks start: {}, end: {}, len: {}",
        dubious_blocks.first().unwrap(),
        dubious_blocks.last().unwrap(),
        dubious_blocks.len()
    );

    let credible_blocks: HashSet<_> = credible_blocks.into_iter().collect();
    let dubious_blocks: HashSet<_> = dubious_blocks.into_iter().collect();

    let diff = credible_blocks.difference(&dubious_blocks);

    log::info!("Diff: {:?}", diff);

    Ok(())
}
