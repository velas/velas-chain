use std::time::Duration;

use solana_storage_bigtable::LedgerStorage;
use solana_transaction_status::ConfirmedBlockWithOptionalMetadata;

use crate::error::AppError;

const NUM_RETRIES: usize = 5;
const RETRY_PAUSE: Duration = Duration::from_secs(10);

pub async fn with_params(
    creds_path: Option<String>,
    instance: String,
) -> Result<LedgerStorage, AppError> {
    log::info!(
        "Creating LedgerStorage: creds_path='{:?}', instance='{}'",
        creds_path,
        instance
    );

    LedgerStorage::new_with_custom_instance(false, None, creds_path.clone(), instance.clone())
        .await
        .map_err(|source| AppError::OpenLedger {
            source,
            creds_path,
            instance,
        })
}

pub async fn get_confirmed_blocks(
    ledger: &LedgerStorage,
    start_slot: u64,
    limit: usize,
) -> Result<Vec<u64>, AppError> {
    let mut source = None;

    for _ in 0..NUM_RETRIES {
        match ledger.get_confirmed_blocks(start_slot, limit).await {
            Ok(blocks) => return Ok(blocks),
            Err(error) => source = Some(error),
        }

        tokio::time::sleep(RETRY_PAUSE).await;
    }

    Err(AppError::GetNativeBlocks {
        source: source.unwrap(),
        start_block: start_slot,
        limit,
    })
}

pub async fn get_confirmed_block(
    ledger: &LedgerStorage,
    slot: u64,
) -> Result<ConfirmedBlockWithOptionalMetadata, AppError> {
    let mut source = None;

    for _ in 0..NUM_RETRIES {
        match ledger.get_confirmed_block(slot).await {
            Ok(block) => return Ok(block),
            Err(error) => source = Some(error),
        }

        tokio::time::sleep(RETRY_PAUSE).await;
    }

    Err(AppError::GetNativeBlock {
        source: source.unwrap(),
        block: slot,
    })
}
