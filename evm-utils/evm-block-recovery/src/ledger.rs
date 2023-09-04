use {
    crate::error::AppError,
    solana_storage_bigtable::{LedgerStorage, LedgerStorageConfig, DEFAULT_APP_PROFILE_ID},
    solana_transaction_status::ConfirmedBlock,
    std::time::Duration,
};

pub async fn with_params(
    creds_path: Option<String>,
    instance: String,
) -> Result<LedgerStorage, AppError> {
    log::info!(
        "Creating LedgerStorage: creds_path='{:?}', instance='{}'",
        creds_path,
        instance
    );
    let config = LedgerStorageConfig {
        read_only: false,
        timeout: None,
        credential_type: solana_storage_bigtable::CredentialType::Filepath(creds_path.clone()),
        instance_name: instance.clone(),
        app_profile_id: DEFAULT_APP_PROFILE_ID.to_string(),
    };
    LedgerStorage::new_with_config(config)
        .await
        .map_err(|source| AppError::OpenLedger {
            source,
            creds_path,
            instance,
        })
}

// struct BTCreds {
//     creds_path: Option<String>,
//     instance: String,
// }

#[derive(Debug)]
pub enum Fetched<T> {
    BlockFound(T),
    BlockNotFound,
}

fn to_fetched<T>(
    result: solana_storage_bigtable::Result<T>,
    slot: u64,
) -> Result<Fetched<T>, AppError> {
    match result {
        Ok(block) => Ok(Fetched::BlockFound(block)),
        Err(error) => match error {
            solana_storage_bigtable::Error::BlockNotFound(_) => Ok(Fetched::BlockNotFound),
            other_error => Err(AppError::GetNativeBlock {
                source: other_error,
                block: slot,
            }),
        },
    }
}

/// Tries to fetch native block from bigtable `ledger` with configurable retry
///
/// * `slot` - number of block to fetch
/// * `num_retries` - number of retries
/// * `pause` - function which generates pause duration for nth retry
pub async fn get_native_block_obsessively<P: Fn(u64) -> Duration>(
    ledger: &mut LedgerStorage,
    slot: u64,
    num_retries: u64,
    pause: P,
    // reinstantiate_ledger: Option<BTCreds>
) -> Result<Fetched<ConfirmedBlock>, AppError> {
    let mut result = to_fetched(ledger.get_confirmed_block(slot).await, slot);

    if result.is_err() {
        for n in 0..num_retries {
            let pause = pause(n + 1);
            let pause_ms = pause.as_millis();

            log::info!(
                "Block {} fetch failed, retry [{}] after {} ms...",
                slot,
                n + 1,
                pause_ms
            );
            log::warn!("Fail reason: {}", result.unwrap_err());

            tokio::time::sleep(pause).await;

            result = to_fetched(ledger.get_confirmed_block(slot).await, slot);

            if result.is_ok() {
                log::info!("Retry success!");
                break;
            }
        }
    }

    result
}
