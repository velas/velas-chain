use anyhow::*;
use solana_storage_bigtable::LedgerStorage;

pub async fn default() -> Result<LedgerStorage> {
    log::info!("Creating LedgerStorage using default method");
    LedgerStorage::new(false, None)
        .await
        .context("Failed to create LedgerStorage using default method")
}

pub async fn with_params(creds_path: String, instance: String) -> Result<LedgerStorage> {
    log::info!(
        "Creating custom LedgerStorage: creds_path='{}', instance={}",
        creds_path,
        instance
    );

    LedgerStorage::new_with_parameters(false, None, creds_path, instance)
        .await
        .context("Can't create custom LedgerStorage")
}
