use anyhow::*;
use solana_storage_bigtable::LedgerStorage;

pub async fn default() -> Result<LedgerStorage> {
    log::info!("Creating LedgerStorage using default method");
    LedgerStorage::new(false, None)
        .await
        .context("Failed to create LedgerStorage using default method")
}

pub async fn with_params(token: String, instance: String) -> Result<LedgerStorage> {
    log::info!(
        "Creating custom LedgerStorage: token_path='{}', instance={}",
        token,
        instance
    );

    LedgerStorage::new_with_parameters(false, None, token, instance)
        .await
        .context("Can't create custom LedgerStorage")
}
