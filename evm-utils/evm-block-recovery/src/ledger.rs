use solana_storage_bigtable::LedgerStorage;

pub async fn with_params(
    creds_path: Option<String>,
    instance: String,
) -> Result<LedgerStorage, solana_storage_bigtable::Error> {
    log::info!(
        "Creating LedgerStorage: creds_path='{:?}', instance='{}'",
        creds_path,
        instance
    );

    LedgerStorage::new_with_custom_instance(false, None, creds_path, instance).await
}
