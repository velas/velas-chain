use solana_storage_bigtable::LedgerStorage;

pub async fn default() -> LedgerStorage {
    LedgerStorage::new(false, None)
        .await
        .expect("Failed to connect to storage")
}
