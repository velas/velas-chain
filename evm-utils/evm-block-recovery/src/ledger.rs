use anyhow::*;
use solana_storage_bigtable::LedgerStorage;

pub async fn with_params(creds_path: Option<String>, instance: String) -> Result<LedgerStorage> {
    match creds_path {
        Some(creds_path) => {
            log::info!(
                "Creating custom LedgerStorage: creds_path='{}', instance={}",
                creds_path,
                instance
            );

            LedgerStorage::new_with_parameters(false, None, creds_path, instance)
                .await
                .context("Can't create custom LedgerStorage")
        }
        None => {
            log::info!("Creating LedgerStorage from environment");

            let is_set = if std::env::var("GOOGLE_APPLICATION_CREDENTIALS").is_ok() {
                "is set"
            } else {
                "is not set"
            };
            log::info!(r#"Environment Variable "GOOGLE_APPLICATION_CREDENTIALS" {is_set}."#);

            LedgerStorage::new(false, None)
                .await
                .context("Failed to create LedgerStorage using default method")
        }
    }
}
