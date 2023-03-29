use std::time::Duration;

use solana_storage_bigtable::LedgerStorage;
use solana_transaction_status::ConfirmedBlockWithOptionalMetadata;

use crate::error::AppError;

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

// struct BTCreds {
//     creds_path: Option<String>,
//     instance: String,
// }

/// Tries to fetch native block from bigtable with configurable retry
/// 
/// * `slot` - number of block to fetch
/// * `num_retries` - number of retries
/// * `pause` - function which generates pause duration for nth retry
pub async fn get_native_block_obsessively<P: Fn(usize) -> Duration>(
    ledger: &mut LedgerStorage,
    slot: u64,
    num_retries: usize,
    pause: P,
    // reinstantiate_ledger: Option<BTCreds>
) -> Result<ConfirmedBlockWithOptionalMetadata, AppError> {
    for n in 0..num_retries+1 {
        let result = ledger.get_confirmed_block(slot).await;
        
        match result {
            Ok(block) => return Ok(block),
            Err(source) => {
                if n == num_retries {
                    return Err(AppError::GetNativeBlock {
                        source,
                        block: slot,
                    })
                }
                tokio::time::sleep(pause(n+1)).await;
            },
        }
    }

    unreachable!()
}
