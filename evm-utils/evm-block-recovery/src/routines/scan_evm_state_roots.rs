mod bigtable_fetcha;
mod range_map;

use {
    crate::{cli::ScanEvmStateRootsArgs, error::AppError},
    evm_state::storage::two_modes_enum::Storage,
};

pub async fn command(args: &ScanEvmStateRootsArgs) -> Result<(), AppError> {
    let ScanEvmStateRootsArgs {
        start,
        end_exclusive,
        evm_state_path,
        workers,
        secondary,
        gc,
        rangemap_json,
    } = args;
    let handle = tokio::runtime::Handle::current();
    let storage = Storage::new(evm_state_path, *secondary, *gc)?;

    let mut rangemap = range_map::MasterRange::new(rangemap_json)?;
    let mut fetcha = bigtable_fetcha::BigtableEVMBlockFetcher::new(*workers as usize);

    let expected_len = if (*start..*end_exclusive).is_empty() {
        0
    } else {
        *end_exclusive - *start
    };

    let bigtable = solana_storage_bigtable::LedgerStorage::new(
        false,
        Some(std::time::Duration::new(5, 0)),
        None,
    )
    .await
    .map_err(|source| AppError::OpenLedger {
        source,
        creds_path: None,
        instance: "velas-ledger".to_string(),
    })?;
    fetcha
        .schedule_range(&bigtable, &handle, *start..*end_exclusive)
        .await?;

    let mut actual_len = 0;
    while let Some((height, key)) = fetcha.get_block().await {
        actual_len += 1;

        let result = if let Some(ref key) = key {
            let present = storage.check_node(key.header.state_root)?;
            if present {
                "Present"
            } else {
                "No root"
            }
        } else {
            "NO BLOCK"
        };
        rangemap.update(height, result.to_string())?;
        log::trace!("{} -> {:?}, {}", height, key, result,);
    }
    assert_eq!(
        actual_len, expected_len,
        "actually processed {} mismatches expected {}",
        actual_len, expected_len
    );
    Ok(())
}
