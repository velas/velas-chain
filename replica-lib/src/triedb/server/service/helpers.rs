use std::{sync::Arc, thread, time::Duration};

use evm_state::BlockNum;
use solana_ledger::blockstore::Blockstore;

use crate::triedb::{
    error::evm_height,
    range::RangeJSON,
    server::config::{Config, HeightIndexSource, RangeSource},
    CachedRootsLedgerStorage, EvmHeightIndex, ReadRange,
};

use super::DispatchSourcesError;

pub(super) fn maybe_init_bigtable(
    config: Config,
    runtime: &tokio::runtime::Runtime,
) -> Result<Option<CachedRootsLedgerStorage>, evm_height::Error> {
    let bigtable = match (config.range_source, config.height_index_source) {
        (RangeSource::BigtableBlockstore, _) | (_, HeightIndexSource::BigtableBlockstore) => {
            let result = init_bigtable(runtime, config.bigtable_length_hint)?;
            Some(result)
        }
        _ => None,
    };
    Ok(bigtable)
}

fn init_bigtable(
    runtime: &tokio::runtime::Runtime,
    bigtable_length_hint: BlockNum,
) -> Result<CachedRootsLedgerStorage, evm_height::Error> {

    log::warn!("init bigtable called");
    let bigtable_blockstore = runtime.block_on(async {
        let bigtable_blockstore = solana_storage_bigtable::LedgerStorage::new(
            false,
            Some(std::time::Duration::new(20, 0)),
            None,
        )
        .await;

        let bigtable_blockstore = match bigtable_blockstore {
            Err(err) => return Err(evm_height::Error::from(err)),
            Ok(bigtable_blockstore) => bigtable_blockstore,
        };
        let bigtable_blockstore =
            CachedRootsLedgerStorage::new(bigtable_blockstore, bigtable_length_hint);
        match bigtable_blockstore.get_last_available_block().await {
            Err(err) => {
                log::error!("ledger storage sanity check failed {:#?}", err);
                return Err(err);
            }
            Ok(height) => {
                log::info!("ledger storage sanity check done : last height {}", height);
            }
        }
        Ok(bigtable_blockstore)
    })?;
    Ok(bigtable_blockstore)
}

type DispatchResult = Result<(Box<dyn ReadRange>, Box<dyn EvmHeightIndex>), DispatchSourcesError>;

const SECONDARY_CATCH_UP_SECONDS: u64 = 40;

fn spin_off_sync_up_thread(solana_blockstore: Arc<Blockstore>) {
    let _jh = std::thread::spawn(move || loop {
        match solana_blockstore.try_catch_up_with_primary() {
            Ok(true) => {
                log::warn!("successfully synced up secondary solana_blockstore with primary");
            }
            Err(err) => {
                log::error!(
                    "problem with syncing up secondary solana_blockstore with primary {:?}",
                    err
                );
            }
            _ => {}
        }

        thread::sleep(Duration::new(SECONDARY_CATCH_UP_SECONDS, 0));
    });
}

pub(super) fn dispatch_sources(
    config: Config,
    bigtable_blockstore: Option<CachedRootsLedgerStorage>,
    solana_blockstore: Option<Arc<Blockstore>>,
) -> DispatchResult {
    let mut sol_blockstore_selected = false;
    let range: Box<dyn ReadRange> = match config.range_source {
        RangeSource::JSON { file } => {
            let file = file.ok_or(DispatchSourcesError::EmptyJsonFileArg)?;
            let range = RangeJSON::new(file, None)?;
            Box::new(range)
        }
        RangeSource::BigtableBlockstore => {
            let bigtable_blockstore = bigtable_blockstore
                .clone()
                .ok_or(DispatchSourcesError::BigtableNonInit)?;
            Box::new(bigtable_blockstore)
        }

        RangeSource::SolanaBlockstore => {
            let solana_blockstore = solana_blockstore
                .clone()
                .ok_or(DispatchSourcesError::SolanaBlockstoreNonInit)?;
            spin_off_sync_up_thread(solana_blockstore.clone());
            sol_blockstore_selected = true;
            Box::new(solana_blockstore)
        }
    };
    let index: Box<dyn EvmHeightIndex> = match config.height_index_source {
        HeightIndexSource::BigtableBlockstore => {
            let bigtable_blockstore =
                bigtable_blockstore.ok_or(DispatchSourcesError::BigtableNonInit)?;
            Box::new(bigtable_blockstore)
        }

        HeightIndexSource::SolanaBlockstore => {
            let solana_blockstore =
                solana_blockstore.ok_or(DispatchSourcesError::SolanaBlockstoreNonInit)?;
            if !sol_blockstore_selected {
                spin_off_sync_up_thread(solana_blockstore.clone());
            }
            Box::new(solana_blockstore)
        }
    };
    Ok((range, index))
}
