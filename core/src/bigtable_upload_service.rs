use solana_ledger::blockstore::Blockstore;
use solana_runtime::commitment::BlockCommitmentCache;
use std::{
    sync::atomic::{AtomicBool, Ordering},
    sync::{Arc, RwLock},
    thread::{self, Builder, JoinHandle},
};
use tokio::runtime;

// Delay uploading the largest confirmed root for this many slots.  This is done in an attempt to
// ensure that the `CacheBlockTimeService` has had enough time to add the block time for the root
// before it's uploaded to BigTable.
//
// A more direct connection between CacheBlockTimeService and BigTableUploadService would be
// preferable...
const LARGEST_CONFIRMED_ROOT_UPLOAD_DELAY: usize = 100;

pub struct BigTableUploadService {
    thread: JoinHandle<()>,
}

impl BigTableUploadService {
    pub fn new(
        runtime_handle: runtime::Handle,
        bigtable_ledger_storage: solana_storage_bigtable::LedgerStorage,
        blockstore: Arc<Blockstore>,
        block_commitment_cache: Arc<RwLock<BlockCommitmentCache>>,
        exit: Arc<AtomicBool>,
    ) -> Self {
        info!("Starting BigTable upload service");
        let thread = Builder::new()
            .name("bigtable-upload".to_string())
            .spawn(move || {
                Self::run(
                    runtime_handle,
                    bigtable_ledger_storage,
                    blockstore,
                    block_commitment_cache,
                    exit,
                )
            })
            .unwrap();

        Self { thread }
    }

    fn run(
        runtime: runtime::Handle,
        bigtable_ledger_storage: solana_storage_bigtable::LedgerStorage,
        blockstore: Arc<Blockstore>,
        block_commitment_cache: Arc<RwLock<BlockCommitmentCache>>,
        exit: Arc<AtomicBool>,
    ) {
        let mut start_slot = 0;
        let mut start_evm_block = 0;
        loop {
            if exit.load(Ordering::Relaxed) {
                break;
            }

            let end_slot = block_commitment_cache
                .read()
                .unwrap()
                .highest_confirmed_root()
                .saturating_sub(LARGEST_CONFIRMED_ROOT_UPLOAD_DELAY as u64);

            if end_slot <= start_slot {
                std::thread::sleep(std::time::Duration::from_secs(1));
                continue;
            }

            let result = runtime.block_on(solana_ledger::bigtable_upload::upload_confirmed_blocks(
                blockstore.clone(),
                bigtable_ledger_storage.clone(),
                start_slot,
                Some(end_slot),
                true,
                false,
                exit.clone(),
            ));

            match result {
                Ok(()) => start_slot = end_slot,
                Err(err) => {
                    warn!("bigtable: upload_confirmed_blocks: {}", err);
                    std::thread::sleep(std::time::Duration::from_secs(2));
                }
            }
            // start to process evm blocks, only if something changed on native chain
            let end_block = blockstore.get_last_available_evm_block().unwrap_or(0);
            if end_block <= start_evm_block {
                std::thread::sleep(std::time::Duration::from_secs(1));
                continue;
            }
            let result =
                runtime.block_on(solana_ledger::bigtable_upload::upload_evm_confirmed_blocks(
                    blockstore.clone(),
                    bigtable_ledger_storage.clone(),
                    start_evm_block,
                    Some(end_block),
                    false,
                    false,
                    exit.clone(),
                ));

            match result {
                Ok(not_confirmed_blocks) => {
                    start_evm_block = end_block - not_confirmed_blocks;
                }
                Err(err) => {
                    warn!("bigtable: upload_evm_confirmed_blocks: {}", err);
                    std::thread::sleep(std::time::Duration::from_secs(2));
                }
            }
        }
    }

    pub fn join(self) -> thread::Result<()> {
        self.thread.join()
    }
}
