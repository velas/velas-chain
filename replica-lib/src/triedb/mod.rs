pub mod bigtable;
mod blockstore;
pub mod client;
pub mod error;
pub mod range;
pub mod server;
pub use bigtable::CachedRootsLedgerStorage;
pub use server::config::{Config, HeightIndexSource, ParseError, RangeSource};

use std::{
    ops::Range,
    time::{Duration, Instant},
};

use evm_state::{BlockNum, Storage, H256};
use triedb::{gc::DbCounter, Database};

use rocksdb::{DBWithThreadMode, SingleThreaded};

use self::error::{evm_height, lock};

use async_trait::async_trait;
use std::future::Future;

type RocksHandleA<'a> = triedb::rocksdb::RocksHandle<'a, &'a triedb::rocksdb::DB>;

pub(self) fn collection(storage: &Storage) -> triedb::gc::TrieCollection<RocksHandleA<'_>> {
    triedb::gc::TrieCollection::new(storage.rocksdb_trie_handle())
}

pub trait TryConvert<S>: Sized {
    type Error;

    fn try_from(value: S) -> Result<Self, Self::Error>;
}


// maximum number of hashes for GetArrayOfNodesRequest (should be around 200 MB
// worth of corresponding nodes)
const MAX_CHUNK_HASHES: usize = 1_000_000;

pub const DB_SEMAPHORE_PERMITS_PER_LARGE_DIFF: u32 = 10;

const MAX_TIMES: usize = 8;
const MIN_DELAY_SEC: u64 = 1;

#[derive(Clone, Copy, Debug)]
pub struct DiffRequest {
    pub heights: (evm_state::BlockNum, evm_state::BlockNum),
    pub expected_hashes: (H256, H256),
}

async fn retry_logged<T, E, Fut, FutureFn>(
    mut f: FutureFn,
    msg: String,
    level: log::Level,
) -> Result<T, E>
where
    Fut: Future<Output = Result<T, E>>,
    FutureFn: FnMut() -> Fut,
{
    let mut count = 0;
    let msg = &msg;

    log::log!(level, "attempting try to {} ({})", msg, count);
    let mut result = (f)().await;
    let mut delay = Duration::new(MIN_DELAY_SEC, 0);

    if let Err(..) = &result {
        for _ in 0..MAX_TIMES - 1 {
            tokio::time::sleep(delay).await;

            log::log!(level, "attempting try to {} ({})", msg, count);
            result = (f)().await;

            if result.is_ok() {
                break;
            }
            count += 1;
            delay *= 2;
        }
    }
    result
}

#[async_trait]
pub trait WriteRange: ReadRange {
    fn update(&self, index: BlockNum) -> std::io::Result<()>;

    fn flush(&self) -> std::io::Result<()>;
}

#[async_trait]
pub trait ReadRange: Send + Sync {
    async fn get(&self) -> Result<std::ops::Range<BlockNum>, evm_height::Error>;
}

#[async_trait]
pub trait EvmHeightIndex: Send + Sync {
    async fn get_evm_confirmed_state_root(
        &self,
        block_num: evm_state::BlockNum,
    ) -> Result<Option<H256>, evm_height::Error>;

    async fn get_evm_confirmed_state_root_retried(
        &self,
        block_num: evm_state::BlockNum,
    ) -> Result<H256, evm_height::Error> {
        retry_logged(
            || async {
                let result = self.get_evm_confirmed_state_root(block_num).await;
                match result {
                    Ok(Some(hash)) => Ok(hash),
                    Ok(None) => Err(evm_height::Error::NoHeightFound(block_num)),
                    Err(err) => Err(err),
                }
            },
            format!("get_evm_confirmed_state_root {}", block_num),
            log::Level::Trace,
        )
        .await
    }

    async fn prefetch_roots(
        &self,
        range: &Range<evm_state::BlockNum>,
    ) -> Result<(), evm_height::Error>;

    async fn prefetch_roots_retried(
        &self,
        range: &Range<evm_state::BlockNum>,
    ) -> Result<(), evm_height::Error> {
        retry_logged(
            || async { self.prefetch_roots(range).await },
            format!("prefetch_roots {:?}", range),
            log::Level::Info,
        )
        .await
    }
}

// bigtable bulk api limited by Vladimir
const MAX_PREFETCH_RANGE_CHUNK: BlockNum = 5_000;

pub(self) fn lock_root<D, F>(
    db: &D,
    locked: H256,
    func: F,
) -> Result<triedb::gc::RootGuard<'_, D, F>, lock::Error>
where
    D: Database + DbCounter,
    F: FnMut(&[u8]) -> Vec<H256>,
{
    let guard = triedb::gc::RootGuard::new(db, locked, func);
    if locked != triedb::empty_trie_hash() && !db.node_exist(locked) {
        return Err(lock::Error::NotFoundTop(locked));
    }
    Ok(guard)
}

pub(self) fn check_root(
    db: &DBWithThreadMode<SingleThreaded>,
    checked: H256,
) -> Result<(), lock::Error>
where
{
    if checked != triedb::empty_trie_hash() && db.get(checked)?.is_none() {
        return Err(lock::Error::NotFoundTop(checked));
    }
    Ok(())
}

pub fn debug_elapsed(start: &mut Instant) -> Duration {
    let duration = start.elapsed();

    *start = Instant::now();
    duration
}
