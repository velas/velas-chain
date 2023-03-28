pub mod bigtable;
pub mod client;
pub mod error;
pub mod range;
pub mod server;
pub use bigtable::CachedRootsLedgerStorage;

use std::{net::SocketAddr, ops::Range, time::Instant};

use backon::{ExponentialBuilder, Retryable};
use evm_state::{BlockNum, Storage, H256};
use triedb::{gc::DbCounter, Database};

use rocksdb::{DBWithThreadMode, SingleThreaded};

use self::{
    error::{EvmHeightError, LockError},
    range::RangeJSON,
};

use async_trait::async_trait;

type RocksHandleA<'a> = triedb::rocksdb::RocksHandle<'a, &'a triedb::rocksdb::DB>;

pub(self) fn collection(storage: &Storage) -> triedb::gc::TrieCollection<RocksHandleA<'_>> {
    triedb::gc::TrieCollection::new(storage.rocksdb_trie_handle())
}

pub trait TryConvert<S>: Sized {
    type Error;

    fn try_from(value: S) -> Result<Self, Self::Error>;
}
//  The difference between 58896219 and 59409340 is 513121.
//  700_000 =~ 513121 * 1.33
//  "Max difference of block height, that server won't reject diff requests of"
pub const MAX_JUMP_OVER_ABYSS_GAP: usize = 700_000;

// maximum number of hashes for GetArrayOfNodesRequest (should be around 200 MB
// worth of corresponding nodes)
const MAX_CHUNK_HASHES: usize = 1_000_000;

const MAX_TIMES: usize = 8;
const MIN_DELAY_SEC: u64 = 1;

#[async_trait]
pub trait EvmHeightIndex {
    async fn get_evm_confirmed_state_root(
        &self,
        block_num: evm_state::BlockNum,
    ) -> Result<H256, EvmHeightError>;

    async fn get_evm_confirmed_state_root_retried(
        &self,
        block_num: evm_state::BlockNum,
    ) -> Result<H256, EvmHeightError> {
        let mut count = 0;
        let fetch_cl = || {
            *(&mut count) += 1;
            let val = count;
            async move {
                log::trace!(
                    "attempting try to get_evm_confirmed_state_root {} ({})",
                    block_num,
                    val,
                );

                self.get_evm_confirmed_state_root(block_num).await
            }
        };

        let result = fetch_cl
            .retry(
                &ExponentialBuilder::default()
                    .with_min_delay(std::time::Duration::new(MIN_DELAY_SEC, 0))
                    .with_max_times(MAX_TIMES),
            )
            .await?;
        Ok(result)
    }

    async fn prefetch_roots(
        &self,
        range: &Range<evm_state::BlockNum>,
    ) -> Result<(), EvmHeightError>;

    async fn prefetch_roots_retried(
        &self,
        range: &Range<evm_state::BlockNum>,
    ) -> Result<(), EvmHeightError> {
        let mut count = 0;
        let fetch_cl = || {
            *(&mut count) += 1;
            let val = count;
            async move {
                log::trace!("attempting try to prefetch_roots {:?} ({})", range, val);

                self.prefetch_roots(range).await
            }
        };

        let result = fetch_cl
            .retry(
                &ExponentialBuilder::default()
                    .with_min_delay(std::time::Duration::new(MIN_DELAY_SEC, 0))
                    .with_max_times(MAX_TIMES),
            )
            .await?;
        Ok(result)
    }
}

// bigtable bulk api limited by Vladimir
const MAX_PREFETCH_RANGE_CHUNK: BlockNum = 5_000;

pub(self) fn lock_root<D, F>(
    db: &D,
    locked: H256,
    func: F,
) -> Result<triedb::gc::RootGuard<'_, D, F>, LockError>
where
    D: Database + DbCounter,
    F: FnMut(&[u8]) -> Vec<H256>,
{
    let guard = triedb::gc::RootGuard::new(db, locked, func);
    if locked != triedb::empty_trie_hash() && !db.node_exist(locked) {
        return Err(LockError::LockRootNotFound(locked));
    }
    Ok(guard)
}

pub(self) fn check_root(
    db: &DBWithThreadMode<SingleThreaded>,
    checked: H256,
) -> Result<(), LockError>
where
{
    if checked != triedb::empty_trie_hash() && db.get(checked)?.is_none() {
        return Err(LockError::LockRootNotFound(checked));
    }
    Ok(())
}

pub fn debug_elapsed(msg: &str, start: &Instant) {
    let duration = start.elapsed();

    log::debug!("Time elapsed on {}  is: {:?}", msg, duration);
}

pub fn start_and_join<S: EvmHeightIndex + Sync + Send + 'static>(
    bind_address: SocketAddr,
    range: RangeJSON,
    storage: server::UsedStorage,
    runtime: tokio::runtime::Runtime,
    block_storage: S,
) -> Result<(), Box<(dyn std::error::Error + 'static)>> {
    let cfg = server::ServiceConfig::new(bind_address, MAX_JUMP_OVER_ABYSS_GAP as BlockNum);
    let deps = server::Deps::new(cfg, storage, range, runtime, block_storage);

    log::info!("starting the thread");
    server::Service::new(deps).into_thread()?.join()?;
    Ok(())
}
