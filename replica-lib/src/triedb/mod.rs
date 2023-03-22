pub mod client;
pub mod error;
pub mod range;
pub mod server;

use std::{net::SocketAddr, time::Instant};

use evm_state::{empty_trie_hash, Storage, H256, BlockNum};
use triedb::{gc::DbCounter, Database};

use rocksdb::{DBWithThreadMode, SingleThreaded};

use self::{error::{EvmHeightError, LockError}, range::RangeJSON};

use async_trait::async_trait;
use solana_storage_bigtable::LedgerStorage;

type RocksHandleA<'a> = triedb::rocksdb::RocksHandle<'a, &'a triedb::rocksdb::DB>;

pub(self) fn collection(storage: &Storage) -> triedb::gc::TrieCollection<RocksHandleA<'_>> {
    triedb::gc::TrieCollection::new(storage.rocksdb_trie_handle())
}

//  The difference between 58896219 and 59409340 is 513121.
//  700_000 =~ 513121 * 1.33
//  "Max difference of block height, that server won't reject diff requests of"
pub const MAX_JUMP_OVER_ABYSS_GAP: usize = 700_000;

// maximum number of hashes for GetArrayOfNodesRequest (should be around 200 MB
// worth of corresponding nodes)
const MAX_CHUNK_HASHES: usize = 1_000_000;

#[async_trait]
pub trait EvmHeightIndex {
    async fn get_evm_confirmed_state_root(
        &self,
        block_num: evm_state::BlockNum,
    ) -> Result<H256, EvmHeightError>;
}

#[async_trait]
impl EvmHeightIndex for LedgerStorage {
    async fn get_evm_confirmed_state_root(
        &self,
        block_num: evm_state::BlockNum,
    ) -> Result<H256, EvmHeightError> {
        if block_num == 0 {
            return Ok(empty_trie_hash());
        }
        let block = self.get_evm_confirmed_full_block(block_num).await?;

        Ok(block.header.state_root)
    }
}

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

pub(self) fn debug_elapsed(msg: &str, start: &Instant) {
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
