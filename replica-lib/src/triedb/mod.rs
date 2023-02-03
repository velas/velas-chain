pub mod client;
pub mod server;
pub mod range;

use std::{time::Instant, net::SocketAddr};

use evm_state::{H256, empty_trie_hash};
use triedb::{Database, gc::DbCounter};

use rocksdb::{DBWithThreadMode, SingleThreaded};

use self::range::MasterRange;

use async_trait::async_trait;
use  solana_storage_bigtable::LedgerStorage;

#[async_trait]
pub trait LittleBig {

    async fn get_evm_confirmed_state_root(
        &self,
        block_num: evm_state::BlockNum,
    ) -> anyhow::Result<H256> ;
}


#[async_trait]
impl LittleBig for LedgerStorage {
    async fn get_evm_confirmed_state_root(
        &self,
        block_num: evm_state::BlockNum,
    ) -> anyhow::Result<H256> {
        if block_num == 0 {
            return Ok(empty_trie_hash());
        }
        let block = self.get_evm_confirmed_full_block(block_num).await?;
        
        Ok(block.header.state_root)
        
    }
}



pub fn lock_root<D, F>(
    db: &D,
    locked: H256,
    func: F,
) -> Result<triedb::gc::RootGuard<'_, D, F>, anyhow::Error>
where
    D: Database + DbCounter,
    F: FnMut(&[u8]) -> Vec<H256>
{
    let guard =
        triedb::gc::RootGuard::new(db, locked, func);
    if locked != triedb::empty_trie_hash() && !db.node_exist(locked) {
        return Err(anyhow::anyhow!("cannot lock root {:?} (not found)", locked));

    }
    Ok(guard)
}

pub fn check_root(
    db: &DBWithThreadMode<SingleThreaded>,
    checked: H256,
) -> Result<(), anyhow::Error>
where
{
    if checked != triedb::empty_trie_hash() && db.get(checked)?.is_none() {
        return Err(anyhow::anyhow!("check root {:?} (not found)", checked));

    }
    Ok(())
}
pub(self) fn debug_elapsed(msg: &str, start: &Instant) {
    let duration = start.elapsed();

    log::debug!("Time elapsed on {}  is: {:?}", msg, duration);
}

pub fn start_and_join<S: LittleBig + Sync + Send + 'static>(
    bind_address: SocketAddr,
    range: MasterRange,
    block_threshold: evm_state::BlockNum,
    storage: server::UsedStorage,
    runtime: tokio::runtime::Runtime,
    block_storage: S,
) -> Result<(), Box<(dyn std::error::Error + 'static)>> {

    let cfg = server::ServiceConfig::new(bind_address, block_threshold);
    let deps = server::Deps::new(cfg, storage, range, runtime, block_storage);

    log::info!("starting the thread");
    server::Service::new(deps)
        .into_thread()?
        .join()?;
    Ok(())
}
