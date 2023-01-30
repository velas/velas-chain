pub mod client;
pub mod server;

use std::{time::Instant, net::SocketAddr};

use evm_state::H256;
use triedb::Database;

pub use triedb::gc::DbCounter;
use rocksdb::{DBWithThreadMode, SingleThreaded};

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

    log::info!("Time elapsed on {}  is: {:?}", msg, duration);
}

pub fn start_and_join(
    bind_address: SocketAddr,
    storage: server::UsedStorage,
) -> Result<(), Box<(dyn std::error::Error + 'static)>> {

    let cfg = server::ServiceConfig::new(bind_address, 2);
    let deps = server::Deps::new(cfg, storage);

    log::info!("starting the thread");
    server::Service::new(deps)
        .into_thread()?
        .join()?;
    Ok(())
}
