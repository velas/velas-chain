pub mod client;
pub mod server;

use std::time::Instant;

use evm_state::H256;
use triedb::Database;

pub use evm_state::storage::account_extractor as func_extractor;
pub use triedb::gc::DbCounter;

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

pub(self) fn debug_elapsed(msg: &str, start: &Instant) {
    let duration = start.elapsed();

    log::info!("Time elapsed on {}  is: {:?}", msg, duration);
}
