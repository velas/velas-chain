use std::{any::Any, panic, time::Instant};

use evm_state::{Storage, StorageSecondary, H256};
use tonic::Response;
use triedb::DiffChange;

use crate::triedb::{
    check_root, debug_elapsed,
    error::{lock, server},
    lock_root,
    server::{Server, UsedStorage},
};

use super::app_grpc;

fn get_state_diff_gc_storage(
    from: H256,
    to: H256,
    storage: &Storage,
) -> Result<Vec<DiffChange>, server::Error> {
    let mut start = Instant::now();

    let db_handle = storage.rocksdb_trie_handle();
    let _from_guard = lock_root(&db_handle, from, evm_state::storage::account_extractor)?;
    let _to_guard = lock_root(&db_handle, to, evm_state::storage::account_extractor)?;
    let _ = debug_elapsed(&mut start);

    let ach = triedb::rocksdb::SyncRocksHandle::new(triedb::rocksdb::RocksDatabaseHandle::new(
        storage.db(),
    ));

    let changeset = triedb::diff(&ach, evm_state::storage::account_extractor, from, to)
        .map_err(|_err| server::Error::TriedbDiff)?;
    let disk_io = debug_elapsed(&mut start);
    log::debug!(
        "disk i/o retrieved diff changeset {:?} {}",
        disk_io,
        changeset.len()
    );
    Ok(changeset)
}

fn get_state_diff_secondary_storage(
    from: H256,
    to: H256,
    storage: &StorageSecondary,
) -> Result<Vec<DiffChange>, server::Error> {
    let mut start = Instant::now();

    let db = storage.db();
    check_root(db, from)?;
    check_root(db, to)?;
    let _ = debug_elapsed(&mut start);

    let ach = storage.rocksdb_trie_handle();

    let changeset = triedb::diff(&ach, evm_state::storage::account_extractor, from, to)
        .map_err(|_err| server::Error::TriedbDiff)?;
    let disk_io = debug_elapsed(&mut start);
    log::debug!(
        "disk i/o retrieved diff changeset {:?} {}",
        disk_io,
        changeset.len()
    );
    Ok(changeset)
}
impl Server {
    pub(super) fn get_node_body(&self, key: H256) -> Result<Vec<u8>, server::Error> {
        let maybe_bytes = match self.storage {
            UsedStorage::WritableWithGC(ref storage) => storage.db().get(key),

            UsedStorage::ReadOnlyNoGC(ref storage) => storage.db().get(key),
        };

        let bytes = maybe_bytes?.ok_or(lock::Error::NotFoundTop(key))?;
        Ok(bytes)
    }
    pub(super) fn state_diff_body(
        &self,
        from: H256,
        to: H256,
    ) -> Result<Response<app_grpc::GetStateDiffReply>, server::Error> {
        let storage = &self.storage;
        let catched: Result<Result<Vec<DiffChange>, server::Error>, Box<dyn Any + Send>> =
            panic::catch_unwind(|| {
                let changeset = match storage {
                    UsedStorage::WritableWithGC(ref storage) => {
                        get_state_diff_gc_storage(from, to, storage)?
                    }
                    UsedStorage::ReadOnlyNoGC(ref storage) => {
                        get_state_diff_secondary_storage(from, to, storage)?
                    }
                };
                Ok(changeset)
            });
        let changeset = match catched {
            Ok(result) => result?,
            Err(panic_msg) => {
                let description = if let Some(description) = panic_msg.downcast_ref::<String>() {
                    format!("{:?}", description)
                } else {
                    format!("{:?}", panic_msg)
                };
                return Err(lock::Error::NotFoundNested {
                    from,
                    to,
                    description,
                })?;
            }
        };

        let reply_changeset = super::helpers::map_changeset(changeset);

        let reply = app_grpc::GetStateDiffReply {
            changeset: reply_changeset,
        };

        Ok(Response::new(reply))
    }
}
