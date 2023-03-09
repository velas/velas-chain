use std::{any::Any, panic, time::Instant};

use evm_rpc::FormatHex;
use evm_state::{Storage, StorageSecondary, H256};
use tonic::{Response, Status};
use triedb::DiffChange;

use crate::triedb::{
    check_root, debug_elapsed, lock_root,
    server::{Server, UsedStorage},
};

use super::app_grpc;

fn get_state_diff_gc_storage(
    from: H256,
    to: H256,
    storage: &Storage,
) -> Result<Vec<DiffChange>, Status> {
    let start = Instant::now();

    let db_handle = storage.rocksdb_trie_handle();
    let _from_guard = lock_root(&db_handle, from, evm_state::storage::account_extractor)
        .map_err(|err| Status::not_found(format!("failure to lock root {}", err)))?;
    let _to_guard = lock_root(&db_handle, to, evm_state::storage::account_extractor)
        .map_err(|err| Status::not_found(format!("failure to lock root {}", err)))?;
    debug_elapsed("locked roots", &start);

    let ach = triedb::rocksdb::SyncRocksHandle::new(triedb::rocksdb::RocksDatabaseHandle::new(
        storage.db(),
    ));

    let changeset =
        triedb::diff(&ach, evm_state::storage::account_extractor, from, to).map_err(|err| {
            log::error!("triedb::diff {:?}", err);
            Status::internal("Cannot calculate diff between states")
        })?;
    debug_elapsed("retrieved changeset", &start);
    Ok(changeset)
}

fn get_state_diff_secondary_storage(
    from: H256,
    to: H256,
    storage: &StorageSecondary,
) -> Result<Vec<DiffChange>, Status> {
    let start = Instant::now();

    let db = storage.db();
    check_root(db, from).map_err(|err| Status::not_found(format!("check root {}", err)))?;
    check_root(db, to).map_err(|err| Status::not_found(format!("check root {}", err)))?;
    debug_elapsed("locked roots", &start);

    let ach = storage.rocksdb_trie_handle();

    let changeset =
        triedb::diff(&ach, evm_state::storage::account_extractor, from, to).map_err(|err| {
            log::error!("triedb::diff {:?}", err);
            Status::internal("Cannot calculate diff between states")
        })?;
    debug_elapsed("retrieved changeset", &start);
    Ok(changeset)
}
impl<S> Server<S> {
    pub(super) fn get_node_body(&self, key: H256) -> Result<Vec<u8>, Status> {
        let maybe_bytes = match self.storage {
            UsedStorage::WritableWithGC(ref storage) => storage.db().get(key),

            UsedStorage::ReadOnlyNoGC(ref storage) => storage.db().get(key),
        };

        let value = if let Ok(option) = maybe_bytes {
            Ok(option)
        } else {
            Err(Status::internal("DB access error"))
        };
        let bytes = value?.ok_or_else(|| Status::not_found(format!("not found {:?}", key)))?;
        Ok(bytes)
    }
    pub(super) fn state_diff_body(
        &self,
        from: H256,
        to: H256,
    ) -> Result<Response<app_grpc::GetStateDiffReply>, Status> {
        let storage = &self.storage;
        let catched: Result<Result<Vec<DiffChange>, Status>, Box<dyn Any + Send>> =
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
                return Err(Status::not_found(format!(
                    "some problem below either {:?} or {:?}: {}",
                    from, to, description
                )));
            }
        };

        let reply_changeset = super::helpers::map_changeset(changeset);

        let reply = app_grpc::GetStateDiffReply {
            changeset: reply_changeset,
            first_root: Some(app_grpc::Hash {
                value: from.format_hex(),
            }),
            second_root: Some(app_grpc::Hash {
                value: to.format_hex(),
            }),
        };

        Ok(Response::new(reply))
    }
}
