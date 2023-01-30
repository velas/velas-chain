use std::time::Instant;

use log::info;

use evm_rpc::FormatHex;
use evm_state::{Storage, StorageSecondary, H256};
use triedb::DiffChange;

use super::UsedStorage;
use app_grpc::backend_server::{Backend, BackendServer};
use tonic::{Request, Response, Status};

use app_grpc::PingReply;
pub mod app_grpc {
    tonic::include_proto!("triedb_repl");
}

use crate::triedb::{check_root, debug_elapsed, lock_root, range::MasterRange, LittleBig};

pub struct Server<S> {
    storage: UsedStorage,
    range: MasterRange,
    block_threshold: evm_state::BlockNum,
    block_storage: S,
}

impl<S> Server<S>
where
    S: LittleBig + Send + Sync + 'static,
{
    pub fn new(
        storage: UsedStorage,
        range: MasterRange,
        block_threshold: evm_state::BlockNum,
        block_storage: S,
    ) -> BackendServer<Self> {
        BackendServer::new(Server {
            storage,
            range,
            block_threshold,
            block_storage,
        })
    }

    async fn fetch_state_roots(
        &self,
        from: evm_state::BlockNum,
        to: evm_state::BlockNum,
    ) -> anyhow::Result<(H256, H256)> {
        let from = self
            .block_storage
            .get_evm_confirmed_state_root(from)
            .await?;
        let to = self.block_storage.get_evm_confirmed_state_root(to).await?;
        Ok((from, to))
    }

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

        let changeset = triedb::diff(&ach, evm_state::storage::account_extractor, from, to)
            .map_err(|err| {
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

        let changeset = triedb::diff(&ach, evm_state::storage::account_extractor, from, to)
            .map_err(|err| {
                log::error!("triedb::diff {:?}", err);
                Status::internal("Cannot calculate diff between states")
            })?;
        debug_elapsed("retrieved changeset", &start);
        Ok(changeset)
    }
}

#[tonic::async_trait]
impl<S: LittleBig + Sync + Send + 'static> Backend for Server<S> {
    async fn ping(&self, request: Request<()>) -> Result<Response<PingReply>, Status> {
        info!("Got a request: {:?}", request);

        let reply = app_grpc::PingReply {
            message: "ABDULA STATUS 7".to_string(),
        };

        Ok(Response::new(reply))
    }

    async fn get_raw_bytes(
        &self,
        request: Request<app_grpc::GetRawBytesRequest>,
    ) -> Result<Response<app_grpc::GetRawBytesReply>, Status> {
        info!("Got a request: {:?}", request);

        let hash = request
            .into_inner()
            .hash
            .ok_or_else(|| Status::invalid_argument("empty arg"))?;

        let key = H256::from_hex(&hash.value).map_err(|_| {
            Status::invalid_argument(format!("Couldn't parse requested hash key {}", hash.value))
        })?;
        let maybe_bytes = match self.storage {
            UsedStorage::WritableWithGC(ref storage) => storage.db().get(key),

            UsedStorage::ReadOnlyNoGC(ref storage) => storage.db().get(key),
        };

        let value = if let Ok(option) = maybe_bytes {
            Ok(option)
        } else {
            Err(Status::internal("DB access error"))
        };
        let bytes = value?.ok_or_else(|| Status::not_found(format!("not found {}", hash.value)))?;

        let reply = app_grpc::GetRawBytesReply { node: bytes };

        Ok(Response::new(reply))
    }

    async fn get_state_diff(
        &self,
        request: Request<app_grpc::GetStateDiffRequest>,
    ) -> Result<Response<app_grpc::GetStateDiffReply>, Status> {
        info!("Got a request: {:?}", request);

        let inner = request.into_inner();
        let height_diff = if inner.to >= inner.from {
            inner.to - inner.from
        } else {
            inner.from - inner.to
        };
        if height_diff > self.block_threshold {
            return Err(Status::invalid_argument(format!(
                "blocks too far {}",
                inner.to - inner.from
            )));
        }
        let (from, to) = self
            .fetch_state_roots(inner.from, inner.to)
            .await
            .map_err(|err| {
                log::error!("fetch_state_roots encountered err {:?}", err);
                Status::internal("failure to fetch state roots")
            })?;

        let changeset = match self.storage {
            UsedStorage::WritableWithGC(ref storage) => {
                Self::get_state_diff_gc_storage(from, to, storage)?
            }
            UsedStorage::ReadOnlyNoGC(ref storage) => {
                Self::get_state_diff_secondary_storage(from, to, storage)?
            }
        };

        let mut reply_changeset = vec![];

        for change in changeset {
            match change {
                triedb::DiffChange::Insert(hash, data) => {
                    let raw_insert = app_grpc::Insert {
                        hash: Some(app_grpc::Hash {
                            value: hash.format_hex(),
                        }),
                        data: data.into(),
                    };
                    reply_changeset.push(raw_insert);
                }
                triedb::DiffChange::Removal(..) => {
                    // skip
                    // no need to transfer it over the wire
                }
            }
        }

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

    async fn get_block_range(
        &self,
        _request: tonic::Request<()>,
    ) -> Result<tonic::Response<app_grpc::GetBlockRangeReply>, tonic::Status> {
        let r: std::ops::Range<evm_state::BlockNum> = self.range.get();
        let reply = app_grpc::GetBlockRangeReply {
            start: r.start,
            end: r.end,
        };

        Ok(Response::new(reply))
    }
}

impl<S: LittleBig + Sync + Send + 'static> BackendServer<Server<S>> {
    pub fn join(&self) -> Result<(), Box<(dyn std::error::Error + 'static)>> {
        Ok(())
    }
}
