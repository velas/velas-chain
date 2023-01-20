use std::time::Instant;

use log::info;

use evm_rpc::FormatHex;
use evm_state::{Storage, H256};

use app_grpc::backend_server::{Backend, BackendServer};
use tonic::{Request, Response, Status};

use app_grpc::PingReply;
pub mod app_grpc {
    tonic::include_proto!("triedb_repl");
}

use crate::triedb_replica::{lock_root, debug_elapsed};


pub struct Server {
    storage: Storage,
}

impl Server {
    pub fn new(storage: Storage) -> BackendServer<Self> {
        BackendServer::new(Server { storage })
    }

    fn parse_state_roots(
        request: Request<app_grpc::GetStateDiffRequest>,
    ) -> Result<(H256, H256), Status> {
        let inner = request.into_inner();

        let first_root = inner
            .first_root
            .ok_or_else(|| Status::invalid_argument("empty arg"))?;
        let second_root = inner
            .second_root
            .ok_or_else(|| Status::invalid_argument("empty arg"))?;

        let first_root = H256::from_hex(&first_root.value).map_err(|_| {
            Status::invalid_argument("Couldn't parse requested hash key1")
        })?;

        let second_root = H256::from_hex(&second_root.value).map_err(|_| {
            Status::invalid_argument("Couldn't parse requested hash key2")
        })?;
        Ok((first_root, second_root))
    }
}

#[tonic::async_trait]
impl Backend for Server {
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
            Status::invalid_argument(format!(
                "Couldn't parse requested hash key {}",
                hash.value
            ))
        })?;
        let maybe_bytes = self.storage.db().get(key);

        let value = if let Ok(option) = maybe_bytes {
            Ok(option)
        } else {
            Err(Status::internal("DB access error"))
        };
        let bytes = value?
            .ok_or_else(|| Status::not_found(format!("not found {}", hash.value)))?;

        let reply = app_grpc::GetRawBytesReply { node: bytes };

        Ok(Response::new(reply))
    }


    async fn get_state_diff(
        &self,
        request: Request<app_grpc::GetStateDiffRequest>,
    ) -> Result<Response<app_grpc::GetStateDiffReply>, Status> {
        let start = Instant::now();
        info!("Got a request: {:?}", request);

        let (from, to) = Self::parse_state_roots(request)?;

        debug_elapsed("parsed request", &start);
        let db_handle = self.storage.rocksdb_trie_handle();
        let _from_guard = lock_root(&db_handle, from, evm_state::storage::account_extractor).map_err(
            |err| Status::not_found(format!("failure to lock root {}", err))
        )?;
        let _to_guard = lock_root(&db_handle, to, evm_state::storage::account_extractor).map_err(
            |err| Status::not_found(format!("failure to lock root {}", err))
        )?;
        debug_elapsed("locked roots", &start);

        let ach = triedb::rocksdb::SyncRocksHandle::new(
            triedb::rocksdb::RocksDatabaseHandle::new(self.storage.db()),
        );

        let changeset = triedb::diff(
            &ach,
            evm_state::storage::account_extractor,
            from,
            to,
        )
        .map_err(|err| {
            log::error!("triedb::diff {:?}", err);
            Status::internal("Cannot calculate diff between states")
        })?;
        debug_elapsed("retrieved changeset", &start);

        let mut reply_changeset = vec![];

        for change in changeset {
            match change {
                triedb::DiffChange::Insert(hash, data) => {
                    let raw_insert = app_grpc::Insert {
                        hash: Some(app_grpc::Hash {
                            value: hash.format_hex(),
                        }),
                        data,
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
        };

        Ok(Response::new(reply))
    }
}

impl BackendServer<Server> {
    pub fn join(&self) -> Result<(), Box<(dyn std::error::Error + 'static)>> {
        Ok(())
    }
}
