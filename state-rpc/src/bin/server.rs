use std::collections::HashMap;
use std::path::Path;

use tonic::{transport::Server, Request, Response, Status};
use derive_more::Display;
use log::{debug, error, log_enabled, info, Level};

use evm_rpc::FormatHex;
use evm_state::rand::Rng;
use evm_state::*;

use state_rpc::finder;
use triedb::state_diff::DiffFinder;

use app_grpc::backend_server::{Backend, BackendServer};
use app_grpc::PingReply;
pub mod app_grpc {
    tonic::include_proto!("rpcserver");
}

struct Rpc {}

#[tonic::async_trait]
impl Backend for Rpc {
    async fn ping(&self, request: Request<()>) -> Result<Response<PingReply>, Status> {
        info!("Got a request: {:?}", request);

        let reply = app_grpc::PingReply {
            message: "Ok".to_string(),
        };

        Ok(Response::new(reply))
    }

    async fn get_block(
        &self,
        request: Request<app_grpc::Hash>,
    ) -> Result<Response<app_grpc::BlockData>, Status> {
        info!("Got a request: {:?}", request);

        let stringified_key = request.into_inner().hash;

        let dir = Path::new("./.tmp/db/");

        let db_handle = Storage::open_persistent(dir, true).expect("could not open database");

        let key = H256::from_hex(&stringified_key).expect("get hash from &str");

        let finder = finder::Finder::new(db_handle);
        let maybe_bytes = finder.find(key);

        let response = if let Ok(Some(bytes)) = maybe_bytes {
            HashMap::from([(stringified_key, bytes)])
        } else {
            HashMap::new()
        };

        let reply = app_grpc::BlockData { data: response };

        Ok(Response::new(reply))
    }

    async fn get_block_multi(
        &self,
        request: Request<app_grpc::MultiHash>,
    ) -> Result<Response<app_grpc::MultiBlockData>, Status> {
        info!("Got a request: {:?}", request);

        let stringified_keys = request.into_inner().hashes;
        let mut response = HashMap::new();
        let dir = Path::new("./.tmp/db/");

        stringified_keys.into_iter().for_each(|stringified_key| {
            let db_handle = Storage::open_persistent(dir, true).expect("could not open database");

            let key = H256::from_hex(&stringified_key).expect("get hash from &str");

            let finder = finder::Finder::new(db_handle);
            let maybe_bytes = finder.find(key);

            if let Ok(Some(bytes)) = maybe_bytes {
                response.insert(stringified_key, bytes);
            }
        });

        let reply = app_grpc::MultiBlockData { data: response };

        Ok(Response::new(reply))
    }

    async fn get_state_diff(
        &self,
        request: Request<app_grpc::StateDiffRequest>,
    ) -> Result<Response<app_grpc::Changeset>, Status> {
        info!("Got a request: {:?}", request);

        let inner = request.into_inner();

        let first_root = inner.first_root;
        let second_root = inner.second_root;

        let start_state_root = H256::from_hex(&first_root).expect("get hash from first_root");
        let end_state_root = H256::from_hex(&second_root).expect("get hash from second_root");

        let dir = Path::new("./.tmp/db/");
        let db_handle = Storage::open_persistent(dir, true).expect("could not open database");

        // TODO: Need to change db_handle type to pass a threadsafe version
        // let diff_finder = DiffFinder::new(db_handle, start_state_root, end_state_root);
        // let changeset = diff_finder.get_changeset(start_state_root, end_state_root);

        // TODO: After changing type above remove this `changeset`
        let changeset = vec![triedb::state_diff::Change::Insert(start_state_root, vec![1,2,3,4,5])];
        let mut diff = vec![];

        for change in changeset {
            match change {
                triedb::state_diff::Change::Insert(hash, data) => {
                    let raw_insert = app_grpc::Insert { hash: hash.to_string(), data: data };
                    let insert = app_grpc::change::Change::Insert(raw_insert);
                    let change = app_grpc::Change { change: Some(insert) };
                    diff.push(change);
                },
                triedb::state_diff::Change::Removal(hash, data) => {
                    let removal = app_grpc::Removal { hash: hash.to_string(), data: data };
                    let removal = app_grpc::change::Change::Removal(removal);
                    let change = app_grpc::Change { change: Some(removal) };
                    diff.push(change);
                },
            }
        }

        let reply = app_grpc::Changeset { changes: diff };

        Ok(Response::new(reply))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    // TODO: Move address to env var
    info!("Starting the State-RPC web server at 127.0.0.1:8000");

    let addr = "127.0.0.1:8000".parse()?;
    let backend = BackendServer::new(Rpc {});

    Server::builder().add_service(backend).serve(addr).await?;

    Ok(())
}
