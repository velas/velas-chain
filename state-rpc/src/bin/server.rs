use std::collections::HashMap;
use std::path::Path;

use derive_more::Display;

use evm_rpc::FormatHex;
use evm_state::rand::Rng;
use evm_state::*;

use tonic::{transport::Server, Request, Response, Status};

use state_rpc::finder;

use app_grpc::backend_server::{Backend, BackendServer};
use app_grpc::PingReply;
pub mod app_grpc {
    tonic::include_proto!("rpcserver");
}

struct Rpc {}

#[tonic::async_trait]
impl Backend for Rpc {
    async fn ping(&self, request: Request<()>) -> Result<Response<PingReply>, Status> {
        println!("Got a request: {:?}", request);

        let reply = app_grpc::PingReply {
            message: "Ok".to_string(),
        };

        Ok(Response::new(reply))
    }

    async fn get_block(
        &self,
        request: Request<app_grpc::Hash>,
    ) -> Result<Response<app_grpc::BlockData>, Status> {
        println!("Got a request: {:?}", request);

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
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // For the future state movement
    // let state_root_str = std::fs::read_to_string("./.tmp/state_root.txt").expect("get the state root");
    // let state_root = H256::from_hex(&state_root_str).expect("get hash from &str");

    let addr = "127.0.0.1:8000".parse()?;
    let backend = BackendServer::new(Rpc {});

    Server::builder().add_service(backend).serve(addr).await?;

    Ok(())
}
