use std::path::Path;

use derive_more::Display;

use evm_state::*;
use evm_state::rand::Rng;
use evm_rpc::FormatHex;

mod utils;
mod finder;

use tonic::{transport::Server, Request, Response, Status};

use app_grpc::backend_server::{Backend, BackendServer};
use app_grpc::PingReply;
pub mod app_grpc {
    tonic::include_proto!("rpcserver");
}

struct Rpc {}

#[tonic::async_trait]
impl Backend for Rpc {
    async fn ping(
        &self,
        request: Request<()>,
    ) -> Result<Response<PingReply>, Status> {
        println!("Got a request: {:?}", request);

        let reply = app_grpc::PingReply {
            message: "Ok".to_string()
        };

        Ok(Response::new(reply))
    }

    async fn get_block(
        &self,
        request: Request<app_grpc::Hash>,
    ) -> Result<Response<app_grpc::BlockData>, Status> {
        println!("Got a request: {:?}", request);

        let data = request.into_inner().hash;


        let dir = Path::new("db/");
        let state_root = H256::from_hex("0xfb6e8eeafc655f1bb97212e7476837449b71a41df8c9d604f3cc7e12cebf0fe7").expect("get hash from &str");

        let new_db = Storage::open_persistent(dir, true).expect("could not open database");

        let h = H256::from_hex(&data).expect("get hash from &str");

        let finder = finder::Finder::new(new_db, h);
        let bytes = finder.traverse(state_root);

        let reply = app_grpc::BlockData {
            data: bytes.unwrap().unwrap()
        };

        Ok(Response::new(reply))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = "127.0.0.1:8000".parse()?;
    let backend = BackendServer::new(Rpc {});

    Server::builder()
       .add_service(backend)
       .serve(addr)
       .await?;

    Ok(())
}

