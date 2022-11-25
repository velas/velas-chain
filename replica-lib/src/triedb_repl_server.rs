use std::collections::HashMap;
use std::default;
use std::path::Path;

use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use std::thread::{self, Builder, JoinHandle, sleep};

use futures_util::FutureExt;
use tokio::runtime::Runtime;
use tokio::sync::oneshot::{self, Receiver, Sender};

use tonic::{transport::Server, Request, Response, Status};
use tonic::{self, transport};

use derive_more::Display;
use log::{debug, error, log_enabled, info, Level};

use evm_rpc::FormatHex;
use evm_state::rand::Rng;
use evm_state::*;

use triedb::state_diff::DiffFinder;

use app_grpc::backend_server::{Backend, BackendServer};
use app_grpc::PingReply;
pub mod app_grpc {
    tonic::include_proto!("triedb_repl");
}

pub struct StateRpcServiceConfig {
    server_addr: SocketAddr,
    worker_threads: usize,
}

impl StateRpcServiceConfig {
    pub fn from_addr_and_thread_pool_size(addr: String, worker_threads: usize) -> Result<Self, String> {
        let server_addr: SocketAddr = addr.parse()
            .map_err(|_| String::from("Unable to parse socket address"))?;

        Ok(StateRpcServiceConfig {
            server_addr,
            worker_threads
        })
    }
}

/// The service wraps the Rpc to make it runnable in the tokio runtime
/// and handles start and stop of the service.
pub struct TriedbReplService {
    triedb_repl_server: BackendServer<TriedbReplServer>,
    thread: JoinHandle<()>,
    exit_signal_sender: Sender<()>,
}

impl TriedbReplService {
    pub fn new(
        config: StateRpcServiceConfig,
        triedb_repl_server: BackendServer<TriedbReplServer>,
    ) -> Result<TriedbReplService, ()> {
        let worker_threads = config.worker_threads;
        let runtime = Arc::new(
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(worker_threads)
                .thread_name("velas-state-rpc-worker")
                .enable_all()
                .build().map_err(|_| ())?
        );
        // let server_cloned = state_rpc_server.clone();
        let (exit_signal_sender, exit_signal_receiver) = oneshot::channel::<()>();

        let thread = Builder::new()
            .name("velas-state-rpc-runtime".to_string())
            .spawn(move || {
                println!("builder: in runtime");
                Self::run_triedb_repl_server_in_runtime(
                    config,
                    runtime,
                    exit_signal_receiver,
                );
            })
            .unwrap();

        Ok(Self {
            triedb_repl_server,
            thread,
            exit_signal_sender,
        })
    }

    // Runs server implementation with a provided configuration
    async fn run_triedb_repl_server(
        config: StateRpcServiceConfig,
        exit_signal: Receiver<()>,
    ) -> Result<(), tonic::transport::Error> {
        info!(
            "Running TriedbReplServer at the endpoint: {:?}",
            config.server_addr
        );

        transport::Server::builder()
            .add_service(TriedbReplServer::new_backend_server())
            .serve_with_shutdown(config.server_addr, exit_signal.map(drop))
            .await
    }

    // Start TriedbReplServer in a Tokio runtime
    fn run_triedb_repl_server_in_runtime(
        config: StateRpcServiceConfig,
        runtime: Arc<Runtime>,
        exit_signal: Receiver<()>,
    ) {
        println!("blocking on runtime: in runtime");
        let result = runtime.block_on(Self::run_triedb_repl_server(
            config,
            exit_signal,
        ));
        println!("blocking on runtime: received the result {:?}", result);

        match result {
            Ok(_) => {
                info!("TriedbReplServer finished");
            }
            Err(err) => {
                error!("TriedbReplServer finished in error: {:}?", err);
            }
        }
    }

    pub fn join(self) -> thread::Result<()> {
        // let _ = self.exit_signal_sender.send(());
        println!("join(): signal received");
        self.triedb_repl_server.join()?;
        println!("join(): joining_triedb_server");
        let r = self.thread.join();
        println!("join(): thread joined");
        r
    }
}

pub struct TriedbReplServer {
    storage: Arc<RwLock<Storage>>
}

impl TriedbReplServer {
    pub fn new_backend_server() -> BackendServer<Self> {
        let path = Path::new("./tmp-ledger-path/archive");
        let storage = Storage::open_persistent(path, true).expect("could not open database");
        let storage = Arc::new(RwLock::new(storage));

        BackendServer::new(TriedbReplServer {
            storage
        })
    }
}

impl BackendServer<TriedbReplServer> {
    fn join(&self) -> thread::Result<()> {
        Ok(())
    }
}

#[tonic::async_trait]
impl Backend for TriedbReplServer {
    async fn ping(&self, request: Request<()>) -> Result<Response<PingReply>, Status> {
        info!("Got a request: {:?}", request);

        let reply = app_grpc::PingReply {
            message: "Ok".to_string(),
        };

        Ok(Response::new(reply))
    }

    async fn get_raw_bytes(
        &self,
        request: Request<app_grpc::GetRawBytesRequest>,
    ) -> Result<Response<app_grpc::GetRawBytesReply>, Status> {
        info!("Got a request: {:?}", request);

        let stringified_key = request.into_inner().hash;

        let db_handle = self.storage.read().map_err(|_| Status::internal("Database connection failure"))?;

        let key = H256::from_hex(&stringified_key).map_err(|_| Status::internal("Couldn't parse requested hash key"))?;
        let maybe_bytes = db_handle.db().get(key);

        let response = if let Ok(Some(bytes)) = maybe_bytes {
            HashMap::from([(stringified_key, bytes)])
        } else {
            HashMap::new()
        };

        let reply = app_grpc::GetRawBytesReply { blocks_data: response };

        Ok(Response::new(reply))
    }

    async fn get_multiple_raw_bytes(
        &self,
        request: Request<app_grpc::GetMultipleRawBytesRequest>,
    ) -> Result<Response<app_grpc::GetMultipleRawBytesReply>, Status> {
        info!("Got a request: {:?}", request);

        let stringified_keys = request.into_inner().hashes;
        let mut response = HashMap::new();
        let db_handle = self.storage.read().map_err(|_| Status::internal("Database connection failure"))?;

        for stringified_key in stringified_keys {
            let key = H256::from_hex(&stringified_key).map_err(|_| Status::internal("Couldn't parse requested hash key"))?;
            let maybe_bytes = db_handle.db().get(key);

            if let Ok(Some(bytes)) = maybe_bytes {
                response.insert(stringified_key, bytes);
            }
        }

        let reply = app_grpc::GetMultipleRawBytesReply { blocks_data: response };

        Ok(Response::new(reply))
    }

    async fn get_state_diff(
        &self,
        request: Request<app_grpc::GetStateDiffRequest>,
    ) -> Result<Response<app_grpc::GetStateDiffReply>, Status> {
        info!("Got a request: {:?}", request);

        let inner = request.into_inner();

        let first_root = inner.first_root;
        let second_root = inner.second_root;

        let start_state_root = H256::from_hex(&first_root).map_err(|_| Status::internal("Couldn't parse requested hash key1"))?;
        info!("First root is: {:?}", start_state_root);

        let end_state_root = H256::from_hex(&second_root).map_err(|_| Status::internal("Couldn't parse requested hash key2"))?;
        info!("Second root is: {:?}", end_state_root);

        let db_handle = self.storage.read().map_err(|_| Status::internal("Database connection failure"))?;
        let async_cached_handle = triedb::gc::testing::AsyncCachedDatabaseHandle::new(db_handle.db());

        let ach = triedb::gc::testing::AsyncCachedHandle::new(async_cached_handle);

        let diff_finder = DiffFinder::new(ach, start_state_root, end_state_root, |child| { vec![] });
        let changeset = diff_finder.get_changeset(start_state_root, end_state_root).map_err(|_| Status::internal("Cannot calculate diff between states"))?;

        let mut reply_changeset = vec![];

        for change in changeset {
            match change {
                triedb::state_diff::Change::Insert(hash, data) => {
                    let raw_insert = app_grpc::Insert { hash: hash.to_string(), data: data };
                    let insert = app_grpc::change::Change::Insert(raw_insert);
                    let change = app_grpc::Change { change: Some(insert) };
                    reply_changeset.push(change);
                },
                triedb::state_diff::Change::Removal(hash, data) => {
                    let removal = app_grpc::Removal { hash: hash.to_string(), data: data };
                    let removal = app_grpc::change::Change::Removal(removal);
                    let change = app_grpc::Change { change: Some(removal) };
                    reply_changeset.push(change);
                },
            }
        }

        let reply = app_grpc::GetStateDiffReply { changeset: reply_changeset };

        Ok(Response::new(reply))
    }
}
