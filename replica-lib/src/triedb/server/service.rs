use evm_state::{BlockNum, StorageSecondary};
use futures_util::FutureExt;
use solana_ledger::blockstore::Blockstore;
use std::net::SocketAddr;
use std::sync::Arc;
use std::thread::{Builder, JoinHandle};
use std::time::Duration;
use tokio::sync::oneshot::{self, Receiver, Sender};

use tonic::{self, transport};

use log::{error, info};

use crate::triedb::error::{evm_height, RangeJsonInitError};
use crate::triedb::{server, EvmHeightIndex, ReadRange};

use self::helpers::{dispatch_sources, maybe_init_bigtable};

use super::config::Config;
use super::{proto, UsedStorage};

use proto::app_grpc::backend_server::BackendServer;
use thiserror::Error;

pub(super) mod helpers;
/// The service wraps the Rpc to make it runnable in the tokio runtime
/// and handles start and stop of the service.
pub struct Service {
    server_addr: SocketAddr,
    server: BackendServer<super::Server>,
    runtime: Option<tokio::runtime::Runtime>,
    storage_clone: UsedStorage,
}

pub struct RunningService {
    thread: JoinHandle<()>,
    server_handle: BackendServer<super::Server>,
    _exit_signal_sender: Sender<()>,
}

const SECONDARY_CATCH_UP_SECONDS: u64 = 7;

#[allow(clippy::result_unit_err)]
impl Service {
    pub fn new(
        server_addr: SocketAddr,
        block_threshold: evm_state::BlockNum,
        storage: UsedStorage,
        range: Box<dyn ReadRange>,
        runtime: tokio::runtime::Runtime,
        block_storage: Box<dyn EvmHeightIndex>,
    ) -> Service {
        runtime.block_on(async {
            let result = range.get().await;
            log::info!("check range at startup : {:?}", result);
        });

        Self {
            server_addr,
            server: super::Server::new(storage.clone(), range, block_threshold, block_storage),
            runtime: Some(runtime),
            storage_clone: storage,
        }
    }

    pub fn into_thread(self) -> std::io::Result<RunningService> {
        let (exit_signal_sender, exit_signal_receiver) = oneshot::channel::<()>();
        let server_handle = self.server.clone();
        let thread = Builder::new()
            .name("velas-state-rpc-runtime".to_string())
            .spawn(move || {
                self.block_on(exit_signal_receiver);
            })?;
        // TODO: register _exit_signal_sender send into Ctrl-C handler
        Ok(RunningService {
            thread,
            _exit_signal_sender: exit_signal_sender,
            server_handle,
        })
    }

    // Start TriedbReplServer in a Tokio runtime
    fn block_on(mut self, exit_signal: Receiver<()>) {
        let runtime = self
            .runtime
            .take()
            .expect("invariant broken: runtime should be moved out only once");
        let result = runtime.block_on(self.run(&runtime, exit_signal));

        match result {
            Ok(_) => {
                info!("TriedbReplServer finished");
            }
            Err(err) => {
                error!("TriedbReplServer finished in error: {:}?", err);
            }
        }
    }

    async fn catch_up_secondary_background(storage: Option<StorageSecondary>) {
        if let Some(storage) = storage {
            loop {
                match storage.try_catch_up() {
                    Ok(..) => {
                        log::warn!("successfully synced up secondary rocksdb with primary");
                    }
                    Err(err) => {
                        log::error!(
                            "problem with syncing up secondary rocksdb with primary {:?}",
                            err
                        );
                    }
                }

                tokio::time::sleep(Duration::new(SECONDARY_CATCH_UP_SECONDS, 0)).await;
            }
        }
    }
    // Runs tonic_server implementation with a provided configuration
    async fn run(
        self,
        runtime: &tokio::runtime::Runtime,
        exit_signal: Receiver<()>,
    ) -> Result<(), tonic::transport::Error> {
        info!(
            "Running triedb replica server at the endpoint: {:?}",
            self.server_addr
        );
        let secondary_storage = match self.storage_clone {
            UsedStorage::WritableWithGC(..) => None,
            UsedStorage::ReadOnlyNoGC(storage) => Some(storage),
        };
        let bg_secondary_jh = runtime.spawn(Self::catch_up_secondary_background(secondary_storage));

        let res = transport::Server::builder()
            .add_service(self.server)
            .serve_with_shutdown(self.server_addr, exit_signal.map(drop))
            .await;

        match bg_secondary_jh.await {
            Ok(..) => {}
            Err(err) => {
                log::error!("catch up with primary task panicked!!! {:?}", err);
            }
        }

        res
    }
}

#[derive(Debug, Error)]
pub enum RunError {
    #[error("io {0}")]
    Io(#[from] std::io::Error),
    #[error("thread join {0:?}")]
    Thread(Box<dyn std::error::Error + 'static>),
}

#[derive(Debug, Error)]
pub enum DispatchSourcesError {
    #[error("empty json file arg")]
    EmptyJsonFileArg,
    #[error("range init json {0}")]
    RangeInit(#[from] RangeJsonInitError),
    #[error("bigtable blockstore not initialized")]
    BigtableNonInit,
    #[error("solana blockstore not initialized")]
    SolanaBlockstoreNonInit,
}

#[derive(Debug, Error)]
pub enum StartError {
    #[error("evm height {0}")]
    EvmHeight(#[from] evm_height::Error),

    #[error("dispatch sources error {0}")]
    DispatchSources(#[from] DispatchSourcesError),
    #[error("run error {0}")]
    Run(#[from] RunError),
}

impl RunningService {
    pub fn start(
        bind_address: SocketAddr,

        config: Config,
        used_storage: server::UsedStorage,
        runtime: tokio::runtime::Runtime,
        solana_blockstore: Option<Arc<Blockstore>>,
    ) -> Result<Self, StartError> {
        log::info!("starting triedb replica server, {:#?}", config);

        let bigtable_blockstore = maybe_init_bigtable(config.clone(), &runtime)?;

        let max_diff_gap = config.max_diff_height_gap;
        let (range, blockstore) = dispatch_sources(config, bigtable_blockstore, solana_blockstore)?;

        let service =
            RunningService::start_internal(bind_address, range, used_storage, runtime, blockstore, max_diff_gap)?;
        Ok(service)
    }

    fn start_internal(
        bind_address: SocketAddr,
        range: Box<dyn ReadRange>,
        storage: server::UsedStorage,
        runtime: tokio::runtime::Runtime,
        block_storage: Box<dyn EvmHeightIndex>,
        max_diff_height_gap: usize,
    ) -> Result<Self, RunError> {
        log::info!("starting the thread");
        let service = server::Service::new(
            bind_address,
            max_diff_height_gap as BlockNum,
            storage,
            range,
            runtime,
            block_storage,
        )
        .into_thread()?;
        Ok(service)
    }
    pub fn join(self) -> Result<(), RunError> {
        self.server_handle.join().map_err(|err| {
            let str = format!("server handle join {:?}", err);
            RunError::Thread(str.into())
        })?;
        self.thread.join().map_err(|err| {
            let str = format!("repr of thread join err {:?}", err);
            RunError::Thread(str.into())
        })?;
        Ok(())
    }
}
