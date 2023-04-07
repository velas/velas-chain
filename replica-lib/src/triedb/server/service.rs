use evm_state::StorageSecondary;
use futures_util::FutureExt;
use std::thread::{Builder, JoinHandle};
use std::time::Duration;
use tokio::sync::oneshot::{self, Receiver, Sender};

use tonic::{self, transport};

use log::{error, info};

use super::{proto, UsedStorage};
use super::{Deps, ServiceConfig};
use proto::app_grpc::backend_server::BackendServer;
/// The service wraps the Rpc to make it runnable in the tokio runtime
/// and handles start and stop of the service.
pub struct Service {
    server: BackendServer<super::Server>,
    config: ServiceConfig,
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
    pub fn new(deps: Deps) -> Service {
        log::info!("creating new evm state rpc service {:#?}", deps);

        deps.runtime.block_on(async {
            let result = deps.range.get().await;
            log::info!("check range at startup : {:?}", result);
        });

        Self {
            server: super::Server::new(
                deps.storage.clone(),
                deps.range,
                deps.service.block_threshold,
                deps.block_storage,
            ),
            runtime: Some(deps.runtime),
            config: deps.service,
            storage_clone: deps.storage,
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
            "Running TriedbReplServer at the endpoint: {:?}",
            self.config.server_addr
        );
        let secondary_storage = match self.storage_clone {
            UsedStorage::WritableWithGC(..) => None,
            UsedStorage::ReadOnlyNoGC(storage) => Some(storage),
        };
        let bg_secondary_jh = runtime.spawn(Self::catch_up_secondary_background(secondary_storage));

        let res = transport::Server::builder()
            .add_service(self.server)
            .serve_with_shutdown(self.config.server_addr, exit_signal.map(drop))
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

impl RunningService {
    pub fn join(self) -> Result<(), String> {
        self.server_handle
            .join()
            .map_err(|err| format!("server handle join {:?}", err))?;
        self.thread
            .join()
            .map_err(|err| format!("repr of thread join err {:?}", err))?;
        Ok(())
    }
}
