use futures_util::FutureExt;
use std::thread::{Builder, JoinHandle};
use tokio::sync::oneshot::{self, Receiver, Sender};

use tonic::{self, transport};

use log::{error, info};

use crate::triedb::LittleBig;

use super::tonic_server;
use super::{Deps, ServiceConfig};
use tonic_server::app_grpc::backend_server::BackendServer;
/// The service wraps the Rpc to make it runnable in the tokio runtime
/// and handles start and stop of the service.
pub struct Service<S: LittleBig + Sync + Send + 'static> {
    server: BackendServer<tonic_server::Server<S>>,
    config: ServiceConfig,
    runtime: Option<tokio::runtime::Runtime>,
}

pub struct RunningService<S: LittleBig + Sync + Send + 'static> {
    thread: JoinHandle<()>,
    server_handle: BackendServer<tonic_server::Server<S>>,
    _exit_signal_sender: Sender<()>,
}

#[allow(clippy::result_unit_err)]
impl<S: LittleBig + Sync + Send + 'static> Service<S> {
    pub fn new(deps: Deps<S>) -> Service<S> {
        log::info!("creating new evm state rpc service {:#?}", deps);
        Self {
            server: tonic_server::Server::new(
                deps.storage,
                deps.range,
                deps.service.block_threshold,
                deps.block_storage,
            ),
            runtime: Some(deps.runtime),
            config: deps.service,
        }
    }

    pub fn into_thread(self) -> std::io::Result<RunningService<S>> {
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
        let runtime = self.runtime.take().unwrap();
        let result = runtime.block_on(self.run(exit_signal));

        match result {
            Ok(_) => {
                info!("TriedbReplServer finished");
            }
            Err(err) => {
                error!("TriedbReplServer finished in error: {:}?", err);
            }
        }
    }
    // Runs tonic_server implementation with a provided configuration
    async fn run(self, exit_signal: Receiver<()>) -> Result<(), tonic::transport::Error> {
        info!(
            "Running TriedbReplServer at the endpoint: {:?}",
            self.config.server_addr
        );

        transport::Server::builder()
            .add_service(self.server)
            .serve_with_shutdown(self.config.server_addr, exit_signal.map(drop))
            .await
    }
}

impl<S: LittleBig + Sync + Send + 'static> RunningService<S> {
    pub fn join(self) -> Result<(), Box<(dyn std::error::Error + 'static)>> {
        self.server_handle.join()?;
        self.thread
            .join()
            .map_err(|err| format!("thread join err {:?}", err.type_id()))?;
        Ok(())
    }
}
