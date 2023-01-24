
use std::thread::{Builder, JoinHandle};
use futures_util::FutureExt;
use tokio::runtime::Runtime;
use tokio::sync::oneshot::{self, Receiver, Sender};

use tonic::{self, transport};

use log::{error, info};

use super::tonic_server;
use tonic_server::app_grpc::backend_server::BackendServer;
use super::{Deps, ServiceConfig};
/// The service wraps the Rpc to make it runnable in the tokio runtime
/// and handles start and stop of the service.
pub struct Service {
    server: BackendServer<tonic_server::Server>,
    config: ServiceConfig,
}

pub struct RunningService {
    thread: JoinHandle<()>,
    server_handle: BackendServer<tonic_server::Server>,
    _exit_signal_sender: Sender<()>,
}

#[allow(clippy::result_unit_err)]
impl Service {

    pub fn new(
        deps: Deps,
    ) -> Service {
        log::info!("creating new evm state rpc service {:?}", deps);
        Self {
            server: tonic_server::Server::new(deps.storage),
            config: deps.service,
        }
    }

    pub fn into_thread(self) -> std::io::Result<RunningService> {
        let (exit_signal_sender, exit_signal_receiver) = oneshot::channel::<()>();
        let runtime = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(self.config.worker_threads)
                .thread_name("velas-state-rpc-worker")
                .enable_all()
                .build()?;
        let server_handle = self.server.clone();
        let thread = Builder::new()
            .name("velas-state-rpc-runtime".to_string())
            .spawn(move || {
                self.block_on(
                    runtime,
                    exit_signal_receiver,
                );
            })?;
        // TODO: register _exit_signal_sender send into Ctrl-C handler 
        Ok(RunningService { thread, _exit_signal_sender: exit_signal_sender, server_handle})
    }

    // Start TriedbReplServer in a Tokio runtime
    fn block_on(
        self, 
        runtime: Runtime,
        exit_signal: Receiver<()>,
    ) {
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
    async fn run(
        self,
        exit_signal: Receiver<()>,
    ) -> Result<(), tonic::transport::Error> {
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

impl RunningService {
    pub fn join(self) -> Result<(), Box<(dyn std::error::Error + 'static)>> {
        self.server_handle.join()?;
        self.thread.join().map_err(|err| format!("thread join err {:?}", err.type_id()))?;
        Ok(())
    }
}
