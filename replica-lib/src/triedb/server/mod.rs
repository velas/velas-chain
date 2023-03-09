use std::net::SocketAddr;

mod proto;
mod service;

use evm_state::{StorageSecondary, Storage as StorageOptimistic};
pub use service::{Service, RunningService};

use self::proto::app_grpc::backend_server::BackendServer;

use super::{range::MasterRange, EvmHeightIndex};
use derivative::Derivative;


#[derive(Debug, Clone)]
pub enum UsedStorage {
    WritableWithGC(StorageOptimistic),
    ReadOnlyNoGC(StorageSecondary),
}

#[derive(Derivative)]
#[derivative(Debug)]
pub struct Deps<S> {
    service: ServiceConfig,
    storage: UsedStorage,
    range: MasterRange,

    runtime: tokio::runtime::Runtime,
    #[derivative(Debug="ignore")]
    block_storage: S,
}

#[derive(Debug)]
pub struct ServiceConfig {
    server_addr: SocketAddr,

    block_threshold: evm_state::BlockNum,
}

impl ServiceConfig {
    pub fn new(
        server_addr: SocketAddr,
        block_threshold: evm_state::BlockNum,
    ) -> Self {
        ServiceConfig { server_addr,  block_threshold }
    }
}

// as there are only 2 fields, the name is shortened: Dependencies -> Deps
impl<S> Deps<S> {
    pub fn new(
        service: ServiceConfig,
        storage: UsedStorage,
        range: MasterRange,
        runtime: tokio::runtime::Runtime,
        block_storage: S,
    ) -> Self {
        Self {
            service,
            storage,
            range,
            block_storage,
            runtime,
        }
    }
}

pub struct Server<S> {
    storage: UsedStorage,
    range: MasterRange,
    block_threshold: evm_state::BlockNum,
    block_storage: S,
}
impl<S> Server<S>
where
    S: EvmHeightIndex + Send + Sync + 'static,
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
}
