use std::net::SocketAddr;

mod proto;
mod service;

use evm_state::{Storage as StorageOptimistic, StorageSecondary};
pub use service::{RunningService, Service};

use self::proto::app_grpc::backend_server::BackendServer;

use super::{EvmHeightIndex, ReadRange};
use derivative::Derivative;

#[derive(Debug, Clone)]
pub enum UsedStorage {
    WritableWithGC(StorageOptimistic),
    ReadOnlyNoGC(StorageSecondary),
}

#[derive(Derivative)]
#[derivative(Debug)]
pub struct Deps {
    service: ServiceConfig,
    storage: UsedStorage,
    #[derivative(Debug = "ignore")]
    range: Box<dyn ReadRange>,

    runtime: tokio::runtime::Runtime,
    #[derivative(Debug = "ignore")]
    block_storage: Box<dyn EvmHeightIndex>,
}

#[derive(Debug)]
pub struct ServiceConfig {
    server_addr: SocketAddr,

    block_threshold: evm_state::BlockNum,
}

impl ServiceConfig {
    pub fn new(server_addr: SocketAddr, block_threshold: evm_state::BlockNum) -> Self {
        ServiceConfig {
            server_addr,
            block_threshold,
        }
    }
}

// as there are only 2 fields, the name is shortened: Dependencies -> Deps
impl Deps {
    pub fn new(
        service: ServiceConfig,
        storage: UsedStorage,
        range: Box<dyn ReadRange>,
        runtime: tokio::runtime::Runtime,
        block_storage: Box<dyn EvmHeightIndex>,
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

pub struct Server {
    storage: UsedStorage,
    range: Box<dyn ReadRange>,
    block_threshold: evm_state::BlockNum,
    block_storage: Box<dyn EvmHeightIndex>,
}

impl Server {
    pub fn new(
        storage: UsedStorage,
        range: Box<dyn ReadRange>,
        block_threshold: evm_state::BlockNum,
        block_storage: Box<dyn EvmHeightIndex>,
    ) -> BackendServer<Self> {
        BackendServer::new(Server {
            storage,
            range,
            block_threshold,
            block_storage,
        })
    }
}
