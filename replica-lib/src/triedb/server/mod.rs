use std::net::SocketAddr;

mod tonic_server;
mod service;

use evm_state::{StorageSecondary, Storage as StorageOptimistic};
pub use service::{Service, RunningService};

use super::range::MasterRange;
use derivative::Derivative;


#[derive(Debug)]
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
