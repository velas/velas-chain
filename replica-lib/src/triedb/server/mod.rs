pub(crate) mod config;
mod proto;
mod service;

use evm_state::{Storage as StorageOptimistic, StorageSecondary};
pub use service::{RunError, RunningService, Service, StartError};

use self::proto::app_grpc::backend_server::BackendServer;

use super::{EvmHeightIndex, ReadRange};
// use derivative::Derivative;

#[derive(Debug, Clone)]
pub enum UsedStorage {
    WritableWithGC(StorageOptimistic),
    ReadOnlyNoGC(StorageSecondary),
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
