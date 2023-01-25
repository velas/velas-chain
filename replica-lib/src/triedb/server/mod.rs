use std::net::SocketAddr;

mod tonic_server;
mod service;

use evm_state::{StorageSecondary, Storage as StorageOptimistic};
pub use service::{Service, RunningService};


#[derive(Debug)]
pub enum UsedStorage {
    WritableWithGC(StorageOptimistic),
    ReadOnlyNoGC(StorageSecondary),
}

#[derive(Debug)]
pub struct Deps {
    service: ServiceConfig,
    storage: UsedStorage,
}

#[derive(Debug)]
pub struct ServiceConfig {
    server_addr: SocketAddr,
    worker_threads: usize,
}

impl ServiceConfig {
    pub fn new(
        server_addr: SocketAddr,
        worker_threads: usize,
    ) -> Self {
        ServiceConfig { server_addr, worker_threads }
    }
}

// as there are only 2 fields, the name is shortened: Dependencies -> Deps
impl Deps {
    pub fn new(
        service: ServiceConfig,
        storage: UsedStorage,
    ) -> Self {
        Self {
            service,
            storage,
        }
    }
}
