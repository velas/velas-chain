use std::net::SocketAddr;

mod server;
mod service;

use evm_state::Storage;
pub use service::{Service, RunningService};

pub struct Dependecies {
    service: ServiceConfig,
    storage: Storage,
}

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

impl Dependecies {
    pub fn new(
        service: ServiceConfig,
        storage: Storage,
    ) -> Self {
        Self {
            service,
            storage,
        }
    }
}
