use std::net::SocketAddr;

use evm_state::Storage;
use solana_replica_lib::triedb_replica::server;

pub fn start_and_join(
    bind_address: SocketAddr,
    storage: Storage,
) -> Result<(), Box<(dyn std::error::Error + 'static)>> {

    let cfg = server::ServiceConfig::new(bind_address, 2);
    let deps = server::Dependecies::new(cfg, storage);

    log::info!("starting the thread");
    server::Service::new(deps)
        .into_thread()?
        .join()?;
    Ok(())
}
