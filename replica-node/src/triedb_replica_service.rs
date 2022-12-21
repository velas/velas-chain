use std::net::SocketAddr;

use evm_state::Storage;
use solana_replica_lib::triedb_replica_server;

pub fn start_and_join(
    bind_address: SocketAddr,
    storage: Storage,
) -> Result<(), Box<(dyn std::error::Error + 'static)>> {

    let cfg = triedb_replica_server::ServiceConfig::new(bind_address, 2);
    let deps = triedb_replica_server::Dependecies::new(cfg, storage);

    log::info!("starting the thread");
    triedb_replica_server::Service::new(deps)
        .into_thread()?
        .join()?;
    Ok(())
}
