//! The main AccountsDb replication node responsible for replicating
//! AccountsDb information from peer a validator or another replica-node.

#![allow(clippy::integer_arithmetic)]

use std::net::SocketAddr;

use solana_replica_lib::triedb::{server::UsedStorage, start_and_join};

use {
    clap::{crate_description, crate_name, App, AppSettings, Arg},
    std::{env, path::PathBuf},
};

use evm_state::Storage;

pub fn main() -> Result<(), Box<(dyn std::error::Error + 'static)>> {
    let matches = App::new(crate_name!())
        .about(crate_description!())
        .version(solana_version::version!())
        .setting(AppSettings::VersionlessSubcommands)
        .setting(AppSettings::InferSubcommands)
        .arg(
            Arg::with_name("evm_state")
                .short("e")
                .long("evm-state")
                .value_name("DIR")
                .takes_value(true)
                .required(true)
                .help("Use DIR as ledger location"),
        )
        .arg(
            Arg::with_name("gc_enabled")
                .long("gc")
                .required(false)
                .takes_value(false)
                .help("whether to open evm_state_db in secondary mode"),
        )
        .arg(
            Arg::with_name("secondary_mode")
                .long("secondary")
                .required(false)
                .takes_value(false)
                .help("whether to open evm_state_db in secondary mode"),
        )
        .arg(
            Arg::with_name("bind_address")
                .long("bind-address")
                .value_name("HOST:PORT")
                .takes_value(true)
                .validator(solana_net_utils::is_host_port)
                .required(true)
                .help("IP:PORT address to bind the state gRPC server"),
        )
        .get_matches();

    let _ = env_logger::Builder::new().parse_filters("info").try_init();

    let evm_state = PathBuf::from(matches.value_of("evm_state").unwrap());
    log::info!("{:?}", evm_state);

    let socket_addr = matches.value_of("bind_address").unwrap();
    let secondary_mode = matches.is_present("secondary_mode");

    let state_rpc_bind_address: SocketAddr = socket_addr.parse()?;

    let gc_enabled = matches.is_present("gc_enabled");

    let used_storage = if secondary_mode {
        UsedStorage::ReadOnlyNoGC(Storage::open_secondary_persistent(
            evm_state,
            gc_enabled, 
        )?)
    } else {
        UsedStorage::WritableWithGC(Storage::open_persistent(
            evm_state,
            gc_enabled, // enable gc
        )?)
    };

    start_and_join(state_rpc_bind_address, used_storage)?;
    Ok(())
}
