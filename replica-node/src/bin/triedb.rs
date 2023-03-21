//! The main AccountsDb replication node responsible for replicating
//! AccountsDb information from peer a validator or another replica-node.

#![allow(clippy::integer_arithmetic)]

use std::net::SocketAddr;

use solana_replica_lib::triedb::{range::RangeJSON, server::UsedStorage, start_and_join};

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
        .arg(
            Arg::with_name("range_file")
                .long("range-file")
                .value_name("FILE")
                .takes_value(true)
                .required(true)
                //  replica-lib/src/triedb/range.rs
                .help("FILE with json of `MasterRange` serialization"),
        )
        //  [2023-02-01T14:54:48Z ERROR solana_replica_lib::triedb::client] main loop during
        //iteration over advance.added_range heights advance error: (0, 3197921),
        // (0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421, 0x768c194b80104b21fd2596b02b05220bd1dab1b2a40d0ed961d07bf5f8b0a8a2),
        // status: InvalidArgument, message: "blocks too far 3197921", details: [],
        //metadata: MetadataMap { headers: {"content-type": "application/grpc", "date": "Wed, 01 Feb 2023 14:54:48 GMT", "content-length": "0"} }
        .arg(
            Arg::with_name("block_height_diff_threshold")
                .long("block-height-diff-threshold")
                .value_name("INTEGER")
                .takes_value(true)
                .required(true)
                //  replica-lib/src/triedb/range.rs
                .help("Max difference of block height, that server won't reject diff requests of"),
        )
        .get_matches();

    let _ = env_logger::Builder::from_default_env().try_init();

    let evm_state = PathBuf::from(matches.value_of("evm_state").unwrap());
    log::info!("{:?}", evm_state);

    let socket_addr = matches.value_of("bind_address").unwrap();
    let secondary_mode = matches.is_present("secondary_mode");

    let state_rpc_bind_address: SocketAddr = socket_addr.parse()?;

    let gc_enabled = matches.is_present("gc_enabled");

    let used_storage = if secondary_mode {
        UsedStorage::ReadOnlyNoGC(Storage::open_secondary_persistent(evm_state, gc_enabled)?)
    } else {
        UsedStorage::WritableWithGC(Storage::open_persistent(
            evm_state, gc_enabled, // enable gc
        )?)
    };

    let range_file = matches.value_of("range_file").unwrap();
    let range = RangeJSON::new(range_file)?;
    let block_threshold = matches
        .value_of("block_height_diff_threshold")
        .unwrap()
        .parse::<evm_state::BlockNum>()?;


    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(10)
        .thread_name("velas-state-rpc-worker")
        .enable_all()
        .build()?;
    let block_storage = runtime
        .block_on(async { solana_storage_bigtable::LedgerStorage::new(false, None, None).await })?;
    start_and_join(
        state_rpc_bind_address,
        range,
        block_threshold,
        used_storage,
        runtime,
        block_storage,
    )?;
    Ok(())
}
