//! The main AccountsDb replication node responsible for replicating
//! AccountsDb information from peer a validator or another replica-node.

#![allow(clippy::integer_arithmetic)]

use std::{
    net::{AddrParseError, SocketAddr},
    str::FromStr,
    sync::Arc,
};

use solana_ledger::{
    blockstore::Blockstore,
    blockstore_db::{AccessType, BlockstoreOptions},
};
use solana_replica_lib::triedb::{
    error::{evm_height, RangeJsonInitError},
    server::{RunError, RunningService, StartError, UsedStorage},
    {Config, HeightIndexSource, ParseError, RangeSource},
};

use {
    clap::{crate_description, crate_name, App, AppSettings, Arg},
    std::{env, path::PathBuf},
};

use evm_state::Storage;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    Storage(#[from] evm_state::storage::Error),
    #[error(transparent)]
    AddrParse(#[from] AddrParseError),
    #[error(transparent)]
    RangeInit(#[from] RangeJsonInitError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("evm height {0}")]
    EvmHeight(#[from] evm_height::Error),
    #[error("blockstore {0}")]
    Blockstore(#[from] solana_ledger::blockstore::BlockstoreError),

    #[error(transparent)]
    Run(#[from] RunError),
    #[error("config parse {0}")]
    ConfigParse(#[from] ParseError),
    #[error(transparent)]
    Start(#[from] StartError),
    #[error(transparent)]
    RangeSource(Box<dyn std::error::Error + 'static>),
}

pub fn main() -> Result<(), Error> {
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
                .help("whether to open evm_state_db with gc_enabled"),
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
            Arg::with_name("range_source")
                .long("range-source")
                .value_name("STRING")
                .takes_value(true)
                .possible_values(&["json", "bigtable", "solana_blockstore"])
                .required(true)
                .help("source of range data"),
        )
        .arg(
            Arg::with_name("height_index_source")
                .long("height-index-source")
                .value_name("STRING")
                .takes_value(true)
                .possible_values(&["bigtable", "solana_blockstore"])
                .required(true)
                .help("source of evm height index data"),
        )
        .arg(
            Arg::with_name("range_file")
                .long("range-file")
                .value_name("FILE")
                .takes_value(true)
                .required(false)
                .required_if("range_source", "json")
                .help("FILE with json of `RangeJSON` serialization"),
        )
        .arg(
            Arg::with_name("bigtable_length_hint")
                .long("bigtable-length-hint")
                .value_name("NUMBER")
                .takes_value(true)
                .required(false)
                .help("NUMBER of last block hint"),
        )
        .arg(
            Arg::with_name("blockstore_path")
                .long("blockstore-path")
                .value_name("DIR")
                .takes_value(true)
                .required(false)
                .required_ifs(&[
                    ("range_source", "solana_blockstore"),
                    ("height_index_source", "solana_blockstore"),
                ])
                .help("PATH of blockstore local storage for range and/or state root index"),
        )
        .arg(
            Arg::with_name("max_height_diff")
                .long("max-height-diff")
                .value_name("NUM")
                .takes_value(true)
                .required(false)
                .help("NUM of maximum height difference"),
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

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(10)
        .thread_name("velas-state-rpc-worker")
        .enable_all()
        .build()?;

    let blockstore_path = matches.value_of("blockstore_path");

    let config = Config::parse_standalone(&matches)?;

    // fence

    let solana_blockstore = init_solana_blockstore(
        config.range_source.clone(),
        config.height_index_source.clone(),
        blockstore_path,
    )?;

    let service = RunningService::start(
        state_rpc_bind_address,
        config,
        used_storage,
        runtime,
        solana_blockstore,
    )?;

    service.join().map_err(|err| RunError::Thread(err.into()))?;
    Ok(())
}

fn init_solana_blockstore(
    range_source: RangeSource,
    height_index_source: HeightIndexSource,
    blockstore_path: Option<&str>,
) -> Result<Option<Arc<Blockstore>>, Error> {
    let solana_blockstore = match (range_source, height_index_source) {
        (RangeSource::SolanaBlockstore, _) | (_, HeightIndexSource::SolanaBlockstore) => {
            log::warn!("init solana_blockstore called");
            let blockstore_path = blockstore_path.expect("blockstore_path is empty");

            let path = PathBuf::from_str(blockstore_path).unwrap();
            let options = BlockstoreOptions {
                access_type: AccessType::TryPrimaryThenSecondary,
                recovery_mode: None,
                enforce_ulimit_nofile: false,
                column_options: Default::default(),
            };
            let solana_blockstore =
                solana_ledger::blockstore::Blockstore::open_with_options(path.as_ref(), options)
                    .map(Arc::new)?;
            Some(solana_blockstore)
        }
        _ => None,
    };
    Ok(solana_blockstore)
}
