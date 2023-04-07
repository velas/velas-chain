//! The main AccountsDb replication node responsible for replicating
//! AccountsDb information from peer a validator or another replica-node.

#![allow(clippy::integer_arithmetic)]

use std::{
    net::{AddrParseError, SocketAddr},
    str::FromStr,
    sync::Arc,
};

use clap::ArgMatches;
use solana_ledger::{blockstore::Blockstore, blockstore_db::AccessType};
use solana_replica_lib::triedb::{
    bigtable::CachedRootsLedgerStorage,
    error::{evm_height, RangeInitError},
    range::RangeJSON,
    server::UsedStorage,
    start_and_join, EvmHeightIndex, ReadRange, RunError,
};

use {
    clap::{crate_description, crate_name, App, AppSettings, Arg},
    std::{env, path::PathBuf},
};

use evm_state::{BlockNum, Storage};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    Storage(#[from] evm_state::storage::Error),
    #[error(transparent)]
    AddrParse(#[from] AddrParseError),
    #[error(transparent)]
    RangeInit(#[from] RangeInitError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("evm height {0}")]
    EvmHeight(#[from] evm_height::Error),
    #[error("blockstore {0}")]
    Blockstore(#[from] solana_ledger::blockstore::BlockstoreError),
    #[error(transparent)]
    Run(#[from] RunError),
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
                .help("PATH of blockstore local storage for range and/or state root index"),
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

    let range_source = matches.value_of("range_source").unwrap();
    let height_index_source = matches.value_of("height_index_source").unwrap();
    let blockstore_path = matches.value_of("blockstore_path");
    let solana_blockstore =
        init_solana_blockstore(range_source, height_index_source, blockstore_path)?;

    let bigtable_length_hint = matches
        .value_of("bigtable_length_hint")
        .unwrap_or(MAINNET_HINT_DEFAULT)
        .parse()
        .expect("parse bigtable_length_hint");

    let bigtable_blockstore = init_bigtable(
        range_source,
        height_index_source,
        &runtime,
        bigtable_length_hint,
    )?;

    let range = dispatch_range_source(
        range_source,
        &matches,
        bigtable_blockstore.clone(),
        solana_blockstore.clone(),
    )?;
    let bigtable_blockstore =
        dispatch_height_index_source(height_index_source, bigtable_blockstore, solana_blockstore)?;

    start_and_join(
        state_rpc_bind_address,
        range,
        used_storage,
        runtime,
        bigtable_blockstore,
    )?;
    Ok(())
}

const MAINNET_HINT_DEFAULT: &str = "62800000";

fn dispatch_range_source(
    range_source: &str,
    matches: &ArgMatches,
    bigtable_blockstore: Option<CachedRootsLedgerStorage>,
    solana_blockstore: Option<Arc<Blockstore>>,
) -> Result<Box<dyn ReadRange>, Error> {
    let range: Box<dyn ReadRange> = match range_source {
        value if value == "json" => {
            let range_file = matches
                .value_of("range_file")
                .expect("empty range-file param");
            let range = RangeJSON::new(range_file, None)?;
            Box::new(range)
        }
        value if value == "bigtable" => {
            let bigtable_blockstore =
                bigtable_blockstore.expect("bigtable_blockstore not initialized");
            Box::new(bigtable_blockstore)
        }

        value if value == "solana_blockstore" => {
            let solana_blockstore = solana_blockstore.expect("blockstore_path arg empty");
            Box::new(solana_blockstore)
        }
        value => {
            return Err(Error::RangeSource(
                format!("invalid choice of range_source {}", value).into(),
            ));
        }
    };
    Ok(range)
}

fn dispatch_height_index_source(
    height_index_source: &str,
    bigtable_blockstore: Option<CachedRootsLedgerStorage>,
    solana_blockstore: Option<Arc<Blockstore>>,
) -> Result<Box<dyn EvmHeightIndex>, Error> {
    let index: Box<dyn EvmHeightIndex> = match height_index_source {
        value if value == "bigtable" => {
            let bigtable_blockstore =
                bigtable_blockstore.expect("bigtable_blockstore not initialized");
            Box::new(bigtable_blockstore)
        }

        value if value == "solana_blockstore" => {
            let solana_blockstore = solana_blockstore.expect("solana_blockstore not initialized");
            Box::new(solana_blockstore)
        }
        value => {
            return Err(Error::RangeSource(
                format!("invalid choice of range_source {}", value).into(),
            ));
        }
    };
    Ok(index)
}
fn init_solana_blockstore(
    range_source: &str,
    height_index_source: &str,
    blockstore_path: Option<&str>,
) -> Result<Option<Arc<Blockstore>>, Error> {
    let solana_blockstore = match (range_source, height_index_source) {
        ("solana_blockstore", _) | (_, "solana_blockstore") => {
            log::warn!("init solana_blockstore called");
            let blockstore_path = blockstore_path.expect("blockstore_path is empty");

            let path = PathBuf::from_str(blockstore_path).unwrap();
            let solana_blockstore = solana_ledger::blockstore::Blockstore::open_with_access_type(
                path.as_ref(),
                AccessType::TryPrimaryThenSecondary,
                None,
                false,
            )
            .map(Arc::new)?;
            Some(solana_blockstore)
        }
        _ => None,
    };
    Ok(solana_blockstore)
}

fn init_bigtable(
    range_source: &str,
    height_index_source: &str,
    runtime: &tokio::runtime::Runtime,
    bigtable_length_hint: BlockNum,
) -> Result<Option<CachedRootsLedgerStorage>, Error> {
    let bigtable = match (range_source, height_index_source) {
        ("bigtable", _) | (_, "bigtable") => {
            log::warn!("init bigtable called");
            let bigtable_blockstore = runtime.block_on(async {
                let bigtable_blockstore = solana_storage_bigtable::LedgerStorage::new(
                    false,
                    Some(std::time::Duration::new(20, 0)),
                    None,
                )
                .await;

                let bigtable_blockstore = match bigtable_blockstore {
                    Err(err) => return Err(evm_height::Error::from(err)),
                    Ok(bigtable_blockstore) => bigtable_blockstore,
                };
                let bigtable_blockstore =
                    CachedRootsLedgerStorage::new(bigtable_blockstore, bigtable_length_hint);
                match bigtable_blockstore.get_last_available_block().await {
                    Err(err) => {
                        return Err(err);
                    }
                    Ok(height) => {
                        log::info!("ledger storage sanity check done : last height {}", height);
                    }
                }
                Ok(bigtable_blockstore)
            })?;
            Some(bigtable_blockstore)
        }
        _ => None,
    };
    Ok(bigtable)
}
