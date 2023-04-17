use std::net::{AddrParseError, SocketAddr};
use std::num::ParseIntError;
use std::path::PathBuf;
use std::str::FromStr;

use solana_replica_lib::triedb::error::evm_height;
use solana_replica_lib::triedb::CachedRootsLedgerStorage;
use solana_replica_lib::triedb::{client::Client, range::RangeJSON};

use clap::{crate_description, crate_name, App, AppSettings, Arg, ArgMatches};
use evm_state::Storage;
use thiserror::Error;

#[derive(Debug)]
struct ParsedArgs {
    state_rpc_address: String,
    timeout_seconds: u64,
    max_height_gap: usize,
    evm_state: PathBuf,
    coarse_range_file: String,
    fine_range_file: String,
    request_workers: u32,
    db_workers: u32,
}

#[derive(Error, Debug)]
enum Error {
    #[error("address parse {0}")]
    AddrParse(#[from] AddrParseError),
    #[error("integer parse {0}")]
    IntParse(#[from] ParseIntError),
    #[error("evm height sanity check {0}")]
    EvmHeightSanityCheck(#[from] evm_height::Error),
    #[error("storage error {0}")]
    Storage(#[from] evm_state::storage::Error),
    #[error("range init {0}")]
    RangeInit(#[from] solana_replica_lib::triedb::error::RangeJsonInitError),
    #[error("solana storage bigtable {0}")]
    StorageBigtable(#[from] solana_storage_bigtable::Error),
    #[error("connect error {0}")]
    Connect(#[from] tonic::transport::Error),
}
const MAX_HEIGHT_DIFF_DEFAULT: &str = "700000";
const TIMEOUT_SECONDS_DEFAULT: &str = "60";

impl ParsedArgs {
    fn parse(matches: ArgMatches) -> Result<Self, Error> {
        let state_rpc_address = matches.value_of("state_rpc_address").unwrap();

        let secure_flag = matches.is_present("tls");
        let secure_flag = if secure_flag { "s" } else { "" };

        let state_rpc_address = {
            SocketAddr::from_str(state_rpc_address)?;

            format!("http{}://{}", secure_flag, state_rpc_address)
        };

        let evm_state = PathBuf::from(matches.value_of("evm_state").unwrap());
        let range_file = matches.value_of("range_file").unwrap().to_string();
        let rangemap_file = matches.value_of("rangemap_file").unwrap().to_string();
        let db_workers = matches.value_of("db_workers").unwrap().parse().unwrap();
        let request_workers = matches
            .value_of("request_workers")
            .unwrap()
            .parse()
            .unwrap();

        let max_height_gap: usize = matches
            .value_of("max_height_diff")
            .unwrap_or(MAX_HEIGHT_DIFF_DEFAULT)
            .parse()?;

        let timeout_seconds: u64 = matches
            .value_of("grpc_timeout_sec")
            .unwrap_or(TIMEOUT_SECONDS_DEFAULT)
            .parse()?;

        Ok(Self {
            state_rpc_address,
            timeout_seconds,
            max_height_gap,
            evm_state,
            coarse_range_file: range_file,
            fine_range_file: rangemap_file,
            db_workers,
            request_workers,
        })
    }

    fn build(self) -> Result<ClientOpts, Error> {
        log::info!("building ClientOpts {:#?}", self);

        let gc_enabled = true;
        let storage = Storage::open_persistent(self.evm_state, gc_enabled)?;

        let range = RangeJSON::new(self.coarse_range_file, Some(self.fine_range_file))?;
        Ok(ClientOpts{
            state_rpc_address: self.state_rpc_address,
            timeout_seconds: self.timeout_seconds,
            max_height_gap: self.max_height_gap,
            storage,
            range,
            request_workers: self.request_workers,
            db_workers: self.db_workers,
        })
    }
}

pub struct ClientOpts {
    state_rpc_address: String,
    timeout_seconds: u64,
    max_height_gap: usize,
    storage: Storage,
    range: RangeJSON,
    request_workers: u32,
    db_workers: u32,
}


#[tokio::main(flavor = "multi_thread", worker_threads = 10)]
async fn main() -> Result<(), Error> {
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
            Arg::with_name("state_rpc_address")
                .long("state-rpc-address")
                .value_name("HOST:PORT")
                .multiple(false)
                // .multiple(true)
                // .number_of_values(1)
                .takes_value(true)
                .validator(solana_net_utils::is_host_port)
                .required(true)
                .help("IP:PORT address of the state gRPC server to connect to"),
        )
        .arg(
            Arg::with_name("tls")
                .long("tls")
                .takes_value(false)
                .help("Use https instead of http"),
        )
        .arg(
            Arg::with_name("range_file")
                .long("range-file")
                .value_name("FILE")
                .takes_value(true)
                .required(true)
                //  replica-lib/src/triedb/range.rs
                .help("FILE with json of coarse `RangeJSON` serialization"),
        )
        .arg(
            Arg::with_name("rangemap_file")
                .long("rangemap-file")
                .value_name("FILE")
                .takes_value(true)
                .required(true)
                //  replica-lib/src/triedb/range.rs
                .help("FILE with json of fine `RangeJSON` serialization"),
        )
        .arg(
            Arg::with_name("request_workers")
                .long("request-workers")
                .value_name("NUM")
                .takes_value(true)
                .default_value("50")
                //  replica-lib/src/triedb/range.rs
                .help("NUM of parallel grpc requests' workers"),
        )
        .arg(
            Arg::with_name("db_workers")
                .long("db-workers")
                .value_name("NUM")
                .takes_value(true)
                .default_value("50")
                //  replica-lib/src/triedb/range.rs
                .help("NUM of parallel db workers"),
        )
        .arg(
            Arg::with_name("grpc_timeout_sec")
                .long("grpc-timeout-sec")
                .value_name("SEC")
                .takes_value(true)
                //  replica-lib/src/triedb/range.rs
                .help("grpc timeout SEC"),
        )
        .arg(
            Arg::with_name("max_height_diff")
                .long("max-height-diff")
                .value_name("NUM")
                .hidden(true)
                .takes_value(true)
                //  replica-lib/src/triedb/range.rs
                .help("NUM of maximum height diff attempted"),
        )
        .get_matches();

    let _ = env_logger::Builder::from_default_env().try_init();
    log::info!("cwd start {}", std::env::current_dir().unwrap().display());
    let client_opts = ParsedArgs::parse(matches)?;
    let client_opts = client_opts.build()?;
    let mut client = connect(client_opts).await?;

    client.sync().await;

    // fortunately, horizon is unreachable
    Ok(())
}

async fn connect(client_opts: ClientOpts) -> Result<Client<CachedRootsLedgerStorage>, Error> {
    let block_storage = solana_storage_bigtable::LedgerStorage::new(
        false,
        Some(std::time::Duration::new(20, 0)),
        None,
    )
    .await?;

    let block_storage = CachedRootsLedgerStorage::new(
        block_storage,
        MAINNET_HINT_DEFAULT.parse().expect("parse hint"),
    );

    let client = async {
        Client::connect(
            client_opts.state_rpc_address,
            client_opts.timeout_seconds,
            client_opts.range,
            client_opts.storage,
            block_storage,
            client_opts.request_workers,
            client_opts.db_workers,
            client_opts.max_height_gap,
        )
        .await
    }
    .await?;

    Ok(client)
}

const MAINNET_HINT_DEFAULT: &str = "62184801";
