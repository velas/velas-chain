use std::net::{AddrParseError, SocketAddr};
use std::num::ParseIntError;
use std::path::PathBuf;
use std::str::FromStr;

use solana_replica_lib::triedb::{client::Client, range::RangeJSON};

use clap::{crate_description, crate_name, App, AppSettings, Arg, ArgMatches};
use evm_state::{BlockNum, Storage};
use solana_storage_bigtable::LedgerStorage;
use thiserror::Error;

#[derive(Debug)]
struct ParsedArgs {
    state_rpc_address: String,
    evm_state: PathBuf,
    range_file: String,
}

#[derive(Error, Debug)]
enum Error {
    #[error("address parse {0}")]
    AddrParse(#[from] AddrParseError),
    #[error("integer parse {0}")]
    IntParse(#[from] ParseIntError),
    #[error("storage error {0}")]
    Storage(#[from] evm_state::storage::Error),
    #[error("range init {0}")]
    RangeInit(#[from] solana_replica_lib::triedb::error::RangeInitError),
    #[error("solana storage bigtable {0}")]
    StorageBigtable(#[from] solana_storage_bigtable::Error),
    #[error("client error {0}")]
    Client(#[from] solana_replica_lib::triedb::error::ClientError),
    #[error("bootstrap error {0}")]
    Bootstrap(#[from] solana_replica_lib::triedb::error::BootstrapError),
}

impl ParsedArgs {
    fn parse(matches: ArgMatches) -> Result<(Option<BlockNum>, Self), Error> {
        let state_rpc_address = matches.value_of("state_rpc_address").unwrap();

        let secure_flag = matches.is_present("tls");
        let secure_flag = if secure_flag { "s" } else { "" };

        let state_rpc_address = {
            SocketAddr::from_str(state_rpc_address)?;

            format!("http{}://{}", secure_flag, state_rpc_address)
        };

        let evm_state = PathBuf::from(matches.value_of("evm_state").unwrap());
        let range_file = matches.value_of("range_file").unwrap().to_string();

        let bootstrap_height = match matches.value_of("bootstrap_height") {
            None => None,
            Some(height_str) => {
                let height = height_str.parse::<BlockNum>()?;
                Some(height)
            }
        };

        Ok((
            bootstrap_height,
            Self {
                state_rpc_address,
                evm_state,
                range_file,
            },
        ))
    }

    fn build(self) -> Result<ClientOpts, Error> {
        log::info!("building ClientOpts {:#?}", self);

        let gc_enabled = true;
        let storage = Storage::open_persistent(self.evm_state, gc_enabled)?;

        let range = RangeJSON::new(self.range_file)?;
        Ok(ClientOpts::new(self.state_rpc_address, storage, range))
    }
}

pub struct ClientOpts {
    state_rpc_address: String,
    storage: Storage,
    range: RangeJSON,
}

impl ClientOpts {
    pub fn new(state_rpc_address: String, storage: Storage, range: RangeJSON) -> Self {
        Self {
            state_rpc_address,
            storage,
            range,
        }
    }
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
                .help("FILE with json of `MasterRange` serialization"),
        )
        .arg(
            Arg::with_name("bootstrap_height")
                .long("bootstrap-height")
                .value_name("BLOCK_NUM")
                .takes_value(true)
                //  replica-lib/src/triedb/range.rs
                .help("BLOCK_NUM to pull starting state from"),
        )
        .get_matches();

    let _ = env_logger::Builder::from_default_env().try_init();
    log::info!("cwd start {}", std::env::current_dir().unwrap().display());

    let (bootstrap_point, client_opts) = ParsedArgs::parse(matches)?;
    let client_opts = client_opts.build()?;
    let mut client = connect(client_opts).await?;

    if let Some(height) = bootstrap_point {
        let mut client = bootstrap(height, client).await?;
        client.routine().await;
    } else {
        client.routine().await;
    }

    // fortunately, horizon is unreachable
    Ok(())
}

async fn connect(client_opts: ClientOpts) -> Result<Client<LedgerStorage>, Error> {
    let block_storage = solana_storage_bigtable::LedgerStorage::new(false, None, None).await?;
    let client = async {
        Client::connect(
            client_opts.state_rpc_address,
            client_opts.range,
            client_opts.storage,
            block_storage,
        )
        .await
    }
    .await?;

    Ok(client)
}

async fn bootstrap(
    height: BlockNum,
    mut client: Client<LedgerStorage>,
) -> Result<Client<LedgerStorage>, Error> {
    // let block_range = client.get_block_range().await;


    client.bootstrap_state(height).await?;
    Ok(client)
}
