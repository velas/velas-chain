use std::net::{AddrParseError, SocketAddr};
use std::path::PathBuf;
use std::str::FromStr;

use solana_replica_lib::triedb::{client::Client, range::MasterRange};

use clap::{crate_description, crate_name, App, AppSettings, Arg, ArgMatches};
use evm_state::{BlockNum, Storage};
use futures::future::join_all;
use solana_storage_bigtable::LedgerStorage;
#[derive(Debug)]
struct ParsedArgs {
    state_rpc_addresses: Vec<String>,
    evm_state: PathBuf,
    range_file: String,
}

impl ParsedArgs {
    fn parse(matches: ArgMatches) -> anyhow::Result<(Option<BlockNum>, Self)> {
        let state_rpc_addresses = matches
            .values_of("state_rpc_address")
            .unwrap()
            .map(|str| str.to_string());

        let secure_flag = matches.is_present("tls");
        let secure_flag = if secure_flag { "s" } else { "" };

        let result: Result<Vec<String>, AddrParseError> = state_rpc_addresses
            .map(|address| {
                SocketAddr::from_str(&address)?;

                Ok(format!("http{}://{}", secure_flag, address))
            })
            .collect();

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
                state_rpc_addresses: result?,
                evm_state,
                range_file,
            },
        ))
    }
    fn build(self) -> anyhow::Result<Vec<ClientOpts>> {
        log::info!("building ClientOpts {:#?}", self);

        let gc_enabled = true;
        let storage = Storage::open_persistent(self.evm_state, gc_enabled)?;

        let range = MasterRange::new(self.range_file)?;
        let result = self
            .state_rpc_addresses
            .into_iter()
            .map(|address| ClientOpts::new(address, storage.clone(), range.clone()))
            .collect();
        Ok(result)
    }
}

pub struct ClientOpts {
    state_rpc_address: String,
    storage: Storage,
    range: MasterRange,
}

impl ClientOpts {
    pub fn new(state_rpc_address: String, storage: Storage, range: MasterRange) -> Self {
        Self {
            state_rpc_address,
            storage,
            range,
        }
    }
}

#[tokio::main(flavor = "multi_thread", worker_threads = 10)]
async fn main() -> anyhow::Result<()> {
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
                .multiple(true)
                .number_of_values(1)
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
    log::info!("cwd start {}", std::env::current_dir()?.display());

    let (bootstrap_point, client_opts) = ParsedArgs::parse(matches)?;
    let client_opts = client_opts.build()?;
    let clients = connect(client_opts).await?;

    if let Some(height) = bootstrap_point {
        let clients = bootstrap(height, clients).await?;
        drive_into_infinity(clients).await;
    } else {
        drive_into_infinity(clients).await;
    }

    // fortunately, horizon is unreachable
    Ok(())
}

async fn connect(client_opts: Vec<ClientOpts>) -> anyhow::Result<Vec<Client<LedgerStorage>>> {
    let block_storage = solana_storage_bigtable::LedgerStorage::new(false, None, None).await?;
    let servers: Vec<_> = client_opts
        .into_iter()
        .map(|client_opts| async {
            let client_result = Client::connect(
                client_opts.state_rpc_address,
                client_opts.range,
                client_opts.storage,
                block_storage.clone(),
            )
            .await;

            match client_result {
                Err(e) => Err(e)?,

                Ok(client) => Ok::<Client<LedgerStorage>, anyhow::Error>(client),
            }
        })
        .collect();

    let connected = join_all(servers).await;
    let clients: Vec<Client<LedgerStorage>> = connected
        .into_iter()
        .filter(|res| {
            if let Err(ref e) = res {
                log::error!("couldn't connect {:?}", e);
            }
            res.is_ok()
        })
        .map(|res| res.unwrap())
        .collect();
    Ok(clients)
}

async fn bootstrap(
    height: BlockNum,
    clients: Vec<Client<LedgerStorage>>,
) -> anyhow::Result<Vec<Client<LedgerStorage>>> {
    let fetch_ranges: Vec<_> = clients
        .into_iter()
        .map(|mut client| async move {
            let block_range = client.get_block_range().await;
            (block_range, client)
        })
        .collect();

    let fetched_ranges = join_all(fetch_ranges).await;
    let (ranges, mut clients): (Vec<_>, Vec<_>) = fetched_ranges.into_iter().unzip();

    let client_indices: Vec<_> = ranges
        .into_iter()
        .enumerate()
        .filter(|(_index, result)| {
            if let Ok(range) = result.clone() {
                (range.start..range.end).contains(&height)
            } else {
                false
            }
        })
        .collect();
    let first = client_indices
        .first()
        .expect("no server contains bootstrap point")
        .0;
    log::info!("client_indices.first() {}", first);
    let hero_client = &mut clients[0];
    hero_client.bootstrap_state(height).await?;
    Ok(clients)
}

async fn drive_into_infinity(clients: Vec<Client<LedgerStorage>>) {
    let extend_range_routines: Vec<_> = clients
        .into_iter()
        .map(|mut client| async move {
            client.extend_range_routine().await;
        })
        .collect();

    join_all(extend_range_routines).await;
}
