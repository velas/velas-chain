use std::net::{AddrParseError, SocketAddr};
use std::path::PathBuf;
use std::str::FromStr;

use solana_replica_lib::triedb::{client::Client, range::MasterRange};

use clap::{crate_description, crate_name, App, AppSettings, Arg, ArgMatches};
use evm_state::Storage;
use futures::future::join_all;
#[derive(Debug)]
struct ParsedArgs {
    state_rpc_addresses: Vec<String>,
    evm_state: PathBuf,
    range_file: String,
}

impl ParsedArgs {
    fn parse(matches: ArgMatches) -> Result<Self, Box<(dyn std::error::Error + 'static)>> {
        let state_rpc_addresses: Vec<String> = matches
            .values_of("state_rpc_address")
            .unwrap()
            .map(|str| str.to_string())
            .collect();

        let secure_flag = matches.is_present("tls");
        let secure_flag = if secure_flag { "s" } else { "" };

        let result: Result<Vec<String>, AddrParseError> = state_rpc_addresses
            .into_iter()
            .map(|address| {
                SocketAddr::from_str(&address)?;

                Ok(format!("http{}://{}", secure_flag, address))
            })
            .collect();

        let evm_state = PathBuf::from(matches.value_of("evm_state").unwrap());
        let range_file = matches.value_of("range_file").unwrap().to_string();
        Ok(Self {
            state_rpc_addresses: result?,
            evm_state,
            range_file,
        })
    }
    fn build(self) -> Result<Vec<ClientOpts>, Box<(dyn std::error::Error + 'static)>> {
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
async fn main() -> Result<(), Box<(dyn std::error::Error + 'static)>> {
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
        .get_matches();

    let _ = env_logger::Builder::from_default_env().try_init();
    log::info!("cwd start {}", std::env::current_dir()?.display());

    let client_opts = ParsedArgs::parse(matches)?.build()?;


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
                Err(e) => {
                    log::error!("couldn't connect {:?}", e);
                    Err(e)?
                }

                Ok(mut client) => {
                    client.server_routine().await;
                    Ok::<(), anyhow::Error>(())
                }
            }
        })
        .collect();

    join_all(servers).await;

    // fortunately, horizon is unreachable
    Ok(())
}
