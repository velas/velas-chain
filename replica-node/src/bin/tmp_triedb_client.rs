use evm_state::{empty_trie_hash, H256};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;

use solana_replica_lib::triedb_replica_client::{Client, ClientOpts};

use clap::{crate_description, crate_name, App, AppSettings, Arg, ArgMatches};
use evm_state::Storage;

#[derive(Debug)]
struct ParsedArgs {
    state_rpc_address: String,
    evm_state: PathBuf,
}

impl ParsedArgs {

    fn build(self) -> Result<ClientOpts, Box<(dyn std::error::Error + 'static)>> {
        log::info!("{:?}", self);

        let storage = Storage::open_persistent(self.evm_state, true)?;
        Ok(ClientOpts::new(self.state_rpc_address, storage))
    }
}


fn parse(
    matches: ArgMatches,
) -> Result<ParsedArgs, Box<(dyn std::error::Error + 'static)>> {

    let state_rpc_address = matches.value_of("state_rpc_address").unwrap();
    SocketAddr::from_str(state_rpc_address)?;

    let secure_flag = matches.is_present("tls");
    let secure_flag = if secure_flag { "s" } else { "" };
    let state_rpc_address = format!("http{}://{}", secure_flag, state_rpc_address);

    let evm_state = PathBuf::from(matches.value_of("evm_state").unwrap());
    Ok(ParsedArgs { state_rpc_address, evm_state })

}

#[tokio::main]
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
        .get_matches();

    let _ = env_logger::Builder::new().parse_filters("info").try_init();
    log::info!("cwd start {}", std::env::current_dir()?.display());

    let client_opts = parse(matches)?.build()?;

    let mut client = Client::connect(client_opts).await?;

    client.ping().await?;

    let raw_bytes_resp = client
        .get_raw_bytes(H256::from_slice(
            &hexutil::read_hex(
                "0xd7a652c1690ec5633137275557c4d2c8f1c4b680647f8b7be5fa591736c84b6b",
            )
            .map_err(|err| format!("parse hex err {:?}", err))?,
        ))
        .await?;

    log::info!("received {}", hexutil::to_hex(&raw_bytes_resp.node));

    let arr_target = [
        [
            empty_trie_hash(),
            H256::from_slice(
                &hexutil::read_hex(
                    "0x854c147f221b6ee0d2d4156ed79c98416a6ba9f2d1c57a089484c80ed44e43bc",
                )
                .map_err(|err| format!("parse hex err {:?}", err))?,
            ),
        ],
        [
            H256::from_slice(
                &hexutil::read_hex(
                    "0x854c147f221b6ee0d2d4156ed79c98416a6ba9f2d1c57a089484c80ed44e43bc",
                )
                .map_err(|err| format!("parse hex err {:?}", err))?,
            ),
            H256::from_slice(
                &hexutil::read_hex(
                    "0xd7a652c1690ec5633137275557c4d2c8f1c4b680647f8b7be5fa591736c84b6b",
                )
                .map_err(|err| format!("parse hex err {:?}", err))?,
            ),
        ],
    ];
    for from_to in arr_target {
        let diff_response = client.get_state_diff(from_to[0], from_to[1]).await?;
        log::info!(
            "changeset received {} -> {}, {}",
            from_to[0],
            from_to[1],
            diff_response.changeset.len()
        );
    }

    Ok(())
}
