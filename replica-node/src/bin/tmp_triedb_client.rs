use evm_state::H256;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;

use solana_replica_lib::triedb::client::{db_handles, Client};

use clap::{crate_description, crate_name, App, AppSettings, Arg, ArgMatches};
use evm_state::Storage;
use solana_replica_lib::triedb::DbCounter;

#[derive(Debug)]
struct ParsedArgs {
    state_rpc_address: String,
    evm_state: PathBuf,
}

impl ParsedArgs {
    fn build(self) -> Result<ClientOpts, Box<(dyn std::error::Error + 'static)>> {
        log::info!("{:?}", self);

        let gc_enabled = true;
        let storage = Storage::open_persistent(self.evm_state, gc_enabled)?;
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
    Ok(ParsedArgs {
        state_rpc_address,
        evm_state,
    })
}

pub struct ClientOpts {
    state_rpc_address: String,
    storage: Storage,
}

impl ClientOpts {
    pub fn new(state_rpc_address: String, storage: Storage) -> Self {
        Self {
            state_rpc_address,
            storage,
        }
    }
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

    let mut client = Client::connect(client_opts.state_rpc_address).await?;
    let (db_handle, collection) = db_handles(&client_opts.storage);

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
    // stattic data from testnet, first hash is empty_trie_hash!()
    let array_hashes = [
        "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
        "0x854c147f221b6ee0d2d4156ed79c98416a6ba9f2d1c57a089484c80ed44e43bc",
        "0xe95926140bd74ade23fe0f97be111b9bb5a4a5ae4e05402fa1b56699fc6fbc25",
        "0x8f7411746b5a5566278a48e12c900d975916c82f4b4599e4109b1fd7e85193f5",
        "0xe3eea950dfa2c3d994a4cb88746005630b81bb624e92e30ea56602d35a6d702c",
        "0x548660695233a203773a3a9d49d28480cd29d9dc934319502d8723a6029f0f93",
        "0xaa3f664876a733b6979c405c941b73907bcb80bd4c81a762276c20189f94e1c2",
        "0x1097f736bb4030b70266e9f3199b8befc645d7742e24c486e573ba29eb121197",
        "0xe10cb3e31af77e58364f62393bc2ee917f987da648b43bd032006907c3af9668",
        "0xd7a652c1690ec5633137275557c4d2c8f1c4b680647f8b7be5fa591736c84b6b",
    ];
    for ind in 0..(array_hashes.len() - 1) {
        let from = H256::from_slice(
            &hexutil::read_hex(array_hashes[ind])
                .map_err(|err| format!("parse hex err {:?}", err))?,
        );

        let to = H256::from_slice(
            &hexutil::read_hex(array_hashes[ind + 1])
                .map_err(|err| format!("parse hex err {:?}", err))?,
        );
        let diff_response = client
            .download_and_apply_diff(&db_handle, &collection, from, to)
            .await;
        log::warn!("is ok {}", diff_response.is_ok());
        match diff_response {
            Err(e) => {
                log::warn!("error: {:?}", e);
            }
            Ok(guard) => {
                log::warn!("persisted root {}", guard.leak_root());
                db_handle.gc_pin_root(to);
                log::warn!("persisted root count after leak {}", db_handle.gc_count(to));
            }
        }
    }

    Ok(())
}
