mod bridge;
mod bundler;
mod middleware;
mod pool;
mod rpc_client;
mod tx_filter;

use log::*;
use std::fs::File;
use std::future::ready;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
};

use evm_rpc::bridge::BridgeERPC;
use evm_rpc::bundler::{BundlerERPC, UserOperation};
use evm_rpc::chain::ChainERPC;
use evm_rpc::error::{Error, *};
use evm_rpc::general::GeneralERPC;
use evm_rpc::*;
use evm_state::*;
use sha3::{Digest, Keccak256};

use jsonrpc_core::BoxFuture;
use jsonrpc_http_server::jsonrpc_core::*;
use jsonrpc_http_server::*;

use snafu::ResultExt;

use derivative::*;
use solana_evm_loader_program::instructions::FeePayerType;
use solana_evm_loader_program::scope::*;
use solana_sdk::{
    fee_calculator::DEFAULT_TARGET_LAMPORTS_PER_SIGNATURE,
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    signer::Signer,
    signers::Signers,
    system_instruction,
    transaction::TransactionError,
};

use solana_client::{
    client_error::{ClientError, ClientErrorKind},
    rpc_config::*,
    rpc_request::RpcResponseErrorData,
    rpc_response::*,
};

use tracing_attributes::instrument;
use tracing_subscriber::prelude::*;
use tracing_subscriber::{
    filter::{LevelFilter, Targets},
    layer::{Layer, SubscriberExt},
};

use ::tokio;

use bridge::*;
use middleware::ProxyMiddleware;
use pool::{
    worker_cleaner, worker_deploy, worker_signature_checker, EthPool, PooledTransaction,
    SystemClock,
};
use rpc_client::AsyncRpcClient;
use tx_filter::TxFilter;

use crate::bundler::Bundler;
use rlp::Encodable;
use secp256k1::Message;
use solana_rpc::rpc::{BatchId, BatchStateMap};
use std::result::Result as StdResult;

type EvmResult<T> = StdResult<T, evm_rpc::Error>;

#[derive(Debug, structopt::StructOpt)]
struct Args {
    keyfile: Option<String>,
    #[structopt(default_value = "http://127.0.0.1:8899")]
    rpc_address: String,
    #[structopt(default_value = "127.0.0.1:8545")]
    binding_address: SocketAddr,
    #[structopt(default_value = "57005")] // 0xdead
    evm_chain_id: u64,
    #[structopt(long = "min-gas-price")]
    min_gas_price: Option<String>,
    #[structopt(long = "verbose-errors")]
    verbose_errors: bool,
    #[structopt(long = "borsh-encoding")]
    borsh_encoding: bool,
    #[structopt(long = "no-simulate")]
    no_simulate: bool, // parse inverted to keep false default
    /// Maximum number of blocks to return in eth_getLogs rpc.
    #[structopt(long = "max-logs-block-count", default_value = "500")]
    max_logs_blocks: u64,

    #[structopt(long = "jaeger-collector-url", short = "j")]
    jaeger_collector_url: Option<String>,

    #[structopt(long = "whitelist-path")]
    whitelist_path: Option<String>,

    /// Maximum number of seconds to process batched jsonrpc requests.
    #[structopt(long = "rpc-max-batch-time")]
    max_batch_duration: Option<u64>,
}

impl Args {
    fn min_gas_price_or_default(&self) -> U256 {
        let gwei: U256 = 1_000_000_000.into();
        fn min_gas_price() -> U256 {
            //TODO: Add gas logic
            (21000 * solana_evm_loader_program::scope::evm::LAMPORTS_TO_GWEI_PRICE
                / DEFAULT_TARGET_LAMPORTS_PER_SIGNATURE)
                .into() // 21000 is smallest call in evm
        }

        let mut gas_price = match self
            .min_gas_price
            .as_ref()
            .and_then(|gas_price| U256::from_dec_str(gas_price).ok())
        {
            Some(gas_price) => {
                info!(r#"--min-gas-price is set to {}"#, &gas_price);
                gas_price
            }
            None => {
                let default_price = min_gas_price();
                warn!(
                    r#"Value of "--min-gas-price" is not set or unable to parse. Default value is: {}"#,
                    default_price
                );
                default_price
            }
        };
        // ceil to gwei for metamask
        gas_price += gwei - 1;
        gas_price - gas_price % gwei
    }
}

const SECRET_KEY_DUMMY: [u8; 32] = [1; 32];

#[paw::main]
#[tokio::main]
async fn main(args: Args) -> StdResult<(), Box<dyn std::error::Error>> {
    env_logger::init();
    let min_gas_price = args.min_gas_price_or_default();
    let keyfile_path = args
        .keyfile
        .unwrap_or_else(|| solana_cli_config::Config::default().keypair_path);
    let server_path = args.rpc_address;
    let binding_address = args.binding_address;

    if let Some(collector) = args.jaeger_collector_url {
        // init tracer
        let fmt_filter = std::env::var("RUST_LOG")
            .ok()
            .and_then(|rust_log| match rust_log.parse::<Targets>() {
                Ok(targets) => Some(targets),
                Err(e) => {
                    eprintln!("failed to parse `RUST_LOG={:?}`: {}", rust_log, e);
                    None
                }
            })
            .unwrap_or_else(|| Targets::default().with_default(LevelFilter::WARN));

        let tracer = opentelemetry_jaeger::new_pipeline()
            .with_service_name("evm-bridge-tracer")
            .with_collector_endpoint(collector)
            .install_batch(opentelemetry::runtime::Tokio)
            .unwrap();
        let opentelemetry = tracing_opentelemetry::layer().with_tracer(tracer);
        let registry = tracing_subscriber::registry()
            .with(tracing_subscriber::fmt::layer().with_filter(fmt_filter))
            .with(opentelemetry);

        registry.try_init().unwrap();
    }

    let mut whitelist = vec![];
    if let Some(path) = args.whitelist_path.map(PathBuf::from) {
        let file = File::open(path).unwrap();
        whitelist = serde_json::from_reader(file).unwrap();
        info!("Got whitelist: {:?}", whitelist);
    }

    let mut meta = EvmBridge::new(
        args.evm_chain_id,
        &keyfile_path,
        vec![evm::SecretKey::from_slice(&SECRET_KEY_DUMMY).unwrap()],
        server_path,
        args.verbose_errors,
        args.borsh_encoding,
        !args.no_simulate, // invert argument
        args.max_logs_blocks,
        min_gas_price,
    );
    meta.set_whitelist(whitelist);
    if let Some(max_duration) = args.max_batch_duration.map(Duration::from_secs) {
        meta.set_max_batch_duration(max_duration);
    }
    let meta = Arc::new(meta);

    let mut io = MetaIoHandler::with_middleware(ProxyMiddleware {});

    let ether_bridge = BridgeErpcImpl;
    io.extend_with(ether_bridge.to_delegate());
    let ether_bundler = BundlerErpcImpl;
    io.extend_with(ether_bundler.to_delegate());
    let ether_chain = ChainErpcProxy;
    io.extend_with(ether_chain.to_delegate());
    let ether_general = GeneralErpcProxy;
    io.extend_with(ether_general.to_delegate());

    let mempool_worker = worker_deploy(meta.clone());

    let cleaner = worker_cleaner(meta.clone());

    let signature_checker = worker_signature_checker(meta.clone());

    info!("Creating server with: {}", binding_address);
    let meta_clone = meta.clone();
    let server = ServerBuilder::with_meta_extractor(
        io.clone(),
        move |_req: &hyper::Request<hyper::Body>| meta_clone.clone(),
    )
    .cors(DomainsValidation::AllowOnly(vec![
        AccessControlAllowOrigin::Any,
    ]))
    .threads(4)
    .cors_max_age(86400)
    .start_http(&binding_address)
    .expect("Unable to start EVM bridge server");

    let ws_server = {
        let mut websocket_binding = binding_address;
        websocket_binding.set_port(binding_address.port() + 1);
        info!("Creating websocket server: {}", websocket_binding);
        jsonrpc_ws_server::ServerBuilder::with_meta_extractor(io, move |_: &_| meta.clone())
            .start(&websocket_binding)
            .expect("Unable to start EVM bridge server")
    };

    let _cleaner = tokio::task::spawn(cleaner);
    let _signature_checker = tokio::task::spawn(signature_checker);
    let mempool_task = tokio::task::spawn(mempool_worker);
    let servers_waiter = tokio::task::spawn_blocking(|| {
        ws_server.wait().unwrap();
        server.wait();
    });

    // wait for any failure/stops.
    tokio::select! {
        _ = servers_waiter => {
            println!("Server exited.");
        }
        _ = mempool_task => {
            println!("Mempool task exited.");
        }
    };
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::AsyncRpcClient;
    use crate::{BridgeErpcImpl, EthPool, EvmBridge, SystemClock};
    use evm_rpc::{BridgeERPC, Hex};
    use evm_state::Address;
    use secp256k1::SecretKey;
    use solana_sdk::signature::Keypair;
    use std::str::FromStr;
    use std::sync::Arc;

    #[test]
    fn test_eth_sign() {
        let signing_key =
            SecretKey::from_str("c21020a52198632ae7d5c1adaa3f83da2e0c98cf541c54686ddc8d202124c086")
                .unwrap();
        let bridge = Arc::new(EvmBridge::new_for_test(
            111u64,
            vec![signing_key],
            "".to_string(),
        ));

        let rpc = BridgeErpcImpl {};
        let address = Address::from_str("0x141a4802f84bb64c0320917672ef7D92658e964e").unwrap();
        let data = "qwe".as_bytes().to_vec();
        let res = rpc.sign(bridge, Hex(address), data.into()).unwrap();
        assert_eq!(res.to_string(), "0xb734e224f0f92d89825f3f69bf03924d7d2f609159d6ce856d37a58d7fcbc8eb6d224fd73f05217025ed015283133c92888211b238272d87ec48347f05ab42a000");
    }
}
