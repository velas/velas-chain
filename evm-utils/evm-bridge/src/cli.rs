use {
    clap::ValueHint,
    log::{info, warn},
    primitive_types::U256,
    solana_cli_config::Config,
    solana_evm_loader_program::scope::evm::LAMPORTS_TO_GWEI_PRICE,
    solana_sdk::fee_calculator::DEFAULT_TARGET_LAMPORTS_PER_SIGNATURE,
    std::{net::SocketAddr, time::Duration},
};

#[derive(clap::Parser, Debug)]
pub struct BridgeCli {
    /// Path to Velas Native keypair file
    #[arg(default_value_t = default_native_keypair(), value_name="FILE_PATH", value_hint=ValueHint::FilePath)]
    pub keyfile: String,

    /// RPC URL of Velas Native node
    #[arg(default_value = "http://127.0.0.1:8899", value_name="URL", value_hint=ValueHint::Url)]
    pub rpc_address: String,

    /// RPC endpoint of Velas EVM bridge
    #[arg(default_value = "127.0.0.1:8545", value_name = "SOCK_ADDR")]
    pub binding_address: SocketAddr,

    /// EVM Chain ID
    #[arg(default_value_t = 0xdead, value_name = "CHAIN_ID")] // 0xdead == 57005
    pub evm_chain_id: u64,

    /// Reject too cheap transactions
    #[arg(long, default_value_t = default_min_gas_price(), value_parser = parse_min_gas_price, value_name = "GWEI")]
    pub min_gas_price: U256,

    /// Print full details in RPC error message, and ignore original message
    #[arg(long)]
    pub verbose_errors: bool,

    /// Use borsh binary encoding instead of bincode
    #[arg(long)]
    pub borsh_encoding: bool,

    /// Disable EVM simulation before processing transaction
    #[arg(long)]
    pub no_simulate: bool,

    /// Maximum number of blocks to return in eth_getLogs RPC call
    #[arg(long, value_name = "NUM", default_value_t = 500)]
    pub max_logs_block_count: u64,

    /// Jaeger distributed tracing collector URL
    #[arg(long, short, value_name = "URL", value_hint = ValueHint::Url)]
    pub jaeger_collector_url: Option<String>,

    /// Allow only whitelisted transactions described in provided file
    #[arg(long, value_name = "FILE_PATH", value_hint = ValueHint::FilePath)]
    pub whitelist_path: Option<String>,

    /// Maximum number of seconds to process batched jsonrpc requests
    #[arg(long, value_parser = parse_seconds_duration, value_name = "SECONDS")]
    pub rpc_max_batch_time: Option<Duration>,
}

fn default_native_keypair() -> String {
    Config::default().keypair_path
}

fn default_min_gas_price() -> U256 {
    //TODO: Add gas logic
    // 21000 is smallest call in evm
    ceil_to_gwei((21000 * LAMPORTS_TO_GWEI_PRICE / DEFAULT_TARGET_LAMPORTS_PER_SIGNATURE).into())
}

fn parse_min_gas_price(arg: &str) -> Result<U256, String> {
    let gas_price = U256::from_dec_str(arg).unwrap_or_else(|e| {
        warn!("Unable to parse `--min-gas-price={arg}` option: {e}");
        default_min_gas_price()
    });

    let gas_price = ceil_to_gwei(gas_price);

    info!("--min-gas-price is set to {gas_price}");

    Ok(gas_price)
}

// for metamask
fn ceil_to_gwei(mut gas_price: U256) -> U256 {
    let gwei: U256 = 1_000_000_000.into();

    gas_price += gwei - 1;
    gas_price - gas_price % gwei
}

fn parse_seconds_duration(arg: &str) -> Result<Duration, String> {
    let seconds: u64 = arg.parse().map_err(|e: core::num::ParseIntError| {
        warn!("Unable to parse `--rpc-max-batch-time={arg}` option: {e}");
        e.to_string()
    })?;

    Ok(Duration::from_secs(seconds))
}
