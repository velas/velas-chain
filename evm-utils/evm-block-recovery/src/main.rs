#![allow(unused)]

pub mod extensions;
pub mod routines;

use clap::{Parser, Subcommand};
use extensions::NativeBlockExt;
use solana_storage_bigtable::LedgerStorage;

#[derive(Parser)]
#[clap(author, version, long_about = None)]
#[clap(name = "EVM Block Recovery")]
#[clap(about = "Tool used for restoring EVM blocks metadata.")]
struct Cli {
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Finds missing ranges of EVM blocks
    Find {
        /// Starting EVM Block number
        #[clap(long)]
        start: u64,

        /// Limit of blocks to search
        #[clap(long)]
        limit: usize,
    },

    /// Restores metadata of specified EVM Block
    Restore {
        /// RPC address of node used for requesting restored EVM header
        #[clap(long)]
        rpc_address: String,

        /// EVM Block number
        #[clap(short = 'b', long = "evm-block")]
        block: u64,

        /// Set this to `true` i
        #[clap(short, long)]
        dry_run: bool,
    },

    /// Checks contents of Native Block
    CheckNative {
        /// Native Block number
        #[clap(short = 'b', long = "native-block")]
        block: u64,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenv::dotenv().expect("`.env` file expected");
    env_logger::init();

    let ledger = LedgerStorage::new(false, None)
        .await
        .expect("Failed to connect to storage");

    let cli = Cli::parse();
    match cli.command {
        Commands::Find { start, limit } => routines::find(&ledger, start, limit).await?,
        Commands::Restore {
            block,
            rpc_address,
            dry_run,
        } => routines::restore(&ledger, rpc_address, block, dry_run).await?,
        Commands::CheckNative { block } => routines::check_native(&ledger, block).await?,
    }

    Ok(())
}
