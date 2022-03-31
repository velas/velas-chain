pub mod data;
pub mod routines;

use clap::{Parser, Subcommand};
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
    /// Finds missing ranges of EVM-blocks
    Find {
        /// Starting EVM Block number
        #[clap(long)]
        start: u64,
        /// Limit of blocks to search
        #[clap(long)]
        limit: u64
    },
    /// Restores metadata of specified EVM Block
    Restore {
        /// EVM Block number
        #[clap(short = 'b', long = "evm-block")]
        block: u64
    },

    /// Checks consistency of EVM block and related native block
    Check {
        /// EVM Block number
        #[clap(short = 'b', long = "evm-block")]
        block: u64
    }
}


#[tokio::main]
async fn main() {
    env_logger::init();
    dotenv::dotenv().expect("`.env` file expected");

    let ledger = LedgerStorage::new(false, None)
        .await
        .expect("Failed to connect to storage");

    let cli = Cli::parse();
    match cli.command {
        Commands::Find { start, limit } => todo!(),
        Commands::Restore { block } => todo!(),
        Commands::Check { block } => todo!(),
    }
}
