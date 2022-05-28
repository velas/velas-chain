pub mod extensions;
pub mod routines;
pub mod timestamp;

use clap::{Parser, Subcommand};
use solana_storage_bigtable::LedgerStorage;

#[derive(Parser)]
#[clap(author, version, long_about = None)]
#[clap(name = "EVM Block Recovery")]
#[clap(about = "Tool used for restoring EVM blocks.")]
struct Cli {
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Finds missing ranges of EVM blocks
    Find {
        /// Starting EVM Block number
        #[clap(long, value_name = "NUM")]
        start: u64,

        /// Limit of blocks to search
        #[clap(long, value_name = "NUM")]
        limit: usize,
    },

    /// Restores EVM subchain
    RestoreChain {
        /// First missing EVM Block
        #[clap(short = 'f', long = "first-block", value_name = "NUM")]
        first: u64,

        /// Last missing EVM Block
        #[clap(short = 'l', long = "last-block", value_name = "NUM")]
        last: u64,

        /// RPC address of node used for requesting restored EVM Header
        #[clap(long, value_name = "URL")]
        rpc_address: String,

        /// Write restored blocks to Ledger Storage
        #[clap(short, long)]
        modify_ledger: bool,

        /// Continue restoring after tx simulation failures
        #[clap(short = 'r', long)]
        force_resume: bool,

        /// Writes restored EVM Blocks as JSON file to directory if set
        #[clap(short, long, value_name = "DIR")]
        output_dir: Option<String>,
    },

    /// Checks contents of Native Block
    CheckNative {
        /// Native Block number
        #[clap(short = 'b', long = "native-block", value_name = "NUM")]
        block: u64,
    },
    CheckEvm {
        #[clap(short = 'b', long = "evm-block", value_name = "NUM")]
        block: u64,
    },
    /// Uploads blocks to bigtable from .json file
    Upload {
        /// Path to file with JSON collection of EVM blocks
        #[clap(short, long, value_name = ".json")]
        collection: String,
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
        Commands::RestoreChain {
            first,
            last,
            rpc_address,
            modify_ledger,
            force_resume,
            output_dir,
        } => {
            routines::restore_chain(
                &ledger,
                routines::find::BlockRange::new(first, last),
                rpc_address,
                modify_ledger,
                force_resume,
                output_dir,
            )
            .await?
        }
        Commands::CheckNative { block } => routines::check_native(&ledger, block).await?,
        Commands::CheckEvm { block } => routines::check_evm(&ledger, block).await.unwrap(),
        Commands::Upload { collection } => routines::upload(&ledger, collection).await.unwrap(),
    }

    Ok(())
}
