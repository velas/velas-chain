pub mod extensions;
pub mod ledger;
pub mod routines;
pub mod timestamp;

use clap::{Parser, Subcommand};

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

    /// Checks content of Native Block
    CheckNative {
        /// Native Block number
        #[clap(short = 'b', long, value_name = "NUM")]
        block_number: u64,
    },

    /// Checks content of Evm Block
    CheckEvm {
        #[clap(short = 'b', long, value_name = "NUM")]
        block_number: u64,
    },

    /// Uploads blocks to Bigtable from .json file
    Upload {
        /// Path to file with JSON collection of EVM blocks
        #[clap(short, long, value_name = "FILE_PATH")]
        collection: String,
    },

    /// Copies sequence of blocks from Source Ledger to Destination Ledger
    RepeatEvm {
        /// First EVM block of the sequence to copy from src to dst
        #[clap(short, long, value_name = "NUM")]
        block_number: u64,

        /// EVM block sequence length
        #[clap(short, long, value_name = "NUM", default_value = "1")]
        limit: u64,

        /// Google credentials JSON filepath of the Source Ledger
        #[clap(long, value_name = "FILE_PATH")]
        src_creds: String,

        /// Source Ledger Instance
        #[clap(long, default_value = "solana-ledger")]
        src_instance: String,

        /// Google credentials JSON filepath of the Destination Ledger
        #[clap(long, value_name = "FILE_PATH")]
        dst_creds: String,

        /// Destination Ledger Instance
        #[clap(long, default_value = "solana-ledger")]
        dst_instance: String,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenv::dotenv().expect("`.env` file expected");
    env_logger::init();

    let cli = Cli::parse();
    match cli.command {
        Commands::Find { start, limit } => {
            routines::find(ledger::default().await?, start, limit).await?
        }
        Commands::RestoreChain {
            first,
            last,
            rpc_address,
            modify_ledger,
            force_resume,
            output_dir,
        } => {
            routines::restore_chain(
                ledger::default().await?,
                routines::find::BlockRange::new(first, last),
                rpc_address,
                modify_ledger,
                force_resume,
                output_dir,
            )
            .await?
        }
        Commands::CheckNative { block_number } => {
            routines::check_native(ledger::default().await?, block_number).await?
        }
        Commands::CheckEvm { block_number } => {
            routines::check_evm(ledger::default().await?, block_number).await?
        }
        Commands::Upload { collection } => {
            routines::upload(ledger::default().await?, collection).await?
        }
        Commands::RepeatEvm {
            block_number,
            limit,
            src_creds,
            src_instance,
            dst_creds,
            dst_instance,
        } => {
            routines::repeat(
                block_number,
                limit,
                ledger::with_params(src_creds, src_instance).await?,
                ledger::with_params(dst_creds, dst_instance).await?,
            )
            .await?
        }
    }

    Ok(())
}
