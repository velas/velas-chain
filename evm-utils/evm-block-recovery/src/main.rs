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

    /// Overrides "GOOGLE_APPLICATION_CREDENTIALS" environment variable value with provided creds file
    #[clap(long, value_name = "FILE_PATH")]
    creds: Option<String>,

    /// Bigtable Instance
    #[clap(long, value_name = "STRING", default_value = "solana-ledger")]
    instance: String,
}

#[derive(Subcommand)]
enum Commands {
    /// Finds missing ranges of EVM Blocks
    FindEvm {
        /// Starting EVM Block number
        #[clap(long, value_name = "NUM")]
        start: u64,

        /// Limit of EVM Blocks to search
        #[clap(long, value_name = "NUM")]
        limit: usize,
    },

    /// Finds missing ranges of Native Blocks
    FindNative {
        /// Starting Native Block number
        #[clap(long, value_name = "NUM")]
        start: u64,

        /// Limit of Native Blocks to search
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

        /// RPC address of archive node used for restoring EVM Header
        #[clap(long, value_name = "URL")]
        archive_url: String,

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
        /// EVM Block number
        #[clap(short = 'b', long, value_name = "NUM")]
        block_number: u64,
    },

    /// Uploads blocks to Bigtable from .json file
    Upload {
        /// Path to file with JSON collection of EVM blocks
        #[clap(short, long, value_name = "FILE_PATH")]
        collection: String,
    },

    /// Copies sequence of EVM Blocks from Source to Destination Ledger
    RepeatEvm {
        /// First EVM Block of the sequence to copy from Src to Dst
        #[clap(short, long, value_name = "NUM")]
        block_number: u64,

        /// EVM Block sequence length
        #[clap(short, long, value_name = "NUM", default_value = "1")]
        limit: u64,

        /// Google credentials JSON filepath of the Source Ledger
        #[clap(long, value_name = "FILE_PATH")]
        src_creds: String,

        /// Source Ledger Instance
        #[clap(long, value_name = "STRING", default_value = "solana-ledger")]
        src_instance: String,

        /// Google credentials JSON filepath of the Destination Ledger
        #[clap(long, value_name = "FILE_PATH")]
        dst_creds: String,

        /// Destination Ledger Instance
        #[clap(long, value_name = "STRING", default_value = "solana-ledger")]
        dst_instance: String,
    },

    /// Copies sequence of Native Blocks from Source to Destination Ledger
    RepeatNative {
        /// First Native Block of the sequence to copy from Src to Dst
        #[clap(short, long, value_name = "NUM")]
        block_number: u64,

        /// Native Block sequence length
        #[clap(short, long, value_name = "NUM", default_value = "1")]
        limit: u64,

        /// Google credentials JSON filepath of the Source Ledger
        #[clap(long, value_name = "FILE_PATH")]
        src_creds: String,

        /// Source Ledger Instance
        #[clap(long, value_name = "STRING", default_value = "solana-ledger")]
        src_instance: String,

        /// Google credentials JSON filepath of the Destination Ledger
        #[clap(long, value_name = "FILE_PATH")]
        dst_creds: String,

        /// Destination Ledger Instance
        #[clap(long, value_name = "STRING", default_value = "solana-ledger")]
        dst_instance: String,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let dotenv = dotenv::dotenv();

    match std::env::var("RUST_LOG") {
        Ok(value) => {
            env_logger::init();
            log::info!(r#"RUST_LOG is set to "{value}""#);
        }
        Err(_err) => {
            std::env::set_var("RUST_LOG", "info");
            env_logger::init();
            log::warn!(r#"Environment variable "RUST_LOG" not found."#);
        }
    }

    match dotenv {
        Ok(path) => {
            log::info!(r#""{}" successfully loaded"#, path.display())
        }
        Err(e) => {
            log::warn!(r#"".env" file not found: {e:?}""#)
        }
    }

    let cli = Cli::parse();
    match cli.command {
        Commands::FindEvm { start, limit } => {
            routines::find_evm(
                ledger::with_params(cli.creds, cli.instance).await?,
                start,
                limit,
            )
            .await
        }
        Commands::FindNative { start, limit } => {
            routines::find_native(
                ledger::with_params(cli.creds, cli.instance).await?,
                start,
                limit,
            )
            .await
        }
        Commands::RestoreChain {
            first,
            last,
            archive_url: rpc_address,
            modify_ledger,
            force_resume,
            output_dir,
        } => {
            routines::restore_chain(
                ledger::with_params(cli.creds, cli.instance).await?,
                routines::find::BlockRange::new(first, last),
                rpc_address,
                modify_ledger,
                force_resume,
                output_dir,
            )
            .await
        }
        Commands::CheckNative { block_number } => {
            routines::check_native(
                ledger::with_params(cli.creds, cli.instance).await?,
                block_number,
            )
            .await
        }
        Commands::CheckEvm { block_number } => {
            routines::check_evm(
                ledger::with_params(cli.creds, cli.instance).await?,
                block_number,
            )
            .await
        }
        Commands::Upload { collection } => {
            routines::upload(
                ledger::with_params(cli.creds, cli.instance).await?,
                collection,
            )
            .await
        }
        Commands::RepeatEvm {
            block_number,
            limit,
            src_creds,
            src_instance,
            dst_creds,
            dst_instance,
        } => {
            routines::repeat_evm(
                block_number,
                limit,
                ledger::with_params(Some(src_creds), src_instance).await?,
                ledger::with_params(Some(dst_creds), dst_instance).await?,
            )
            .await
        }
        Commands::RepeatNative {
            block_number,
            limit,
            src_creds,
            src_instance,
            dst_creds,
            dst_instance,
        } => {
            routines::repeat_native(
                block_number,
                limit,
                ledger::with_params(Some(src_creds), src_instance).await?,
                ledger::with_params(Some(dst_creds), dst_instance).await?,
            )
            .await
        }
    }
}
