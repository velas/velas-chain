#[derive(clap::Parser)]
#[clap(author, version, long_about = None)]
#[clap(name = "EVM Block Recovery")]
#[clap(about = "Tool used for restoring EVM blocks.")]
pub struct Cli {
    #[clap(subcommand)]
    pub command: Commands,

    /// Overrides "GOOGLE_APPLICATION_CREDENTIALS" environment variable value with provided creds file
    #[clap(long, value_name = "FILE_PATH", value_hint = clap::ValueHint::FilePath)]
    pub creds: Option<String>,

    /// Bigtable Instance
    #[clap(long, value_name = "STRING", default_value = "solana-ledger")]
    pub instance: String,
}

#[derive(clap::Subcommand)]
pub enum Commands {
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
        #[clap(long, value_name = "URL", value_hint = clap::ValueHint::Url)]
        archive_url: String,

        /// Write restored blocks to Ledger Storage
        #[clap(short, long)]
        modify_ledger: bool,

        /// Continue restoring after tx simulation failures
        #[clap(short = 'r', long)]
        force_resume: bool,

        /// Writes restored EVM Blocks as JSON file to directory if set
        #[clap(short, long, value_name = "DIR", value_hint = clap::ValueHint::DirPath)]
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
        #[clap(short, long, value_name = "FILE_PATH", value_hint = clap::ValueHint::FilePath)]
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
        #[clap(long, value_name = "FILE_PATH", value_hint = clap::ValueHint::FilePath)]
        src_creds: String,

        /// Source Ledger Instance
        #[clap(long, value_name = "STRING", default_value = "solana-ledger")]
        src_instance: String,

        /// Google credentials JSON filepath of the Destination Ledger
        #[clap(long, value_name = "FILE_PATH", value_hint = clap::ValueHint::FilePath)]
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
        #[clap(long, value_name = "FILE_PATH", value_hint = clap::ValueHint::FilePath)]
        src_creds: String,

        /// Source Ledger Instance
        #[clap(long, value_name = "STRING", default_value = "solana-ledger")]
        src_instance: String,

        /// Google credentials JSON filepath of the Destination Ledger
        #[clap(long, value_name = "FILE_PATH", value_hint = clap::ValueHint::FilePath)]
        dst_creds: String,

        /// Destination Ledger Instance
        #[clap(long, value_name = "STRING", default_value = "solana-ledger")]
        dst_instance: String,
    },
}
