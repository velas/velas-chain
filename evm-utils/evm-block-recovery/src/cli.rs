const DEFAULT_INSTANCE: &str = "solana-ledger";
const DEFAULT_BIGTABLE_LIMIT: &str = "150000";

#[derive(clap::Parser)]
#[clap(author, version, long_about = None)]
#[clap(name = "EVM Block Recovery")]
#[clap(about = "Tool used for restoring EVM blocks.")]
pub struct Cli {
    #[clap(subcommand)]
    pub command: Commands,

    /// Optionally override "GOOGLE_APPLICATION_CREDENTIALS" environment variable value
    #[clap(long, value_name = "FILE_PATH", value_hint = clap::ValueHint::FilePath)]
    pub creds: Option<String>,

    /// Bigtable Instance
    #[clap(long, value_name = "STRING", default_value = DEFAULT_INSTANCE)]
    pub instance: String,
}

#[derive(clap::Subcommand)]
pub enum Commands {
    /// Finds missing ranges of EVM Blocks
    FindEvm {
        /// Starting EVM Block number
        #[clap(long, value_name = "NUM")]
        start_block: u64,

        /// Limit of EVM Blocks to search
        #[clap(long, value_name = "NUM")]
        end_block: u64,

        /// Bigtable limit TODO: implement bitgable limit for evm part
        #[clap(long, value_name = "NUM", default_value = DEFAULT_BIGTABLE_LIMIT)]
        bigtable_limit: usize,
    },

    /// Finds missing ranges of Native Blocks
    FindNative {
        /// Starting Native Block number
        #[clap(long, value_name = "NUM")]
        start_block: u64,

        /// Last Native Block to search
        #[clap(long, value_name = "NUM")]
        end_block: u64,

        /// Bigtable limit
        #[clap(long, value_name = "NUM", default_value = DEFAULT_BIGTABLE_LIMIT)]
        bigtable_limit: usize,
    },

    /// Restores EVM subchain
    RestoreChain {
        /// First missing EVM Block
        #[clap(long, value_name = "NUM")]
        first_block: u64,

        /// Last missing EVM Block
        #[clap(long, value_name = "NUM")]
        last_block: u64,

        /// RPC address of archive node used for restoring EVM Header
        #[clap(long, value_name = "URL", value_hint = clap::ValueHint::Url)]
        archive_url: String,

        /// Write restored blocks to Ledger Storage
        #[clap(long)]
        modify_ledger: bool,

        /// Continue restoring after tx simulation failures
        #[clap(long)]
        force_resume: bool,

        /// TODO: explain JSON schema and reason why this param is required during blocks restore
        #[clap(long, value_name = "FILE_PATH", default_value = "./timestamps/blocks.json", value_hint = clap::ValueHint::FilePath)]
        timestamps: String,

        /// Writes restored EVM Blocks as JSON file to directory if set
        #[clap(long, value_name = "DIR", value_hint = clap::ValueHint::DirPath)]
        output_dir: Option<String>,
    },

    /// Checks content of Native Block
    CheckNative {
        /// Native Block number
        #[clap(short, long, value_name = "NUM")]
        slot: u64,
    },

    /// Checks content of Evm Block
    CheckEvm {
        /// EVM Block number
        #[clap(short = 'b', long, value_name = "NUM")]
        block_number: u64,
    },

    /// Compares difference of Native Block sets
    CompareNative {
        /// First Native Slot
        #[clap(long, value_name = "NUM")]
        start_slot: u64,

        /// Limit of Native Blocks to search
        #[clap(long, value_name = "NUM")]
        limit: usize,

        /// Google credentials JSON filepath of the "Credible Ledger"
        #[clap(long, value_name = "FILE_PATH", value_hint = clap::ValueHint::FilePath)]
        credible_ledger_creds: String,

        /// "Credible Ledger" Instance
        #[clap(long, value_name = "STRING", default_value = DEFAULT_INSTANCE)]
        credible_ledger_instance: String,

        /// Google credentials JSON filepath of the "Deceptive Ledger"
        #[clap(long, value_name = "FILE_PATH", value_hint = clap::ValueHint::FilePath)]
        dubious_ledger_creds: String,

        /// "Deceptive Ledger" Instance
        #[clap(long, value_name = "STRING", default_value = DEFAULT_INSTANCE)]
        dubious_ledger_instance: String,
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
        #[clap(long, value_name = "STRING", default_value = DEFAULT_INSTANCE)]
        src_instance: String,

        /// Google credentials JSON filepath of the Destination Ledger
        #[clap(long, value_name = "FILE_PATH", value_hint = clap::ValueHint::FilePath)]
        dst_creds: String,

        /// Destination Ledger Instance
        #[clap(long, value_name = "STRING", default_value = DEFAULT_INSTANCE)]
        dst_instance: String,
    },

    /// Copies sequence of Native Blocks from Source to Destination Ledger
    RepeatNative {
        /// First Native Block of the sequence to copy from Src to Dst
        #[clap(short, long, value_name = "NUM")]
        start_slot: u64,

        /// Native Block sequence length
        #[clap(short, long, value_name = "NUM")]
        end_slot: u64,

        /// Google credentials JSON filepath of the Source Ledger
        #[clap(long, value_name = "FILE_PATH", value_hint = clap::ValueHint::FilePath)]
        src_creds: String,

        /// Source Ledger Instance
        #[clap(long, value_name = "STRING", default_value = DEFAULT_INSTANCE)]
        src_instance: String,

        /// Google credentials JSON filepath of the Destination Ledger
        #[clap(long, value_name = "FILE_PATH", value_hint = clap::ValueHint::FilePath)]
        dst_creds: String,

        /// Destination Ledger Instance
        #[clap(long, value_name = "STRING", default_value = DEFAULT_INSTANCE)]
        dst_instance: String,
    },
}
