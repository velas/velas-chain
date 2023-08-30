use {evm_state::BlockNum, solana_storage_bigtable::DEFAULT_INSTANCE_NAME, std::path::PathBuf};

const DEFAULT_BIGTABLE_LIMIT: &str = "150000";

#[derive(clap::Parser)]
pub struct Cli {
    #[clap(subcommand)]
    pub subcommand: Command,

    /// Optionally override "GOOGLE_APPLICATION_CREDENTIALS" environment variable value
    #[clap(long, value_name = "FILE_PATH", value_hint = clap::ValueHint::FilePath)]
    pub creds: Option<String>,

    /// Bigtable Instance
    #[clap(long, value_name = "STRING", default_value = DEFAULT_INSTANCE_NAME)]
    pub instance: String,

    /// Enables additional structured output to stdout for use in embedded environment
    #[clap(long, value_name = "BOOL")]
    pub embed: bool,
}

#[derive(clap::Subcommand)]
pub enum Command {
    /// Finds missing ranges of EVM Blocks
    FindEvm(FindEvmArgs),

    /// Finds missing ranges of Native Blocks
    FindNative(FindNativeArgs),

    /// Restores EVM subchain
    RestoreChain(RestoreChainArgs),

    /// Checks content of Native Block
    CheckNative(CheckNativeArgs),

    /// Checks content of Evm Block
    CheckEvm(CheckEvmArgs),

    /// Compares difference of Native Block sets
    CompareNative(CompareNativeArgs),

    /// Uploads blocks to Bigtable from .json file
    Upload(UploadArgs),

    /// Copies sequence of EVM Blocks from Source to Destination Ledger
    RepeatEvm(RepeatEvmArgs),

    /// Copies sequence of Native Blocks from Source to Destination Ledger
    RepeatNative(RepeatNativeArgs),

    ScanEvmStateRoots(ScanEvmStateRootsArgs),

    ScratchPad,

    /// Generetes Shell Completions for this Utility
    Completion(CompletionArgs),
}

#[derive(clap::Args)]
pub struct FindEvmArgs {
    /// Starting EVM Block number
    #[clap(long, value_name = "NUM")]
    pub start_block: u64,

    /// Limit of EVM Blocks to search
    #[clap(long, value_name = "NUM")]
    pub end_block: Option<u64>,

    #[clap(long, value_name = "NUM")]
    /// Alternative to `end_block` if it's not set
    pub limit: Option<u64>,

    /// Maximum amount of blocks in chunk per one fetch
    #[clap(long, value_name = "NUM", default_value = DEFAULT_BIGTABLE_LIMIT)]
    pub bigtable_limit: usize,
}

#[derive(clap::Args)]
pub struct FindNativeArgs {
    /// Starting Native Block number
    #[clap(long, value_name = "NUM")]
    pub start_block: u64,

    /// Last Native Block to search
    #[clap(long, value_name = "NUM")]
    pub end_block: Option<u64>,

    #[clap(long, value_name = "NUM")]
    /// Alternative to `end_block` if it's not set
    pub limit: Option<u64>,

    /// Maximum amount of blocks in chunk per one fetch
    #[clap(long, value_name = "NUM", default_value = DEFAULT_BIGTABLE_LIMIT)]
    pub bigtable_limit: usize,
}

#[derive(clap::Args)]
pub struct RestoreChainArgs {
    /// First missing EVM Block
    #[clap(long, value_name = "NUM")]
    pub first_block: u64,

    /// Last missing EVM Block
    #[clap(long, value_name = "NUM")]
    pub last_block: u64,

    /// RPC address of archive node used for restoring EVM Header
    #[clap(long, value_name = "URL", value_hint = clap::ValueHint::Url)]
    pub archive_url: String,

    /// Write restored blocks to Ledger Storage
    #[clap(long)]
    pub modify_ledger: bool,

    /// Continue restoring after tx simulation failures
    #[clap(long)]
    pub force_resume: bool,

    /// Path to JSON file containing missing parts of EVM Blocks needed for restoration
    #[clap(long, value_name = "FILE_PATH", default_value = "./timestamps/blocks.json", value_hint = clap::ValueHint::FilePath)]
    pub timestamps: String,

    /// Writes restored EVM Blocks as JSON file to directory if set
    #[clap(long, value_name = "DIR", value_hint = clap::ValueHint::DirPath)]
    pub output_dir: Option<String>,

    /// Offset in hours to change timestamp string like "2022-08-16T02:02:04.000Z"
    /// This is useful when timestamp storage use Z as reference to local timestamp instead of UTC.
    #[clap(long, value_name = "OFFSET_HOURS")]
    pub hrs_offset: Option<i64>,
}

#[derive(clap::Args)]
pub struct CheckNativeArgs {
    /// Native Block number
    #[clap(short, long, value_name = "NUM")]
    pub slot: u64,
}

#[derive(clap::Args)]
pub struct CheckEvmArgs {
    /// EVM Block number
    #[clap(short = 'b', long, value_name = "NUM")]
    pub block_number: u64,
}

#[derive(clap::Args)]
pub struct CompareNativeArgs {
    /// First Native Slot
    #[clap(long, value_name = "NUM")]
    pub start_slot: u64,

    /// Limit of Native Blocks to search
    #[clap(long, value_name = "NUM")]
    pub limit: usize,

    /// Google credentials JSON filepath of the "Credible Ledger"
    #[clap(long, value_name = "FILE_PATH", value_hint = clap::ValueHint::FilePath)]
    pub credible_ledger_creds: String,

    /// "Credible Ledger" Instance
    #[clap(long, value_name = "STRING", default_value = DEFAULT_INSTANCE_NAME)]
    pub credible_ledger_instance: String,

    /// Google credentials JSON filepath of the "Deceptive Ledger"
    #[clap(long, value_name = "FILE_PATH", value_hint = clap::ValueHint::FilePath)]
    pub dubious_ledger_creds: String,

    /// "Deceptive Ledger" Instance
    #[clap(long, value_name = "STRING", default_value = DEFAULT_INSTANCE_NAME)]
    pub dubious_ledger_instance: String,
}

#[derive(clap::Args)]
pub struct UploadArgs {
    /// Path to file with JSON collection of EVM blocks
    #[clap(short, long, value_name = "FILE_PATH", value_hint = clap::ValueHint::FilePath)]
    pub collection: String,
}

#[derive(clap::Args)]
pub struct RepeatEvmArgs {
    /// First EVM Block of the sequence to copy from Src to Dst
    #[clap(short, long, value_name = "NUM")]
    pub block_number: u64,

    /// EVM Block sequence length
    #[clap(short, long, value_name = "NUM", default_value = "1")]
    pub limit: u64,

    /// Google credentials JSON filepath of the Source Ledger
    #[clap(long, value_name = "FILE_PATH", value_hint = clap::ValueHint::FilePath)]
    pub src_creds: String,

    /// Source Ledger Instance
    #[clap(long, value_name = "STRING", default_value = DEFAULT_INSTANCE_NAME)]
    pub src_instance: String,

    /// Google credentials JSON filepath of the Destination Ledger
    #[clap(long, value_name = "FILE_PATH", value_hint = clap::ValueHint::FilePath)]
    pub dst_creds: String,

    /// Destination Ledger Instance
    #[clap(long, value_name = "STRING", default_value = DEFAULT_INSTANCE_NAME)]
    pub dst_instance: String,
}

#[derive(clap::Args)]
pub struct RepeatNativeArgs {
    /// First Native Block of the sequence to copy from Src to Dst
    #[clap(short, long, value_name = "NUM")]
    pub start_slot: u64,

    /// Native Block sequence length
    #[clap(short, long, value_name = "NUM")]
    pub end_slot: u64,

    /// Google credentials JSON filepath of the Source Ledger
    #[clap(long, value_name = "FILE_PATH", value_hint = clap::ValueHint::FilePath)]
    pub src_creds: String,

    /// Source Ledger Instance
    #[clap(long, value_name = "STRING", default_value = DEFAULT_INSTANCE_NAME)]
    pub src_instance: String,

    /// Google credentials JSON filepath of the Destination Ledger
    #[clap(long, value_name = "FILE_PATH", value_hint = clap::ValueHint::FilePath)]
    pub dst_creds: String,

    /// Destination Ledger Instance
    #[clap(long, value_name = "STRING", default_value = DEFAULT_INSTANCE_NAME)]
    pub dst_instance: String,
}

#[derive(clap::Args)]
pub struct ScanEvmStateRootsArgs {
    #[arg(short, long)]
    pub start: BlockNum,

    #[arg(short, long)]
    pub end_exclusive: BlockNum,

    #[arg(short, long, value_name = "DIR")]
    pub evm_state_path: PathBuf,

    #[arg(short, long)]
    pub workers: u16,

    #[arg(short, long)]
    pub secondary: bool,

    #[arg(short, long)]
    pub gc: bool,

    #[arg(short, long, value_name = "FILE")]
    pub rangemap_json: PathBuf,
}

#[derive(clap::Args)]
pub struct CompletionArgs {
    /// Which shell completions to generate
    #[arg(value_enum)]
    #[clap(long, value_name = "STRING")]
    pub shell: clap_complete::Shell,
}
