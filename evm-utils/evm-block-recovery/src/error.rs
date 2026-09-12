use {
    crate::routines::repeat::BlockMessage, evm_state::Block,
    solana_transaction_status::ConfirmedBlock,
};

pub type RoutineResult = std::result::Result<(), AppError>;

#[allow(clippy::large_enum_variant)]
#[derive(thiserror::Error, Debug)]
pub enum AppError {
    /////////////////////////////////////////////////////////////////////////////////////
    // Unspecified Errors
    /////////////////////////////////////////////////////////////////////////////////////
    #[error("Vector of ID's is too short, try to increase a limit")]
    VectorIsTooShort,

    #[error("Not enough blocks to compare content of two ledgers")]
    NotEnoughBlocksToCompare,

    #[error("Unable to process RPC request")]
    RpcRequest(#[source] solana_client::client_error::ClientError),

    #[error("Native block {block_height:?} contains non-trivial instructions")]
    NonTrivialInstructionsInBlock { block_height: Option<u64> },

    #[error("Cannot find block timestamp, native timestamp usage is forbidden")]
    NoTimestampForBlock,

    #[error("Block restore failed: try `--force-resume` mode")]
    TxSimulatedWithErrors,

    #[error("Native vs EVM Blocks amount mismatch")]
    BlocksAmountMismatch,

    /////////////////////////////////////////////////////////////////////////////////////
    // Errors of invalid arguments
    /////////////////////////////////////////////////////////////////////////////////////
    #[error("`end_block` or `limit` argument must be present")]
    NoLastBlockBoundary,

    #[error("`end_slot` should be greater or equal than `start_slot`")]
    EndSlotLessThanStartSlot,

    /////////////////////////////////////////////////////////////////////////////////////
    // Errors of LedgerStorage
    /////////////////////////////////////////////////////////////////////////////////////
    #[error("Unable to initialize `LedgerStorage` with creds={creds_path:?}, instance={instance}")]
    OpenLedger {
        #[source]
        source: solana_storage_bigtable::Error,
        creds_path: Option<String>,
        instance: String,
    },

    #[error("Unable to get EVM Block")]
    GetEvmBlock(#[source] solana_storage_bigtable::Error),

    #[error("Unable to get EVM Block Header {number}")]
    GetEvmBlockHeader {
        #[source]
        source: solana_storage_bigtable::Error,
        number: u64,
    },

    #[error("Unable to get EVM Confirmed Block IDs: start_block={start_block}, limit={limit}")]
    GetEvmBlockNums {
        #[source]
        source: solana_storage_bigtable::Error,
        start_block: u64,
        limit: usize,
    },

    #[error("Unable to get native block {block}")]
    GetNativeBlock {
        #[source]
        source: solana_storage_bigtable::Error,
        block: u64,
    },

    #[error("Unable to get Native Confirmed Block IDs start_block={start_block}, limit={limit}")]
    GetNativeBlocks {
        #[source]
        source: solana_storage_bigtable::Error,
        start_block: u64,
        limit: usize,
    },

    #[error("Unable to write block to bigtable")]
    UploadEvmBlock(#[source] solana_storage_bigtable::Error),

    /////////////////////////////////////////////////////////////////////////////////////
    // IO Errors
    /////////////////////////////////////////////////////////////////////////////////////
    #[error("Unable to read file")]
    ReadFile(#[source] std::io::Error),

    /////////////////////////////////////////////////////////////////////////////////////
    // Ser/De Errors
    /////////////////////////////////////////////////////////////////////////////////////
    #[error("Unable to deserialize JSON")]
    JsonDeserialize(#[source] serde_json::Error),

    /////////////////////////////////////////////////////////////////////////////////////
    // Tokio Errors
    /////////////////////////////////////////////////////////////////////////////////////
    #[error("Unable to send EVM message through a tokio channel")]
    SendAsyncEVM(#[source] tokio::sync::mpsc::error::SendError<BlockMessage<Block>>),

    #[error("Unable to send Native message through a tokio channel")]
    SendAsyncNative(#[source] tokio::sync::mpsc::error::SendError<BlockMessage<ConfirmedBlock>>),

    #[error("Unable to join async tasks")]
    TokioTaskJoin(#[source] tokio::task::JoinError),

    #[error("i/o error")]
    IO(#[from] std::io::Error),
    #[error("i/o error")]
    Storage(#[from] evm_state::storage::Error),
}

impl AppError {
    pub fn exit_code(&self) -> i32 {
        match self {
            AppError::VectorIsTooShort => 1001,
            AppError::NotEnoughBlocksToCompare => 1002,
            AppError::RpcRequest(_) => 1003,
            AppError::NonTrivialInstructionsInBlock { .. } => 1004,
            AppError::NoTimestampForBlock => 1005,
            AppError::TxSimulatedWithErrors => 1006,
            AppError::BlocksAmountMismatch => 1007,
            AppError::NoLastBlockBoundary => 1008,
            AppError::EndSlotLessThanStartSlot => 1009,
            AppError::OpenLedger { .. } => 1010,
            AppError::GetEvmBlock(_) => 1011,
            AppError::GetEvmBlockHeader { .. } => 1012,
            AppError::GetEvmBlockNums { .. } => 1013,
            AppError::GetNativeBlock { .. } => 1014,
            AppError::GetNativeBlocks { .. } => 1015,
            AppError::UploadEvmBlock(_) => 1016,
            AppError::ReadFile(_) => 1017,
            AppError::JsonDeserialize(_) => 1018,
            AppError::SendAsyncEVM(_) => 1019,
            AppError::SendAsyncNative(_) => 1020,
            AppError::TokioTaskJoin(_) => 1021,
            AppError::IO(_) => 1022,
            AppError::Storage(_) => 1023,
        }
    }
}
