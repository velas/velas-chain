use evm_state::{BlockNum, H256};
use rocksdb::Error as RocksError;
use thiserror::Error;
use triedb::Error as TriedbError;

#[derive(Error, Debug)]
pub enum EvmHeightError {
    #[error("bigtable error : `{0}`")]
    Bigtable(#[from] solana_storage_bigtable::Error),
}

#[derive(Error, Debug)]
pub enum LockError {
    #[error("hash not found: `{0:?}`")]
    LockRootNotFound(H256),
    #[error(transparent)]
    RocksDBError(#[from] RocksError),
}
#[derive(Error, Debug)]
pub enum ServerError {
    #[error("evm height : `{0}`")]
    EvmHeight(#[from] EvmHeightError),
    #[error(transparent)]
    Lock(#[from] LockError),
}

#[derive(Error, Debug)]
pub enum ClientError {
    #[error("invalid GetStateDiffReply: some of the hashes is empty")]
    EmptyHashGetStateDiffReply,
    #[error("could not parse hash \"{0}\"")]
    CouldNotParseHash(String),
    // probably means different chains or forks were involved
    #[error("hash mismatch on receiving GetStateDiffReply: height: {height}, expected: {expected}, actual: {actual}")]
    HashMismatch {
        height: evm_state::BlockNum,
        expected: H256,
        actual: H256,
    },
    #[error(transparent)]
    Lock(#[from] LockError),
    #[error("connect error {0}")]
    Connect(#[from] tonic::transport::Error),
    #[error("grpc error {0}")]
    GRPC(#[from] tonic::Status),
    #[error("GetArrayOfNodesReply: len mismatch on input/output {0} {1}")]
    GetArrayOfNodesReplyLenMismatch(usize, usize),
    #[error("GetArrayOfNodesReply: hash mismatch on expected/actual{0:?} {1:?}")]
    GetArrayOfNodesReplyHashMismatch(H256, H256),
    #[error("triedb error {0}")]
    Triedb(#[from] TriedbError),
}

#[derive(Error, Debug)]
pub enum ClientAdvanceError {
    #[error("evm height : `{0}`")]
    EvmHeight(#[from] EvmHeightError),
    #[error("heights advance error: {heights:?}, {hashes:?}, {state_rpc_address}, {error}")]
    ClientErrorWithContext {
        heights: Option<(evm_state::BlockNum, evm_state::BlockNum)>,
        hashes: Option<(H256, H256)>,
        state_rpc_address: String,

        #[source]
        error: ClientError,
    },
    #[error("no useful advance can be made on {state_rpc_address};  our : {self_range:?} ; offer: {server_offer:?}")]
    EmptyAdvance {
        state_rpc_address: String,
        self_range: std::ops::Range<BlockNum>,
        server_offer: std::ops::Range<BlockNum>,
    },
}

#[derive(Error, Debug)]
pub enum BootstrapError {
    #[error("evm height : `{0}`")]
    EvmHeight(#[from] EvmHeightError),
    #[error("client error {0}")]
    ClientError(#[from] ClientError),
}

#[derive(Error, Debug)]
pub enum RangeInitError {
    #[error(transparent)]
    IoError(#[from] std::io::Error),
    #[error(transparent)]
    SerdeJson(#[from] serde_json::Error),
}

pub fn source_matches_type<T: std::error::Error + 'static>(
    mut err: &(dyn std::error::Error + 'static),
) -> bool {
    let type_name = std::any::type_name::<T>();
    loop {
        if let Some(transport) = err.downcast_ref::<T>() {
            log::error!("matching source type `{:?}`: `{}`", transport, type_name);
            break true;
        }
        if let Some(source) = err.source() {
            log::debug!("Caused by: {}", source);
            err = source;
        } else {
            break false;
        }
    }
}
