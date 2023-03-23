use evm_state::{H256, BlockNum};
use rocksdb::Error as RocksError;
use thiserror::Error;
use triedb::Error as TriedbError;

#[derive(Error, Debug)]
pub enum EvmHeightError {
    #[error("bigtable error : `{0}`")]
    Bigtable(#[from] solana_storage_bigtable::Error),
    #[error("zero hight forbidden")]
    ZeroHeightForbidden,
}

impl From<EvmHeightError> for tonic::Status {
    fn from(err: EvmHeightError) -> Self {
        match err {
            EvmHeightError::Bigtable(ref bigtable) => match bigtable {
                solana_storage_bigtable::Error::BlockNotFound(..) => {
                    tonic::Status::not_found(format!("{:?}", err))
                }
                _ => tonic::Status::internal(format!("{:?}", err)),
            },
            EvmHeightError::ZeroHeightForbidden => tonic::Status::not_found(format!("{:?}", err)),
        }
    }
}
#[derive(Error, Debug)]
pub enum LockError {
    #[error("hash not found: `{0:?}`")]
    LockRootNotFound(H256),
    #[error(transparent)]
    RocksDBError(#[from] RocksError),
}
#[derive(Error, Debug)]
pub enum ServerProtoError {
    #[error("invalid request: some of the hashes is empty")]
    EmptyHash,
    #[error("invalid request: could not parse hash \"{0}\"")]
    CouldNotParseHash(String),
    #[error("get array of nodes request: exceeded max array len {actual}, max {max}")]
    ExceededMaxChunkGetArrayOfNodes { actual: usize, max: usize },
}

impl From<ServerProtoError> for tonic::Status {
    fn from(err: ServerProtoError) -> Self {
        match err {
            variant @ (ServerProtoError::EmptyHash | ServerProtoError::CouldNotParseHash(..)) => {
                tonic::Status::invalid_argument(format!("{:?}", variant))
            }
            variant @ ServerProtoError::ExceededMaxChunkGetArrayOfNodes { .. } => {
                tonic::Status::failed_precondition(format!("{:?}", variant))
            }
        }
    }
}

#[derive(Error, Debug)]
pub enum ServerError {
    #[error("rocksdb error {0}")]
    RocksDBError(#[from] RocksError),
    #[error("proto violated error {0}")]
    ProtoViolated(#[from] ServerProtoError),
    #[error("evm height : `{0}`")]
    EvmHeight(#[from] EvmHeightError),
    #[error(transparent)]
    Lock(#[from] LockError),
    // probably means different chains or forks were involved
    #[error("hash mismatch in GetStateDiffRequest: height: {height}, expected: {expected}, actual: {actual}")]
    HashMismatch {
        height: evm_state::BlockNum,
        expected: H256,
        actual: H256,
    },
    #[error("triedb diff")]
    TriedbDiff,
    #[error("not found (top level): {0:?}")]
    NotFoundTopLevel(H256),
    #[error("not found (nested): either under {from:?} or {to:?}, {description}")]
    NotFoundNested {
        from: H256,
        to: H256,
        description: String,
    },
}

impl From<ServerError> for tonic::Status {
    fn from(err: ServerError) -> Self {
        match err {
            proto_violated @ ServerError::ProtoViolated(..) => proto_violated.into(),
            hash_mismatch @ ServerError::HashMismatch { .. } => {
                tonic::Status::failed_precondition(format!("{:?}", hash_mismatch))
            }
            not_found_top_level @ ServerError::NotFoundTopLevel(..) => {
                tonic::Status::not_found(format!("{:?}", not_found_top_level))
            }
            lock @ ServerError::Lock(..) => tonic::Status::not_found(format!("{:?}", lock)),
            rocks @ ServerError::RocksDBError(..) => {
                tonic::Status::internal(format!("{:?}", rocks))
            }
            ServerError::EvmHeight(inner) => inner.into(),
            triedb_diff @ ServerError::TriedbDiff => {
                tonic::Status::internal(format!("{:?}", triedb_diff))
            }
            not_found_nested @ ServerError::NotFoundNested { .. } => {
                tonic::Status::not_found(format!("not found {:?}", not_found_nested))
            }
        }
    }
}

#[derive(Error, Debug)]
pub enum ClientProtoError {
    #[error("invalid GetStateDiffReply: some of the hashes is empty")]
    EmptyHash,
    #[error("invalid GetStateDiffReply: could not parse hash \"{0}\"")]
    CouldNotParseHash(String),
    #[error("GetArrayOfNodesReply: len mismatch on input/output {0} {1}")]
    GetArrayOfNodesReplyLenMismatch(usize, usize),
    #[error("GetArrayOfNodesReply: hash mismatch on expected/actual{0:?} {1:?}")]
    GetArrayOfNodesReplyHashMismatch(H256, H256),
}

#[derive(Error, Debug)]
pub enum ClientError {
    #[error("proto violated error {0}")]
    ProtoViolated(#[from] ClientProtoError),
    #[error(transparent)]
    Lock(#[from] LockError),
    #[error("connect error {0}")]
    Connect(#[from] tonic::transport::Error),
    #[error("grpc error {0}")]
    GRPC(#[from] tonic::Status),
    #[error("triedb error {0}")]
    Triedb(#[from] TriedbError),
    #[error("prefetch height absent: {height}")]
    PrefetchHeightAbsent {
        height: BlockNum,
    },
    #[error("mismatch at height: {actual:?} instead of {expected:?}, {height}")]
    PrefetchHeightMismatch {
        actual: H256,
        expected: H256,
        height: BlockNum,
    },
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
