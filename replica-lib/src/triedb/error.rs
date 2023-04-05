use std::ops::Range;

use evm_state::{BlockNum, H256};
use rocksdb::Error as RocksError;
use thiserror::Error;
use tokio::task::JoinError;
use tonic::Code;
use triedb::Error as TriedbError;

#[derive(Error, Debug)]
pub enum EvmHeightError {
    #[error("bigtable error : `{0}`")]
    Bigtable(#[from] solana_storage_bigtable::Error),
    #[error("zero hight forbidden")]
    ZeroHeightForbidden,
    #[error("max block chunk exceeded: {actual}, {max}")]
    MaxBlockChunkExceeded { actual: BlockNum, max: BlockNum },
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
            EvmHeightError::ZeroHeightForbidden => {
                tonic::Status::invalid_argument(format!("{:?}", err))
            }
            EvmHeightError::MaxBlockChunkExceeded { .. } => {
                tonic::Status::resource_exhausted(format!("{:?}", err))
            }
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

impl From<LockError> for tonic::Status {
    fn from(err: LockError) -> Self {
        match err {
            LockError::LockRootNotFound(..) => tonic::Status::not_found(format!("{:?}", err)),
            LockError::RocksDBError { .. } => tonic::Status::internal(format!("{:?}", err)),
        }
    }
}
#[derive(Error, Debug)]
pub enum ServerProtoError {
    #[error("invalid request: some of the hashes is empty")]
    EmptyHash,
    #[error("invalid request: could not parse hash \"{0}\"")]
    CouldNotParseHash(String),
    #[error("get array of nodes request: exceeded max array len {actual}, max {max}")]
    ExceededMaxChunkGetArrayOfNodes { actual: usize, max: usize },
    #[error("requested diff of blocks too far away {from:?} -> {to:?}")]
    StateDiffBlocksTooFar { from: u64, to: u64 },
}

impl From<ServerProtoError> for tonic::Status {
    fn from(err: ServerProtoError) -> Self {
        match err {
            ServerProtoError::EmptyHash | ServerProtoError::CouldNotParseHash(..) => {
                tonic::Status::invalid_argument(format!("{:?}", err))
            }
            ServerProtoError::ExceededMaxChunkGetArrayOfNodes { .. } => {
                tonic::Status::failed_precondition(format!("{:?}", err))
            }
            ServerProtoError::StateDiffBlocksTooFar { .. } => {
                tonic::Status::failed_precondition(format!("{:?}", err))
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
    #[error("not completely present {ours:?}, requested - {requested:?}")]
    PrefetchRange {
        ours: Range<BlockNum>,
        requested: Range<BlockNum>,
    },
}

impl From<ServerError> for tonic::Status {
    fn from(err: ServerError) -> Self {
        match err {
            ServerError::ProtoViolated(err) => err.into(),
            hash_mismatch @ ServerError::HashMismatch { .. } => {
                tonic::Status::failed_precondition(format!("{:?}", hash_mismatch))
            }
            not_found_top_level @ ServerError::NotFoundTopLevel(..) => {
                tonic::Status::not_found(format!("{:?}", not_found_top_level))
            }
            ServerError::Lock(lock) => lock.into(),
            rocks @ ServerError::RocksDBError(..) => {
                tonic::Status::internal(format!("{:?}", rocks))
            }
            ServerError::EvmHeight(inner) => inner.into(),
            triedb_diff @ ServerError::TriedbDiff => {
                tonic::Status::internal(format!("{:?}", triedb_diff))
            }
            not_found_nested @ ServerError::NotFoundNested { .. } => {
                tonic::Status::not_found(format!("{:?}", not_found_nested))
            }
            prefetch_range @ ServerError::PrefetchRange { .. } => {
                tonic::Status::not_found(format!("{:?}", prefetch_range))
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
    PrefetchHeightAbsent { height: BlockNum },
    #[error("mismatch at height: {actual:?} instead of {expected:?}, {height}")]
    PrefetchHeightMismatch {
        actual: H256,
        expected: H256,
        height: BlockNum,
    },
    #[error("evm height : `{0}`")]
    EvmHeight(#[from] EvmHeightError),
    #[error("get nodes details: `{0}`")]
    GetNodes(#[from] GetNodesError),
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

#[derive(Clone, Copy, Debug)]
pub struct DiffRequest {
    pub heights: (evm_state::BlockNum, evm_state::BlockNum),
    pub expected_hashes: (H256, H256),
}

#[derive(Error, Debug)]
pub enum GetNodesError {
    #[error("fast {0}")]
    Fast(GetNodesFastError),
    #[error("retried {0}")]
    Slow(GetNodesSlowError),
}

#[derive(Error, Debug)]
#[error("the last after many retries {0:?}")]
pub struct GetNodesSlowError(usize, #[source] tonic::Status);

#[derive(Error, Debug)]
pub enum GetNodesFastError {
    #[error("server exceeded max chunk of get nodes {0:?}, {1:?}")]
    ServerExceededMaxChunk(usize, #[source] tonic::Status),
    #[error("server could not parse hash {0:?}, {1:?}")]
    ServerCouldNotParseHash(usize, #[source] tonic::Status),
    #[error("server not found {0:?}, {1:?}")]
    ServerNotFound(usize, #[source] tonic::Status),
    #[error("unknown {0:?}")]
    Unknown(#[source] tonic::Status),
}

impl GetNodesError {
    pub fn from_with_metadata(value: tonic::Status, request_len: usize) -> Self {
        match value.code() {
            Code::FailedPrecondition => match value.message() {
                message @ _ if message.contains("ExceededMaxChunkGetArrayOfNodes") => Self::Fast(
                    GetNodesFastError::ServerExceededMaxChunk(request_len, value),
                ),
                _ => Self::Fast(GetNodesFastError::Unknown(value.clone())),
            },
            Code::NotFound => match value.message() {
                message @ _ if message.contains("NotFoundTopLevel") => {
                    Self::Fast(GetNodesFastError::ServerNotFound(request_len, value))
                }

                _ => Self::Fast(GetNodesFastError::Unknown(value.clone())),
            },
            Code::InvalidArgument => match value.message() {
                message @ _ if message.contains("CouldNotParseHash") => Self::Fast(
                    GetNodesFastError::ServerCouldNotParseHash(request_len, value),
                ),

                _ => Self::Fast(GetNodesFastError::Unknown(value.clone())),
            },
            _ => Self::Slow(GetNodesSlowError(request_len, value)),
        }
    }
}

#[derive(Error, Debug)]
pub enum StageOneNetworkFastError {
    #[error("server hash mismatch {0:?}, {1:?}")]
    ServerHashMismatch(DiffRequest, #[source] tonic::Status),
    #[error("server blocks too far {0:?}, {1:?}")]
    ServerBlocksTooFar(DiffRequest, #[source] tonic::Status),
    #[error("server block not found {0:?}, {1:?}")]
    ServerBlockNotFoundLedgerStorage(DiffRequest, #[source] tonic::Status),
    #[error("server zero height metadata reqeusted {0:?}, {1:?}")]
    ServerZeroHeight(DiffRequest, #[source] tonic::Status),
    #[error("server proto, empty hash {0:?}, {1:?}")]
    ServerProtoEmptyHash(DiffRequest, #[source] tonic::Status),
    #[error("server proto, could not parse {0:?}, {1:?}")]
    ServerProtoCouldNotParseHash(DiffRequest, #[source] tonic::Status),
    #[error("server lock or check root, {0:?}, {1:?}")]
    ServerLockOrCheckRoot(DiffRequest, #[source] tonic::Status),
    #[error("server deeply broken tree, {0:?}, {1:?}")]
    ServerDeeplyBrokenTree(DiffRequest, #[source] tonic::Status),
    #[error("unknown {0:?}")]
    Unknown(#[source] tonic::Status),
}
#[derive(Error, Debug)]
#[error("the last after many retries {0:?}")]
pub struct StageOneNetworkSlowError(DiffRequest, #[source] tonic::Status);

#[derive(Error, Debug)]
pub enum StageOneNetworkError {
    #[error("fast {0}")]
    Fast(StageOneNetworkFastError),
    #[error("retried {0}")]
    Slow(StageOneNetworkSlowError),
}

impl StageOneNetworkError {
    pub fn from_with_metadata(value: tonic::Status, request: DiffRequest) -> Self {
        match value.code() {
            Code::FailedPrecondition => match value.message() {
                message @ _ if message.contains("HashMismatch") => {
                    Self::Fast(StageOneNetworkFastError::ServerHashMismatch(request, value))
                }
                message @ _ if message.contains("StateDiffBlocksTooFar") => {
                    Self::Fast(StageOneNetworkFastError::ServerBlocksTooFar(request, value))
                }
                _ => Self::Fast(StageOneNetworkFastError::Unknown(value.clone())),
            },
            Code::NotFound => match value.message() {
                message @ _ if message.contains("Bigtable(BlockNotFound") => Self::Fast(
                    StageOneNetworkFastError::ServerBlockNotFoundLedgerStorage(request, value),
                ),
                message @ _ if message.contains("LockRootNotFound") => Self::Fast(
                    StageOneNetworkFastError::ServerLockOrCheckRoot(request, value),
                ),

                message @ _ if message.contains("NotFoundNested") => Self::Fast(
                    StageOneNetworkFastError::ServerDeeplyBrokenTree(request, value),
                ),

                _ => Self::Fast(StageOneNetworkFastError::Unknown(value.clone())),
            },
            Code::InvalidArgument => match value.message() {
                message @ _ if message.contains("ZeroHeightForbidden") => {
                    Self::Fast(StageOneNetworkFastError::ServerZeroHeight(request, value))
                }
                message @ _ if message.contains("EmptyHash") => Self::Fast(
                    StageOneNetworkFastError::ServerProtoEmptyHash(request, value),
                ),
                message @ _ if message.contains("CouldNotParseHash(") => Self::Fast(
                    StageOneNetworkFastError::ServerProtoCouldNotParseHash(request, value),
                ),

                _ => Self::Fast(StageOneNetworkFastError::Unknown(value.clone())),
            },
            _ => Self::Slow(StageOneNetworkSlowError(request, value)),
        }
    }
}

#[derive(Error, Debug)]
pub enum StageOneRequestError {
    #[error("network {0}")]
    Network(#[from] StageOneNetworkError),
    #[error("parse diff response {0}")]
    ProtoViolated(#[from] ClientProtoError),
}

#[derive(Error, Debug)]
pub enum StageOneError {
    #[error("request {0}")]
    Request(#[from] StageOneRequestError),
    #[error("evm_height {0}")]
    EvmHeight(#[from] EvmHeightError),
}

#[derive(Error, Debug)]
pub enum StageTwoError {
    #[error("stage one {0}")]
    StageOne(#[from] StageOneError),
    #[error("apply {0}")]
    Apply(#[from] StageTwoApplyError),
    #[error("joined blocking db task panicked {0}")]
    ApplyDBTaskPanicked(#[from] JoinError),
}

#[derive(Error, Debug)]
pub enum StageTwoApplyError {
    #[error("triedb error {0}")]
    Triedb(#[from] TriedbError),
    #[error("lock error {0}")]
    Lock(#[from] LockError),
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

#[cfg(test)]
mod tests {
    use evm_state::empty_trie_hash;
    use tonic::Code;

    use crate::triedb::error::{
        DiffRequest, EvmHeightError, GetNodesError, GetNodesFastError, LockError, ServerProtoError,
        StageOneNetworkError, StageOneNetworkFastError,
    };

    use super::ServerError;

    #[test]
    fn test_from_with_metadata_diff_request() {
        {
            let err = ServerError::HashMismatch {
                height: 10,
                expected: empty_trie_hash(),
                actual: empty_trie_hash(),
            };

            let status: tonic::Status = err.into();

            let diff_request_stub = DiffRequest {
                heights: (1, 2),
                expected_hashes: (empty_trie_hash(), empty_trie_hash()),
            };

            let result = StageOneNetworkError::from_with_metadata(status, diff_request_stub);

            assert_matches!(
                result,
                StageOneNetworkError::Fast(StageOneNetworkFastError::ServerHashMismatch { .. })
            );
        }
        // #### fence
        {
            let err = ServerProtoError::StateDiffBlocksTooFar {
                from: 1,
                to: 70000000,
            };

            let status: tonic::Status = err.into();

            let diff_request_stub = DiffRequest {
                heights: (1, 2),
                expected_hashes: (empty_trie_hash(), empty_trie_hash()),
            };

            let result = StageOneNetworkError::from_with_metadata(status, diff_request_stub);

            assert_matches!(
                result,
                StageOneNetworkError::Fast(StageOneNetworkFastError::ServerBlocksTooFar { .. })
            );
        } // #### fence
        {
            let random_status =
                tonic::Status::new(Code::FailedPrecondition, "undecipherable gibberish");
            let diff_request_stub = DiffRequest {
                heights: (1, 2),
                expected_hashes: (empty_trie_hash(), empty_trie_hash()),
            };
            let random_status_result =
                StageOneNetworkError::from_with_metadata(random_status, diff_request_stub);
            assert_matches!(
                random_status_result,
                StageOneNetworkError::Fast(StageOneNetworkFastError::Unknown(..))
            );
        }
        // #### fence
        {
            let bt_err = solana_storage_bigtable::Error::BlockNotFound(70000000);
            let evm_height = Into::<EvmHeightError>::into(bt_err);
            let err = Into::<ServerError>::into(evm_height);

            let status: tonic::Status = err.into();

            let diff_request_stub = DiffRequest {
                heights: (1, 2),
                expected_hashes: (empty_trie_hash(), empty_trie_hash()),
            };

            let result = StageOneNetworkError::from_with_metadata(status, diff_request_stub);

            assert_matches!(
                result,
                StageOneNetworkError::Fast(
                    StageOneNetworkFastError::ServerBlockNotFoundLedgerStorage { .. }
                )
            );
        } // #### fence
          // #### fence
        {
            let evm_height = EvmHeightError::ZeroHeightForbidden;
            let err = Into::<ServerError>::into(evm_height);

            let status: tonic::Status = err.into();

            let diff_request_stub = DiffRequest {
                heights: (1, 2),
                expected_hashes: (empty_trie_hash(), empty_trie_hash()),
            };

            let result = StageOneNetworkError::from_with_metadata(status, diff_request_stub);

            assert_matches!(
                result,
                StageOneNetworkError::Fast(StageOneNetworkFastError::ServerZeroHeight { .. })
            );
        } // #### fence
          // #### fence
        {
            let empty = ServerProtoError::EmptyHash;
            let err = Into::<ServerError>::into(empty);

            let status: tonic::Status = err.into();

            let diff_request_stub = DiffRequest {
                heights: (1, 2),
                expected_hashes: (empty_trie_hash(), empty_trie_hash()),
            };

            let result = StageOneNetworkError::from_with_metadata(status, diff_request_stub);

            assert_matches!(
                result,
                StageOneNetworkError::Fast(StageOneNetworkFastError::ServerProtoEmptyHash { .. })
            );
        } // #### fence

        {
            let parse = ServerProtoError::CouldNotParseHash("gibberish".to_owned());
            let err = Into::<ServerError>::into(parse);

            let status: tonic::Status = err.into();

            let diff_request_stub = DiffRequest {
                heights: (1, 2),
                expected_hashes: (empty_trie_hash(), empty_trie_hash()),
            };

            let result = StageOneNetworkError::from_with_metadata(status, diff_request_stub);

            assert_matches!(
                result,
                StageOneNetworkError::Fast(
                    StageOneNetworkFastError::ServerProtoCouldNotParseHash { .. }
                )
            );
        } // #### fence

        {
            let lock = LockError::LockRootNotFound(empty_trie_hash());
            let err = Into::<ServerError>::into(lock);

            let status: tonic::Status = err.into();

            let diff_request_stub = DiffRequest {
                heights: (1, 2),
                expected_hashes: (empty_trie_hash(), empty_trie_hash()),
            };

            let result = StageOneNetworkError::from_with_metadata(status, diff_request_stub);

            assert_matches!(
                result,
                StageOneNetworkError::Fast(StageOneNetworkFastError::ServerLockOrCheckRoot { .. })
            );
        } // #### fence

        {
            let err = ServerError::NotFoundNested {
                from: empty_trie_hash(),
                to: empty_trie_hash(),
                description: "giggsdfsfl".to_owned(),
            };

            let status: tonic::Status = err.into();

            let diff_request_stub = DiffRequest {
                heights: (1, 2),
                expected_hashes: (empty_trie_hash(), empty_trie_hash()),
            };

            let result = StageOneNetworkError::from_with_metadata(status, diff_request_stub);

            assert_matches!(
                result,
                StageOneNetworkError::Fast(StageOneNetworkFastError::ServerDeeplyBrokenTree { .. })
            );
        } // #### fence
    }

    #[test]
    fn test_from_with_metadata_get_nodes() {
        {
            let empty = ServerProtoError::ExceededMaxChunkGetArrayOfNodes {
                actual: 100,
                max: 50,
            };
            let err = Into::<ServerError>::into(empty);

            let status: tonic::Status = err.into();

            let result = GetNodesError::from_with_metadata(status, 10);

            assert_matches!(
                result,
                GetNodesError::Fast(GetNodesFastError::ServerExceededMaxChunk { .. })
            );
        }

        {
            let empty = ServerProtoError::CouldNotParseHash("gibberish".to_string());
            let err = Into::<ServerError>::into(empty);

            let status: tonic::Status = err.into();

            let result = GetNodesError::from_with_metadata(status, 10);

            assert_matches!(
                result,
                GetNodesError::Fast(GetNodesFastError::ServerCouldNotParseHash { .. })
            );
        }

        {
            let err = ServerError::NotFoundTopLevel(empty_trie_hash());

            let status: tonic::Status = err.into();

            let result = GetNodesError::from_with_metadata(status, 10);

            assert_matches!(
                result,
                GetNodesError::Fast(GetNodesFastError::ServerNotFound { .. })
            );
        }
    }
    // #### fence
}
