use evm_state::{BlockNum, H256};
use std::ops::Range;
use thiserror::Error;

use super::{evm_height, lock};

use rocksdb::Error as RocksError;

pub mod proto;

#[derive(Error, Debug)]
pub enum Error {
    #[error("proto violated error {0}")]
    Proto(#[from] proto::Error),
    #[error("evm height : `{0}`")]
    EvmHeight(#[from] evm_height::Error),
    // probably means different chains or forks were involved
    #[error("not completely present {ours:?}, requested - {requested:?}")]
    PrefetchRange {
        ours: Range<BlockNum>,
        requested: Range<BlockNum>,
    },
    #[error("hash mismatch in GetStateDiffRequest: height: {height}, expected: {expected}, actual: {actual}")]
    HashMismatch {
        height: evm_state::BlockNum,
        expected: H256,
        actual: H256,
    },
    #[error("rocksdb error {0}")]
    RocksDB(#[from] RocksError),
    #[error(transparent)]
    Lock(#[from] lock::Error),
    #[error("triedb diff")]
    TriedbDiff,
}

impl From<Error> for tonic::Status {
    fn from(err: Error) -> Self {
        match err {
            Error::Proto(err) => err.into(),
            hash_mismatch @ Error::HashMismatch { .. } => {
                tonic::Status::failed_precondition(format!("{:?}", hash_mismatch))
            }
            Error::Lock(lock) => lock.into(),
            rocks @ Error::RocksDB(..) => tonic::Status::internal(format!("{:?}", rocks)),
            Error::EvmHeight(inner) => inner.into(),
            triedb_diff @ Error::TriedbDiff => {
                tonic::Status::internal(format!("{:?}", triedb_diff))
            }
            prefetch_range @ Error::PrefetchRange { .. } => {
                tonic::Status::not_found(format!("{:?}", prefetch_range))
            }
        }
    }
}
