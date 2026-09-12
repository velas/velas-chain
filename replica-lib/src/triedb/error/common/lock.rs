use thiserror::Error;

use evm_state::H256;
use rocksdb::Error as RocksError;

#[derive(Error, Debug)]
pub enum Error {
    #[error("not found (top level): {0:?}")]
    NotFoundTop(H256),
    #[error(
        "not found (nested in GetStateDiffRequest): either under {from:?} or {to:?}, {description}"
    )]
    NotFoundNested {
        from: H256,
        to: H256,
        description: String,
    },
    #[error(transparent)]
    RocksDB(#[from] RocksError),
}

impl From<Error> for tonic::Status {
    fn from(err: Error) -> Self {
        match err {
            Error::NotFoundTop(..) => tonic::Status::not_found(format!("{:?}", err)),
            Error::NotFoundNested { .. } => tonic::Status::not_found(format!("{:?}", err)),
            Error::RocksDB { .. } => tonic::Status::internal(format!("{:?}", err)),
        }
    }
}
