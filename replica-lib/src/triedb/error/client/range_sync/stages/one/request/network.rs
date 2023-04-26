use thiserror::Error;

use tonic::Code;

#[derive(Error, Debug)]
pub enum FastError {
    #[error("server hash mismatch {0:?}")]
    HashMismatch(#[source] tonic::Status),
    #[error("server blocks too far {0:?}")]
    ExceedDiffMaxGap(#[source] tonic::Status),
    #[error("server block not found  {0:?}")]
    BlockNotFound(#[source] tonic::Status),
    #[error("server zero height metadata reqeusted  {0:?}")]
    ZeroHeight(#[source] tonic::Status),
    #[error("server proto, empty hash {0:?}")]
    EmptyHash(#[source] tonic::Status),
    #[error("server proto, could not parse {0:?}")]
    ParseHash(#[source] tonic::Status),
    #[error("server lock or check root,  {0:?}")]
    LockRoot(#[source] tonic::Status),
    #[error("server deeply broken tree, {0:?}")]
    TreeBroken(#[source] tonic::Status),
    #[error("unknown {0:?}")]
    Unknown(#[source] tonic::Status),
}

#[derive(Error, Debug)]
#[error("the last after many retries {0:?}")]
pub struct SlowError(#[source] tonic::Status);

#[derive(Error, Debug)]
pub enum Error {
    #[error("fast {0}")]
    Fast(FastError),
    #[error("retried {0}")]
    Slow(SlowError),
}

impl From<tonic::Status> for Error {
    fn from(value: tonic::Status) -> Self {
        match value.code() {
            Code::FailedPrecondition => match value.message() {
                message if message.contains("HashMismatch") => {
                    Self::Fast(FastError::HashMismatch(value))
                }
                message if message.contains("ExceedBlocksMaxGap") => {
                    Self::Fast(FastError::ExceedDiffMaxGap(value))
                }
                _ => Self::Fast(FastError::Unknown(value.clone())),
            },
            Code::NotFound => match value.message() {
                message if message.contains("Bigtable(BlockNotFound") => {
                    Self::Fast(FastError::BlockNotFound(value))
                }
                message if message.contains("NotFoundTop") => {
                    Self::Fast(FastError::LockRoot(value))
                }

                message if message.contains("NotFoundNested") => {
                    Self::Fast(FastError::TreeBroken(value))
                }

                _ => Self::Fast(FastError::Unknown(value.clone())),
            },
            Code::InvalidArgument => match value.message() {
                message if message.contains("ForbidZero") => {
                    Self::Fast(FastError::ZeroHeight(value))
                }
                message if message.contains("HashEmpty") => Self::Fast(FastError::EmptyHash(value)),
                message if message.contains("HashParse") => Self::Fast(FastError::ParseHash(value)),

                _ => Self::Fast(FastError::Unknown(value.clone())),
            },
            _ => Self::Slow(SlowError(value)),
        }
    }
}
