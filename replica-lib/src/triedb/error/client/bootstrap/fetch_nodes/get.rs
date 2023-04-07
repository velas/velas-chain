use tonic::Code;

use thiserror::Error;

#[derive(Error, Debug)]
#[error("the last after many retries {0:?}")]
pub struct SlowError(#[source] tonic::Status);

#[derive(Error, Debug)]
pub enum FastError {
    #[error("server exceeded max chunk of get nodes {0:?}")]
    ExceedMaxChunk(#[source] tonic::Status),
    #[error("server could not parse hash {0:?}")]
    ParseHash(#[source] tonic::Status),
    #[error("server not found {0:?}")]
    NotFound(#[source] tonic::Status),
    #[error("unknown {0:?}")]
    Unknown(#[source] tonic::Status),
}

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
                message if message.contains("ExceedNodesMaxChunk") => {
                    Self::Fast(FastError::ExceedMaxChunk(value))
                }
                _ => Self::Fast(FastError::Unknown(value.clone())),
            },
            Code::NotFound => match value.message() {
                message if message.contains("NotFoundTop") => {
                    Self::Fast(FastError::NotFound(value))
                }

                _ => Self::Fast(FastError::Unknown(value.clone())),
            },
            Code::InvalidArgument => match value.message() {
                message if message.contains("HashParse") => Self::Fast(FastError::ParseHash(value)),

                _ => Self::Fast(FastError::Unknown(value.clone())),
            },
            _ => Self::Slow(SlowError(value)),
        }
    }
}
