use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("invalid request: some of the hashes is empty")]
    HashEmpty,
    #[error("invalid request: could not parse hash \"{0}\"")]
    HashParse(String),
    #[error("get array of nodes request: exceeded max array len {actual}, max {max}")]
    ExceedNodesMaxChunk { actual: usize, max: usize },
    #[error("requested diff of blocks too far away {from:?} -> {to:?}")]
    ExceedBlocksMaxGap { from: u64, to: u64 },
}

impl From<Error> for tonic::Status {
    fn from(err: Error) -> Self {
        match err {
            Error::HashEmpty | Error::HashParse(..) => {
                tonic::Status::invalid_argument(format!("{:?}", err))
            }
            Error::ExceedNodesMaxChunk { .. } => {
                tonic::Status::failed_precondition(format!("{:?}", err))
            }
            Error::ExceedBlocksMaxGap { .. } => {
                tonic::Status::failed_precondition(format!("{:?}", err))
            }
        }
    }
}
