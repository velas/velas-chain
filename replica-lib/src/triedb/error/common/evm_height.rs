use evm_state::BlockNum;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("bigtable error : `{0}`")]
    Bigtable(#[from] solana_storage_bigtable::Error),
    #[error("zero hight forbidden")]
    ForbidZero,
    #[error("max block chunk exceeded: {actual}, {max}")]
    ExceedMaxChunk { actual: BlockNum, max: BlockNum },
}

impl From<Error> for tonic::Status {
    fn from(err: Error) -> Self {
        match err {
            Error::Bigtable(ref bigtable) => match bigtable {
                solana_storage_bigtable::Error::BlockNotFound(..) => {
                    tonic::Status::not_found(format!("{:?}", err))
                }
                _ => tonic::Status::internal(format!("{:?}", err)),
            },
            Error::ForbidZero => tonic::Status::invalid_argument(format!("{:?}", err)),
            Error::ExceedMaxChunk { .. } => tonic::Status::resource_exhausted(format!("{:?}", err)),
        }
    }
}
