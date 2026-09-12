use thiserror::Error;

use crate::triedb::error::{evm_height, lock};

use super::{check_height, proto};

pub mod stages;

#[derive(Error, Debug)]
pub enum Error {
    #[error("proto violated error {0}")]
    Proto(#[from] proto::Error),
    #[error("check height: `{0}`")]
    CheckHeight(#[from] check_height::Error),
    #[error(transparent)]
    Lock(#[from] lock::Error),
    #[error("grpc error {0}")]
    GRPCUnhandled(#[from] tonic::Status),
    #[error("evm height : `{0}`")]
    EvmHeight(#[from] evm_height::Error),
}
