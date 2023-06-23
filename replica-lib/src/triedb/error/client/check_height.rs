use evm_state::{BlockNum, H256};
use thiserror::Error;

use super::proto;

#[derive(Error, Debug)]
pub enum Error {
    #[error("proto violated error {0}")]
    Proto(#[from] proto::Error),
    #[error("grpc error {0}")]
    GRPCUnhandled(#[from] tonic::Status),
    #[error("mismatch at height: {actual:?} instead of {expected:?}, {height}")]
    HashMismatch {
        actual: H256,
        expected: H256,
        height: BlockNum,
    },
    #[error("prefetch height absent: {height}")]
    HeightAbsent { height: BlockNum },
}
