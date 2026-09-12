use thiserror::Error;

use crate::triedb::error::evm_height;

pub mod request;

#[derive(Error, Debug)]
pub enum Error {
    #[error("request {0}")]
    Request(#[from] request::Error),
    #[error("evm_height {0}")]
    EvmHeight(#[from] evm_height::Error),
}
