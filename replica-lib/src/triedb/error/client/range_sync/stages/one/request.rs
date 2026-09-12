use thiserror::Error;

use crate::triedb::{error::client::proto, DiffRequest};

pub mod network;

#[derive(Error, Debug)]
pub enum Error {
    #[error("network {0:?} {1}")]
    Network(DiffRequest, #[source] network::Error),
    #[error("parse diff response {0:?} {1}")]
    Proto(DiffRequest, #[source] proto::Error),
}
