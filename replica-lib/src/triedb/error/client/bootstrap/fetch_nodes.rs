use thiserror::Error;

use crate::triedb::error::client::proto;

pub mod get;

#[derive(Error, Debug)]
pub enum Error {
    #[error("get nodes {0}")]
    Get(usize, #[source] get::Error),
    #[error("proto violated error {0}")]
    Proto(#[from] proto::Error),
}
