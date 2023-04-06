use thiserror::Error;
use triedb::Error as TriedbError;

use crate::triedb::error::evm_height;

use super::check_height;

pub mod fetch_nodes;

#[derive(Error, Debug)]
pub enum Error {
    #[error("evm height : `{0}`")]
    EvmHeight(#[from] evm_height::Error),
    #[error("fetch nodes: `{0}`")]
    FetchNodes(#[from] fetch_nodes::Error),
    #[error("check height: `{0}`")]
    CheckHeight(#[from] check_height::Error),
    #[error("triedb error {0}")]
    Triedb(#[from] TriedbError),
}
