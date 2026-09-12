use thiserror::Error;

use triedb::Error as TriedbError;

use crate::triedb::error::lock;

#[derive(Error, Debug)]
pub enum Error {
    #[error("triedb error {0}")]
    Triedb(#[from] TriedbError),
    #[error("lock error {0}")]
    Lock(#[from] lock::Error),
}
