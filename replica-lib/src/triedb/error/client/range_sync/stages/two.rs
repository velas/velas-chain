use thiserror::Error;
use tokio::task::JoinError;

use crate::triedb::DiffRequest;

use super::one;

pub mod apply;

#[derive(Error, Debug)]
pub enum Error {
    #[error("stage one {0}")]
    StageOne(#[from] one::Error),
    #[error("apply {0:?} {1}")]
    Apply(DiffRequest, #[source] apply::Error),
    #[error("joined blocking db task panicked {0:?} {1}")]
    TaskPanicked(DiffRequest, #[source] JoinError),
}
