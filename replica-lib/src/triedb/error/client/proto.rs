use evm_state::H256;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("invalid GetStateDiffReply: some of the hashes is empty")]
    EmptyHash,
    #[error("invalid GetStateDiffReply: could not parse hash \"{0}\"")]
    ParseHash(String),
    #[error("GetArrayOfNodesReply: len mismatch on input/output {0} {1}")]
    NodesLenMismatch(usize, usize),
    #[error("GetArrayOfNodesReply: hash mismatch on expected/actual{0:?} {1:?}")]
    NodesHashMismatch(H256, H256),
}
