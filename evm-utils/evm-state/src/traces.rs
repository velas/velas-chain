use {crate::H256, evm::executor::traces::Trace};

#[derive(Debug, Clone)]
pub struct TraceResultsWithTransactionHash {
    pub output: Vec<u8>,
    pub trace: Vec<Trace>,
    pub transaction_hash: H256,
}
