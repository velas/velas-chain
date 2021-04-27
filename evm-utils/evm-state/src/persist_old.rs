use crate::{AccountState, BlockNum, Maybe, TransactionReceipt};
use ethbloom::Bloom;
use primitive_types::{H160, H256};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// compatibility with old persist
/// without field block_version

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Incomming {
    pub block_number: BlockNum,
    pub timestamp: u64,
    pub used_gas: u64,
    state_root: H256,
    last_block_hash: H256,
    /// Maybe::Nothing indicates removed account
    state_updates: HashMap<H160, (Maybe<AccountState>, HashMap<H256, H256>)>,

    /// Transactions that was processed but wasn't committed.
    /// Transactions should be ordered by execution order on all validators.
    executed_transactions: Vec<(H256, TransactionReceipt)>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Committed {
    pub block: BlockHeader,
    /// Transactions should be ordered somehow, because we
    pub committed_transactions: Vec<(H256, TransactionReceipt)>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockHeader {
    pub parent_hash: H256,
    pub state_root: H256,
    pub native_chain_hash: H256,
    pub transactions: Vec<H256>,
    pub transactions_root: H256,
    pub receipts_root: H256,
    pub logs_bloom: Bloom,
    pub block_number: u64,
    pub gas_limit: u64,
    pub gas_used: u64,
    pub timestamp: u64,
    pub native_chain_slot: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum EvmPersistState {
    Committed(Committed),
    Incomming(Incomming), // Usually bank will never try to freeze banks with persist state.
}

// Convert from legacy structure to new one

impl From<Incomming> for crate::state::Incomming {
    fn from(incomming: Incomming) -> Self {
        Self {
            block_number: incomming.block_number,
            timestamp: incomming.timestamp,
            used_gas: incomming.used_gas,
            state_root: incomming.state_root,
            last_block_hash: incomming.last_block_hash,
            state_updates: incomming.state_updates,

            executed_transactions: incomming.executed_transactions,
            block_version: crate::BlockVersion::InitVersion,
        }
    }
}

impl From<BlockHeader> for crate::types::BlockHeader {
    fn from(block_header: BlockHeader) -> Self {
        Self {
            parent_hash: block_header.parent_hash,
            state_root: block_header.state_root,
            native_chain_hash: block_header.native_chain_hash,
            transactions: block_header.transactions,
            transactions_root: block_header.transactions_root,
            receipts_root: block_header.receipts_root,
            logs_bloom: block_header.logs_bloom,
            block_number: block_header.block_number,
            gas_limit: block_header.gas_limit,

            gas_used: block_header.gas_used,
            timestamp: block_header.timestamp,
            native_chain_slot: block_header.native_chain_slot,
            version: crate::BlockVersion::InitVersion,
        }
    }
}

impl From<Committed> for crate::state::Committed {
    fn from(committed: Committed) -> Self {
        Self {
            block: committed.block.into(),
            committed_transactions: committed.committed_transactions,
        }
    }
}

impl From<EvmPersistState> for crate::state::EvmPersistState {
    fn from(persist: EvmPersistState) -> Self {
        match persist {
            EvmPersistState::Committed(c) => Self::Committed(c.into()),
            EvmPersistState::Incomming(c) => Self::Incomming(c.into()),
        }
    }
}

// Convert from real structure to legacy one

impl From<crate::state::Incomming> for Incomming {
    fn from(incomming: crate::state::Incomming) -> Self {
        Self {
            block_number: incomming.block_number,
            timestamp: incomming.timestamp,
            used_gas: incomming.used_gas,
            state_root: incomming.state_root,
            last_block_hash: incomming.last_block_hash,
            state_updates: incomming.state_updates,

            executed_transactions: incomming.executed_transactions,
        }
    }
}

impl From<crate::types::BlockHeader> for BlockHeader {
    fn from(block_header: crate::types::BlockHeader) -> Self {
        Self {
            parent_hash: block_header.parent_hash,
            state_root: block_header.state_root,
            native_chain_hash: block_header.native_chain_hash,
            transactions: block_header.transactions,
            transactions_root: block_header.transactions_root,
            receipts_root: block_header.receipts_root,
            logs_bloom: block_header.logs_bloom,
            block_number: block_header.block_number,
            gas_limit: block_header.gas_limit,

            gas_used: block_header.gas_used,
            timestamp: block_header.timestamp,
            native_chain_slot: block_header.native_chain_slot,
        }
    }
}

impl From<crate::state::Committed> for Committed {
    fn from(committed: crate::state::Committed) -> Self {
        Self {
            block: committed.block.into(),
            committed_transactions: committed.committed_transactions,
        }
    }
}

impl From<crate::state::EvmPersistState> for EvmPersistState {
    fn from(persist: crate::state::EvmPersistState) -> Self {
        match persist {
            crate::state::EvmPersistState::Committed(c) => Self::Committed(c.into()),
            crate::state::EvmPersistState::Incomming(c) => Self::Incomming(c.into()),
        }
    }
}
