use std::convert::TryInto;

use sha3::{Digest, Keccak256};
use snafu::ResultExt;
use solana_sdk::commitment_config::{CommitmentConfig, CommitmentLevel};

use evm_rpc::{
    basic::BasicERPC,
    chain_mock::ChainMockERPC,
    error::{self, Error},
    Bytes, Either, Hex, RPCBlock, RPCLog, RPCLogFilter, RPCReceipt, RPCTopicFilter, RPCTransaction,
};
use evm_state::{AccountProvider, Address, Gas, LogFilter, H256, U256};
use solana_runtime::bank::Bank;

use crate::rpc::JsonRpcRequestProcessor;
use std::sync::Arc;

const DEFAULT_COMITTMENT: Option<CommitmentConfig> = Some(CommitmentConfig {
    commitment: CommitmentLevel::Processed,
});

fn block_to_bank_and_root(
    block: Option<String>,
    meta: &JsonRpcRequestProcessor,
) -> Option<(Arc<Bank>, H256)> {
    let commitment = if let Some(block) = &block {
        match block.as_ref() {
            "earliest" => Some(CommitmentLevel::Confirmed),
            "latest" => Some(CommitmentLevel::Processed),
            "pending" => Some(CommitmentLevel::Processed),
            v => {
                // Try to parse newest version of block commitment.
                if let Ok(c) = serde_json::from_str::<CommitmentLevel>(v) {
                    Some(c)
                } else {
                    // Probably user provide specific slot number, we didn't support bank from future, so just return default.
                    None
                }
            }
        }
    } else {
        None
    };
    let bank = meta.bank(commitment.map(|commitment| CommitmentConfig { commitment }));
    let last_root = {
        let lock = bank.evm_state.read().expect("Evm state poisoned");
        let block_num = block_to_confirmed_num(block, meta).unwrap_or_else(|| lock.block_number());
        meta.blockstore
            .get_evm_block(block_num)
            .map(|(b, _)| b.header.state_root)
            .unwrap_or_else(|_| lock.last_root())
    };
    Some((bank, last_root))
}

fn block_to_confirmed_num(
    block: Option<impl AsRef<str>>,
    meta: &JsonRpcRequestProcessor,
) -> Option<u64> {
    let block = block?;
    match block.as_ref() {
        "earliest" => meta.blockstore.get_first_available_evm_block().ok(),
        "pending" | "latest" => meta.blockstore.get_last_available_evm_block().ok(),
        v => Hex::<u64>::from_hex(&v).ok().map(|f| f.0),
    }
}

pub struct ChainMockERPCImpl;
impl ChainMockERPC for ChainMockERPCImpl {
    type Metadata = JsonRpcRequestProcessor;

    fn network_id(&self, meta: Self::Metadata) -> Result<String, Error> {
        let bank = meta.bank(None);
        Ok(format!("{:#x}", bank.evm_chain_id))
    }

    fn chain_id(&self, meta: Self::Metadata) -> Result<Hex<u64>, Error> {
        let bank = meta.bank(None);
        Ok(Hex(bank.evm_chain_id))
    }

    // TODO: Add network info
    fn is_listening(&self, _meta: Self::Metadata) -> Result<bool, Error> {
        Ok(true)
    }

    fn peer_count(&self, _meta: Self::Metadata) -> Result<Hex<usize>, Error> {
        Ok(Hex(0))
    }

    fn sha3(&self, _meta: Self::Metadata, bytes: Bytes) -> Result<Hex<H256>, Error> {
        Ok(Hex(H256::from_slice(
            Keccak256::digest(bytes.0.as_slice()).as_slice(),
        )))
    }

    fn client_version(&self, _meta: Self::Metadata) -> Result<String, Error> {
        Ok(String::from("velas-chain/v0.3.0"))
    }

    fn protocol_version(&self, _meta: Self::Metadata) -> Result<String, Error> {
        Ok(String::from("0"))
    }

    fn is_syncing(&self, _meta: Self::Metadata) -> Result<bool, Error> {
        Err(Error::Unimplemented {})
    }

    fn coinbase(&self, _meta: Self::Metadata) -> Result<Hex<Address>, Error> {
        Ok(Hex(Address::from_low_u64_be(0)))
    }

    fn is_mining(&self, _meta: Self::Metadata) -> Result<bool, Error> {
        Ok(false)
    }

    fn hashrate(&self, _meta: Self::Metadata) -> Result<String, Error> {
        Err(Error::Unimplemented {})
    }

    fn block_by_hash(
        &self,
        _meta: Self::Metadata,
        _block_hash: Hex<H256>,
        _full: bool,
    ) -> Result<Option<RPCBlock>, Error> {
        Err(Error::Unimplemented {})
    }

    fn block_by_number(
        &self,
        meta: Self::Metadata,
        block: String,
        full: bool,
    ) -> Result<Option<RPCBlock>, Error> {
        let num = block_to_confirmed_num(Some(&block), &meta);
        // TODO: Inline evm_state lookups, and request only solana headers.
        let block_num = num.unwrap_or(0);
        let (block, confirmed) = match meta.blockstore.get_evm_block(block_num) {
            Err(e) => {
                error!("Error requesting block:{}, error:{:?}", block_num, e);
                return Ok(None);
            }
            Ok(b) => b,
        };

        let block_hash = block.header.hash();
        let parent_hash = block.header.parent_hash;
        let transactions = if full {
            let txs = block
                .transactions
                .into_iter()
                .map(|(_k, v)| v)
                .filter_map(|receipt| RPCTransaction::new_from_receipt(receipt, block_hash).ok())
                .collect();
            Either::Right(txs)
        } else {
            let txs = block
                .transactions
                .into_iter()
                .map(|(k, _v)| Hex(k))
                .collect();
            Either::Left(txs)
        };

        let result = RPCBlock {
            number: U256::from(block.header.block_number).into(),
            hash: block_hash.into(),
            parent_hash: parent_hash.into(),
            size: 0x100.into(),
            gas_limit: Hex(block.header.gas_limit.into()),
            gas_used: Hex(block.header.gas_used.into()),
            timestamp: Hex(block.header.timestamp.into()),
            transactions,
            nonce: 0x7bb9369dcbaec019.into(),
            logs_bloom: block.header.logs_bloom, // H2048
            transactions_root: Hex(block.header.transactions_root),
            state_root: Hex(block.header.state_root),
            receipts_root: Hex(block.header.receipts_root),
            miner: Address::zero().into(),
            difficulty: U256::zero().into(),
            total_difficulty: U256::zero().into(),
            extra_data: b"Native chain data ommitted...".to_vec().into(),
            sha3_uncles: H256::zero().into(),
            is_finalized: confirmed,
            uncles: vec![],
        };
        Ok(Some(result))
    }

    fn block_transaction_count_by_number(
        &self,
        _meta: Self::Metadata,
        _block: String,
    ) -> Result<Option<Hex<usize>>, Error> {
        Ok(None)
    }

    fn block_transaction_count_by_hash(
        &self,
        _meta: Self::Metadata,
        _block_hash: Hex<H256>,
    ) -> Result<Option<Hex<usize>>, Error> {
        Err(Error::Unimplemented {})
    }

    fn uncle_by_block_hash_and_index(
        &self,
        _meta: Self::Metadata,
        _block_hash: Hex<H256>,
        _uncle_id: Hex<U256>,
    ) -> Result<Option<RPCBlock>, Error> {
        Err(Error::Unimplemented {})
    }

    fn uncle_by_block_number_and_index(
        &self,
        _meta: Self::Metadata,
        _block: String,
        _uncle_id: Hex<U256>,
    ) -> Result<Option<RPCBlock>, Error> {
        Err(Error::Unimplemented {})
    }

    fn block_uncles_count_by_hash(
        &self,
        _meta: Self::Metadata,
        _block_hash: Hex<H256>,
    ) -> Result<Option<Hex<usize>>, Error> {
        Err(Error::Unimplemented {})
    }

    fn block_uncles_count_by_number(
        &self,
        _meta: Self::Metadata,
        _block: String,
    ) -> Result<Option<Hex<usize>>, Error> {
        Err(Error::Unimplemented {})
    }

    fn transaction_by_block_hash_and_index(
        &self,
        _meta: Self::Metadata,
        _block_hash: Hex<H256>,
        _tx_id: Hex<U256>,
    ) -> Result<Option<RPCTransaction>, Error> {
        Err(Error::Unimplemented {})
    }

    fn transaction_by_block_number_and_index(
        &self,
        _meta: Self::Metadata,
        _block: String,
        _tx_id: Hex<U256>,
    ) -> Result<Option<RPCTransaction>, Error> {
        Err(Error::Unimplemented {})
    }
}

pub struct BasicERPCImpl;
impl BasicERPC for BasicERPCImpl {
    type Metadata = JsonRpcRequestProcessor;

    // The same as get_slot
    fn block_number(&self, meta: Self::Metadata) -> Result<Hex<usize>, Error> {
        let bank = meta.bank(Some(CommitmentConfig::processed()));
        let evm = bank.evm_state.read().unwrap();
        Ok(Hex(evm.block_number() as usize))
    }

    fn balance(
        &self,
        meta: Self::Metadata,
        address: Hex<Address>,
        block: Option<String>,
    ) -> Result<Hex<U256>, Error> {
        let (bank, root) = block_to_bank_and_root(block.clone(), &meta).ok_or_else(|| {
            error::Error::StateNotFoundForBlock {
                block: block.unwrap_or("latest".to_string()),
            }
        })?;
        let evm_state = bank.evm_state.read().expect("Evm state poisoned");
        let account = evm_state
            .get_account_state_at(root, address.0)
            .unwrap_or_default();
        Ok(Hex(account.balance))
    }

    fn storage_at(
        &self,
        meta: Self::Metadata,
        address: Hex<Address>,
        data: Hex<H256>,
        block: Option<String>,
    ) -> Result<Hex<H256>, Error> {
        let (bank, root) = block_to_bank_and_root(block.clone(), &meta).ok_or_else(|| {
            error::Error::StateNotFoundForBlock {
                block: block.unwrap_or("latest".to_string()),
            }
        })?;
        let evm_state = bank.evm_state.read().expect("Evm state poisoned");
        Ok(Hex(evm_state
            .get_storage_at(root, address.0, data.0)
            .unwrap_or_default()))
    }

    fn transaction_count(
        &self,
        meta: Self::Metadata,
        address: Hex<Address>,
        block: Option<String>,
    ) -> Result<Hex<U256>, Error> {
        let (bank, root) = block_to_bank_and_root(block.clone(), &meta).ok_or_else(|| {
            error::Error::StateNotFoundForBlock {
                block: block.unwrap_or("latest".to_string()),
            }
        })?;
        let evm_state = bank.evm_state.read().expect("Evm state poisoned");
        let account = evm_state
            .get_account_state_at(root, address.0)
            .unwrap_or_default();
        Ok(Hex(account.nonce))
    }

    fn code(
        &self,
        meta: Self::Metadata,
        address: Hex<Address>,
        block: Option<String>,
    ) -> Result<Bytes, Error> {
        let (bank, root) = block_to_bank_and_root(block.clone(), &meta).ok_or_else(|| {
            error::Error::StateNotFoundForBlock {
                block: block.unwrap_or("latest".to_string()),
            }
        })?;
        let evm_state = bank.evm_state.read().expect("Evm state poisoned");
        let account = evm_state
            .get_account_state_at(root, address.0)
            .unwrap_or_default();
        Ok(Bytes(account.code.into()))
    }

    fn transaction_by_hash(
        &self,
        meta: Self::Metadata,
        tx_hash: Hex<H256>,
    ) -> Result<Option<RPCTransaction>, Error> {
        let receipt = meta
            .blockstore
            .find_evm_transaction(tx_hash.0)
            .map_err(anyhow::Error::from)
            .with_context(|| error::NativeRpcError {})?;

        Ok(match receipt {
            Some(receipt) => {
                let (block, _) = meta
                    .blockstore
                    .get_evm_block(receipt.block_number)
                    .map_err(|_| Error::BlockNotFound {
                        block: receipt.block_number,
                    })?;
                let block_hash = block.header.hash();
                Some(RPCTransaction::new_from_receipt(receipt, block_hash)?)
            }
            None => None,
        })
    }

    fn transaction_receipt(
        &self,
        meta: Self::Metadata,
        tx_hash: Hex<H256>,
    ) -> Result<Option<RPCReceipt>, Error> {
        let receipt = meta
            .blockstore
            .find_evm_transaction(tx_hash.0)
            .map_err(anyhow::Error::from)
            .with_context(|| error::NativeRpcError {})?;

        Ok(match receipt {
            Some(receipt) => {
                let (block, _) = meta
                    .blockstore
                    .get_evm_block(receipt.block_number)
                    .map_err(|_| Error::BlockNotFound {
                        block: receipt.block_number,
                    })?;
                let block_hash = block.header.hash();
                Some(RPCReceipt::new_from_receipt(receipt, block_hash)?)
            }
            None => None,
        })
    }

    fn call(
        &self,
        meta: Self::Metadata,
        tx: RPCTransaction,
        block: Option<String>,
    ) -> Result<Bytes, Error> {
        let result = call(meta, tx, block)?;
        Ok(Bytes(result.1))
    }

    fn estimate_gas(
        &self,
        meta: Self::Metadata,
        tx: RPCTransaction,
        block: Option<String>,
    ) -> Result<Hex<Gas>, Error> {
        let result = call(meta, tx, block)?;
        Ok(Hex(result.2.into()))
    }

    fn logs(&self, meta: Self::Metadata, log_filter: RPCLogFilter) -> Result<Vec<RPCLog>, Error> {
        let bank = meta.bank(None);

        let evm_lock = bank.evm_state.read().expect("Evm lock poisoned");
        let block_num = evm_lock.block_number();
        let to = block_to_confirmed_num(log_filter.to_block.as_ref(), &meta).unwrap_or(block_num);
        let from =
            block_to_confirmed_num(log_filter.from_block.as_ref(), &meta).unwrap_or(block_num);

        let filter = LogFilter {
            address: log_filter.address.map(|k| k.0),
            topics: log_filter
                .topics
                .into_iter()
                .flatten()
                .map(RPCTopicFilter::to_topics)
                .collect(),
            from_block: from,
            to_block: to,
        };
        warn!("filter = {:?}", filter);
        let logs = meta
            .blockstore
            .filter_logs(filter)
            .map_err(|e| {
                warn!("filter_logs = {:?}", e);
                e
            })
            .map_err(anyhow::Error::from)
            .with_context(|| error::NativeRpcError {})?;
        Ok(logs.into_iter().map(|l| l.into()).collect())
    }
}

fn call(
    meta: JsonRpcRequestProcessor,
    tx: RPCTransaction,
    _block: Option<String>,
) -> Result<(evm_state::ExitReason, Vec<u8>, u64), Error> {
    let caller = tx.from.map(|a| a.0).unwrap_or_default();

    let value = tx.value.map(|a| a.0).unwrap_or_else(|| 0.into());
    let input = tx.data.map(|a| a.0).unwrap_or_else(Vec::new);
    let gas_limit = tx.gas.map(|a| a.0).unwrap_or_else(|| 300000000.into());
    let gas_limit: u64 = gas_limit
        .try_into()
        .map_err(|e: &str| Error::BigIntTrimFailed {
            input_data: gas_limit.to_string(),
            error: e.to_string(),
        })?;

    let bank = meta.bank(DEFAULT_COMITTMENT);
    let evm_state = bank
        .evm_state
        .read()
        .expect("meta bank EVM state was poisoned");

    let evm_state = evm_state.clone();
    let evm_state = match evm_state.new_from_parent(0) {
        // TODO get timestamp from bank
        evm_state::EvmState::Incomming(i) => i,
        evm_state::EvmState::Committed(_) => unreachable!(),
    };
    let mut estimate_config = evm_state::EvmConfig::default();
    estimate_config.estimate = true;
    let mut executor = evm_state::Executor::with_config(
        evm_state,
        Default::default(), // TODO replace by chain_id getter from bank.
        estimate_config,
    );

    let result = if let Some(address) = tx.to {
        let address = address.0;
        debug!(
            "Trying to execute tx = {:?}",
            (caller, address, value, &input, gas_limit)
        );
        executor.with_executor(|e| e.transact_call(caller, address, value, input, gas_limit))
    } else {
        executor.with_executor(|e| (e.transact_create(caller, value, input, gas_limit), vec![]))
    };

    let gas_used = executor.deconstruct().state.used_gas;
    Ok((result.0, result.1, gas_used))
}
