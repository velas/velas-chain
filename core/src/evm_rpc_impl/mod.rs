#![allow(clippy::upper_case_acronyms)]

use std::convert::TryInto;
use std::str::FromStr;

use sha3::{Digest, Keccak256};
use snafu::ResultExt;
use solana_sdk::commitment_config::{CommitmentConfig, CommitmentLevel};
use solana_transaction_status::UiTransactionEncoding;

use evm_rpc::{
    basic::BasicERPC,
    chain_mock::ChainMockERPC,
    error::{self, Error},
    Bytes, Either, Hex, RPCBlock, RPCLog, RPCLogFilter, RPCReceipt, RPCTransaction,
};
use evm_state::{Address, BlockMeta, Config, Gas, LogFilter, H256, U256};

use crate::rpc::JsonRpcRequestProcessor;

const DEFAULT_COMITTMENT: Option<CommitmentConfig> = Some(CommitmentConfig {
    commitment: CommitmentLevel::Processed,
});

fn block_to_commitment(block: Option<String>) -> Option<CommitmentConfig> {
    let commitment = match block?.as_ref() {
        "earliest" => CommitmentLevel::Finalized,
        "latest" => CommitmentLevel::Confirmed,
        "pending" => CommitmentLevel::Confirmed,
        v => {
            // Try to parse newest version of block commitment.
            if let Ok(c) = serde_json::from_str::<CommitmentLevel>(v) {
                c
            } else {
                // Probably user provide specific slot number, we didn't support bank from future, so just return default.
                return None;
            }
        }
    };
    Some(CommitmentConfig { commitment })
}

fn block_to_confirmed_num(
    block: Option<impl AsRef<str>>,
    meta: &JsonRpcRequestProcessor,
) -> Option<u64> {
    let block = block?;
    match block.as_ref() {
        "pending" => None,
        "earliest" => Some(meta.get_first_available_block()),
        "latest" => Some(meta.get_slot(None)),
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
        Ok(String::from("velas-chain/v0.1.0"))
    }

    fn protocol_version(&self, _meta: Self::Metadata) -> Result<String, Error> {
        Ok(String::from("0"))
    }

    fn is_syncing(&self, _meta: Self::Metadata) -> Result<bool, Error> {
        Ok(false)
    }

    fn coinbase(&self, _meta: Self::Metadata) -> Result<Hex<Address>, Error> {
        Ok(Hex(Address::from_low_u64_be(0)))
    }

    fn is_mining(&self, _meta: Self::Metadata) -> Result<bool, Error> {
        Ok(false)
    }

    fn hashrate(&self, _meta: Self::Metadata) -> Result<String, Error> {
        Ok(String::from("0x00"))
    }

    fn block_by_hash(
        &self,
        _meta: Self::Metadata,
        _block_hash: Hex<H256>,
        _full: bool,
    ) -> Result<Option<RPCBlock>, Error> {
        Ok(Some(RPCBlock {
            number: U256::zero().into(),
            hash: H256::zero().into(),
            parent_hash: H256::zero().into(),
            size: 0x100.into(),
            gas_limit: Gas::zero().into(),
            gas_used: Gas::zero().into(),
            timestamp: 0.into(),
            transactions: Either::Left(vec![]),
            nonce: 0.into(),
            sha3_uncles: H256::zero().into(),
            logs_bloom: H256::zero().into(), // H2048
            transactions_root: H256::zero().into(),
            state_root: H256::zero().into(),
            receipts_root: H256::zero().into(),
            miner: Address::zero().into(),
            difficulty: U256::zero().into(),
            total_difficulty: U256::zero().into(),
            extra_data: b"Native chain data ommitted...".to_vec().into(),
            uncles: vec![],
        }))
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
        if block_num == 0 {
            return Ok(None);
        }
        let block = match meta
            .get_confirmed_block(block_num, UiTransactionEncoding::Binary.into())
            .with_context(|| error::ProxyRpcError {})?
        {
            Some(block) => block,
            None => return Ok(None),
        };

        let block_hash = solana_sdk::hash::Hash::from_str(&block.blockhash).unwrap();
        let block_hash = H256::from_slice(&block_hash.0);
        let parent_hash = solana_sdk::hash::Hash::from_str(&block.previous_blockhash).unwrap();
        let bank = meta.bank(None);
        let evm_lock = bank.evm_state.read().expect("Evm lock poisoned");
        let tx_hashes = evm_lock
            .get_block_meta(block_num)
            .map(|BlockMeta { transactions, .. }| transactions);
        let transactions = if full {
            let txs = tx_hashes
                .iter()
                .flatten()
                .map(|tx_hash| {
                    evm_lock
                        .get_transaction_receipt(*tx_hash)
                        .expect("Transaction exist")
                })
                .filter_map(|receipt| RPCTransaction::new_from_receipt(receipt, block_hash).ok())
                .collect();
            Either::Right(txs)
        } else {
            let txs = tx_hashes.into_iter().flatten().map(Hex).collect();
            Either::Left(txs)
        };
        drop(evm_lock);

        let result = RPCBlock {
            number: U256::from(block_num).into(),
            hash: H256::from_slice(&block_hash.0).into(),
            parent_hash: H256::from_slice(&parent_hash.0).into(),
            size: 0x100.into(),
            gas_limit: Hex(0x10000.into()),
            gas_used: Gas::zero().into(),
            timestamp: Hex(block.block_time.unwrap_or(0) as u64),
            transactions,

            nonce: 0x7bb9369dcbaec019.into(),
            sha3_uncles: H256::zero().into(),
            logs_bloom: H256::zero().into(), // H2048
            transactions_root: H256::zero().into(),
            state_root: H256::zero().into(),
            receipts_root: H256::zero().into(),
            miner: Address::zero().into(),
            difficulty: U256::zero().into(),
            total_difficulty: U256::zero().into(),
            extra_data: b"Native chain data ommitted...".to_vec().into(),
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
        let bank = meta.bank(None);
        Ok(Hex(bank.slot() as usize))
    }

    fn balance(
        &self,
        meta: Self::Metadata,
        address: Hex<Address>,
        block: Option<String>,
    ) -> Result<Hex<U256>, Error> {
        let bank = meta.bank(block_to_commitment(block));
        let evm_state = bank.evm_state.read().unwrap();
        let account = evm_state.get_account_state(address.0).unwrap_or_default();
        Ok(Hex(account.balance))
    }

    fn storage_at(
        &self,
        meta: Self::Metadata,
        address: Hex<Address>,
        data: Hex<H256>,
        block: Option<String>,
    ) -> Result<Hex<H256>, Error> {
        let bank = meta.bank(block_to_commitment(block));
        let evm_state = bank.evm_state.read().unwrap();
        Ok(Hex(evm_state
            .get_storage(address.0, data.0)
            .unwrap_or_default()))
    }

    fn transaction_count(
        &self,
        meta: Self::Metadata,
        address: Hex<Address>,
        block: Option<String>,
    ) -> Result<Hex<U256>, Error> {
        let bank = meta.bank(block_to_commitment(block));
        let evm_state = bank.evm_state.read().unwrap();
        let account = evm_state.get_account_state(address.0).unwrap_or_default();
        Ok(Hex(account.nonce))
    }

    fn code(
        &self,
        meta: Self::Metadata,
        address: Hex<Address>,
        block: Option<String>,
    ) -> Result<Bytes, Error> {
        let bank = meta.bank(block_to_commitment(block));
        let evm_state = bank.evm_state.read().unwrap();
        let account = evm_state.get_account_state(address.0).unwrap_or_default();
        Ok(Bytes(account.code.into()))
    }

    fn transaction_by_hash(
        &self,
        meta: Self::Metadata,
        tx_hash: Hex<H256>,
    ) -> Result<Option<RPCTransaction>, Error> {
        let bank = meta.bank(CommitmentConfig::processed().into());
        let evm_state = bank.evm_state.read().unwrap();
        let receipt = evm_state.get_transaction_receipt(tx_hash.0);

        Ok(match receipt {
            Some(receipt) => {
                let block_hash = meta
                    .get_confirmed_block_hash(receipt.block_number)
                    .with_context(|| error::ProxyRpcError {})?;
                let block_hash = block_hash.ok_or(Error::BlockNotFound {
                    block: receipt.block_number,
                })?;
                let block_hash = solana_sdk::hash::Hash::from_str(&block_hash).unwrap();
                let block_hash = H256::from_slice(&block_hash.0);

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
        let bank = meta.bank(CommitmentConfig::processed().into());
        let evm_state = bank.evm_state.read().unwrap();
        let receipt = evm_state.get_transaction_receipt(tx_hash.0);

        Ok(match receipt {
            Some(receipt) => {
                let block_hash = meta
                    .get_confirmed_block_hash(receipt.block_number)
                    .with_context(|| error::ProxyRpcError {})?;
                let block_hash = block_hash.ok_or(Error::BlockNotFound {
                    block: receipt.block_number,
                })?;
                let block_hash = solana_sdk::hash::Hash::from_str(&block_hash).unwrap();
                let block_hash = H256::from_slice(&block_hash.0);
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
        let slot = bank.slot();

        let evm_lock = bank.evm_state.read().expect("Evm lock poisoned");
        let to = block_to_confirmed_num(log_filter.to_block.as_ref(), &meta).unwrap_or(slot);
        let from = block_to_confirmed_num(log_filter.from_block.as_ref(), &meta).unwrap_or(slot);

        let filter = LogFilter {
            address: log_filter.address.map(|k| k.0),
            topics: vec![],
            from_block: from,
            to_block: to,
        };

        Ok(evm_lock
            .get_logs(filter)
            .into_iter()
            .map(|l| l.into())
            .collect())
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
    let estimate_config = Config {
        estimate: true,
        ..Config::istanbul()
    };

    let mut executor = evm_state::Executor::with_config(
        evm_state,
        estimate_config,
        gas_limit,
        bank.evm_chain_id,
        bank.slot(),
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

    let gas_used = executor.used_gas();
    Ok((result.0, result.1, gas_used))
}
