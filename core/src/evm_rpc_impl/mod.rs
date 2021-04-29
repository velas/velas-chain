use std::convert::TryInto;

use sha3::{Digest, Keccak256};
use solana_sdk::commitment_config::{CommitmentConfig, CommitmentLevel};

use evm_rpc::{
    basic::BasicERPC,
    chain_mock::ChainMockERPC,
    error::{Error, IntoNativeRpcError},
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
) -> (Arc<Bank>, H256) {
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
        meta.get_evm_block_by_id(block_num)
            .map(|(b, _)| b.header.state_root)
            .unwrap_or_else(|| lock.last_root())
    };
    (bank, last_root)
}

fn block_to_confirmed_num(
    block: Option<impl AsRef<str>>,
    meta: &JsonRpcRequestProcessor,
) -> Option<u64> {
    let block = block?;
    match block.as_ref() {
        "earliest" => Some(meta.get_frist_available_evm_block()),
        "pending" | "latest" => Some(meta.get_last_available_evm_block().unwrap_or_else(|| {
            let bank = meta.bank(Some(CommitmentConfig::processed()));
            let evm = bank.evm_state.read().unwrap();
            evm.block_number().saturating_sub(1)
        })),
        v => Hex::<u64>::from_hex(&v).ok().map(|f| f.0),
    }
}

pub struct ChainMockErpcImpl;
impl ChainMockERPC for ChainMockErpcImpl {
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
        meta: Self::Metadata,
        block_hash: Hex<H256>,
        full: bool,
    ) -> Result<Option<RPCBlock>, Error> {
        debug!("Requested hash = {:?}", block_hash.0);
        let block = match meta.get_evm_block_id_by_hash(block_hash.0) {
            None => {
                error!("Not found block for hash:{}", block_hash);
                return Ok(None);
            }
            Some(b) => b,
        };
        debug!("Found block = {:?}", block);

        self.block_by_number(meta, format!("{:#x}", block), full)
    }

    fn block_by_number(
        &self,
        meta: Self::Metadata,
        block: String,
        full: bool,
    ) -> Result<Option<RPCBlock>, Error> {
        let num = block_to_confirmed_num(Some(&block), &meta);
        // TODO: Inline evm_state lookups, and request only solana headers.
        let (block, confirmed) = match num.and_then(|block_num| meta.get_evm_block_by_id(block_num))
        {
            None => {
                error!("Error requesting block:{} ({:?}) not found", block, num);
                return Ok(None);
            }
            Some(b) => b,
        };

        let bank = meta.bank(None);
        let chain_id = bank.evm_chain_id;

        let block_hash = block.header.hash();
        let transactions = if full {
            let txs = block
                .transactions
                .into_iter()
                .filter_map(|(hash, receipt)| {
                    RPCTransaction::new_from_receipt(receipt, hash, block_hash, chain_id).ok()
                })
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

        Ok(Some(RPCBlock::new_from_head(
            block.header,
            confirmed,
            transactions,
        )))
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

pub struct BasicErpcImpl;
impl BasicERPC for BasicErpcImpl {
    type Metadata = JsonRpcRequestProcessor;

    fn block_number(&self, meta: Self::Metadata) -> Result<Hex<usize>, Error> {
        let block = block_to_confirmed_num(Some("latest"), &meta).unwrap_or(0);
        Ok(Hex(block as usize))
    }

    fn balance(
        &self,
        meta: Self::Metadata,
        address: Hex<Address>,
        block: Option<String>,
    ) -> Result<Hex<U256>, Error> {
        let (bank, root) = block_to_bank_and_root(block, &meta);
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
        let (bank, root) = block_to_bank_and_root(block, &meta);
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
        let (bank, root) = block_to_bank_and_root(block, &meta);
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
        let (bank, root) = block_to_bank_and_root(block, &meta);
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
        let bank = meta.bank(None);
        let chain_id = bank.evm_chain_id;
        let receipt = meta.get_evm_receipt_by_hash(tx_hash.0);

        Ok(match receipt {
            Some(receipt) => {
                let (block, _) = meta.get_evm_block_by_id(receipt.block_number).ok_or({
                    Error::BlockNotFound {
                        block: receipt.block_number,
                    }
                })?;
                let block_hash = block.header.hash();
                Some(RPCTransaction::new_from_receipt(
                    receipt, tx_hash.0, block_hash, chain_id,
                )?)
            }
            None => None,
        })
    }

    fn transaction_receipt(
        &self,
        meta: Self::Metadata,
        tx_hash: Hex<H256>,
    ) -> Result<Option<RPCReceipt>, Error> {
        let receipt = meta.get_evm_receipt_by_hash(tx_hash.0);
        Ok(match receipt {
            Some(receipt) => {
                let (block, _) = meta.get_evm_block_by_id(receipt.block_number).ok_or({
                    Error::BlockNotFound {
                        block: receipt.block_number,
                    }
                })?;
                let block_hash = block.header.hash();
                Some(RPCReceipt::new_from_receipt(
                    receipt, tx_hash.0, block_hash,
                )?)
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
        const MAX_NUM_BLOCKS: u64 = 1000;
        let bank = meta.bank(None);

        let evm_lock = bank.evm_state.read().expect("Evm lock poisoned");
        let block_num = evm_lock.block_number();
        let mut to =
            block_to_confirmed_num(log_filter.to_block.as_ref(), &meta).unwrap_or(block_num);
        let from =
            block_to_confirmed_num(log_filter.from_block.as_ref(), &meta).unwrap_or(block_num);
        if to > from + MAX_NUM_BLOCKS {
            warn!(
                "Log filter, block range is too big, reducing, to={}, from={}",
                to, from
            );
            to = from + MAX_NUM_BLOCKS
        }

        let filter = LogFilter {
            address: log_filter.address.map(|k| k.0),
            topics: log_filter
                .topics
                .into_iter()
                .flatten()
                .map(RPCTopicFilter::into_topics)
                .collect(),
            from_block: from,
            to_block: to,
        };
        debug!("filter = {:?}", filter);

        let logs = meta
            .blockstore
            .filter_logs(filter)
            .map_err(|e| {
                debug!("filter_logs error = {:?}", e);
                e
            })
            .into_native_error()?;
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
    let input = tx.input.map(|a| a.0).unwrap_or_else(Vec::new);
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
    let estimate_config = evm_state::EvmConfig {
        estimate: true,
        ..Default::default()
    };

    let last_hashes = bank.evm_hashes();
    let mut executor = evm_state::Executor::with_config(
        evm_state,
        evm_state::ChainContext::new(last_hashes),
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
