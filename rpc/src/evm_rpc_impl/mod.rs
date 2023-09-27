use std::str::FromStr;

use sha3::{Digest, Keccak256};
use solana_evm_loader_program::processor::BURN_ADDR;
use solana_sdk::account::{AccountSharedData, ReadableAccount};
use solana_sdk::commitment_config::CommitmentConfig;
use solana_sdk::keyed_account::KeyedAccount;
use solana_sdk::pubkey::Pubkey;

use crate::rpc::JsonRpcRequestProcessor;
use crate::rpc_health::RpcHealthStatus;
use evm_rpc::error::EvmStateError;
use evm_rpc::{
    chain::ChainERPC,
    error::{into_native_error, BlockNotFound, Error, StateNotFoundForBlock},
    general::GeneralERPC,
    trace::{TraceERPC, TraceMeta},
    BlockId, BlockRelId, Bytes, Either, Hex, RPCBlock, RPCLog, RPCLogFilter, RPCReceipt,
    RPCTopicFilter, RPCTransaction,
};
use evm_state::{
    AccountProvider, AccountState, Address, Block, BlockHeader, Committed, ExecutionResult, Gas,
    LogFilter, Transaction, TransactionAction, TransactionInReceipt, TransactionReceipt,
    TransactionSignature, UnsignedTransactionWithCaller, H160, H256, U256,
};
use jsonrpc_core::BoxFuture;
use snafu::ensure;
use snafu::ResultExt;
use solana_runtime::bank::Bank;
use std::{cell::RefCell, future::ready, sync::Arc};

const GAS_PRICE: u64 = 3;

use tracing_attributes::instrument;

#[derive(Debug)]
pub struct StateRootWithBank {
    pub state_root: Option<H256>,
    pub bank: Option<Arc<Bank>>,
    pub block: BlockId,
    pub block_timestamp: Option<u64>,
}

impl StateRootWithBank {
    pub fn get_account_state_at(
        &self,
        meta: &JsonRpcRequestProcessor,
        address: H160,
    ) -> Result<Option<AccountState>, Error> {
        ensure!(
            self.state_root.is_some(),
            BlockNotFound { block: self.block }
        );

        let root = *self.state_root.as_ref().unwrap();
        if let Some(bank) = &self.bank {
            let evm = bank.evm_state.read().unwrap();

            assert!(evm.last_root() == root, "we store bank with invalid root");
            return Ok(evm.get_account_state(address));
        }
        let archive_evm_state = meta
            .evm_state_archive(self.block_timestamp)
            .ok_or(Error::ArchiveNotSupported)?;
        ensure!(
            archive_evm_state.kvs().check_root_exist(root),
            StateNotFoundForBlock { block: self.block }
        );
        Ok(archive_evm_state
            .get_account_state_at(root, address)
            .unwrap_or_default())
    }

    pub fn get_storage_at(
        &self,
        meta: &JsonRpcRequestProcessor,
        address: H160,
        idx: H256,
    ) -> Result<Option<H256>, Error> {
        ensure!(
            self.state_root.is_some(),
            BlockNotFound { block: self.block }
        );

        let root = *self.state_root.as_ref().unwrap();
        if let Some(bank) = &self.bank {
            let evm = bank.evm_state.read().unwrap();

            assert!(evm.last_root() == root, "we store bank with invalid root");
            return Ok(evm.get_storage(address, idx));
        }
        let archive_evm_state = meta
            .evm_state_archive(self.block_timestamp)
            .ok_or(Error::ArchiveNotSupported)?;
        ensure!(
            archive_evm_state.kvs().check_root_exist(root),
            StateNotFoundForBlock { block: self.block }
        );
        Ok(archive_evm_state
            .get_storage_at(root, address, idx)
            .unwrap_or_default())
    }
}

#[instrument(skip(meta))]
async fn block_to_state_root(
    block: Option<BlockId>,
    meta: &JsonRpcRequestProcessor,
) -> StateRootWithBank {
    let block_id = block.unwrap_or_default();

    let mut found_block_hash = None;

    let block_num = match block_id {
        BlockId::RelativeId(BlockRelId::Pending) | BlockId::RelativeId(BlockRelId::Latest) => {
            let bank = meta.bank(Some(CommitmentConfig::processed()));
            let evm = bank.evm_state.read().unwrap();
            let last_root = evm.last_root();
            drop(evm);
            return StateRootWithBank {
                state_root: Some(last_root),
                bank: Some(bank),
                block: block_id,
                block_timestamp: None,
            };
        }
        BlockId::RelativeId(BlockRelId::Earliest) | BlockId::Num(Hex(0)) => {
            meta.get_first_available_evm_block().await
        }
        BlockId::Num(num) => num.0,
        BlockId::BlockHash { block_hash } => {
            found_block_hash = Some(block_hash);
            if let Some(num) = meta.get_evm_block_id_by_hash(block_hash).await {
                num
            } else {
                return StateRootWithBank {
                    state_root: None,
                    bank: None,
                    block: block_id,
                    block_timestamp: None,
                };
            }
        }
    };
    StateRootWithBank {
        state_root: meta
            .get_evm_block_by_id(block_num) // TODO: don't request full block.
            .await
            .filter(|(b, _)| {
                // if requested specific block hash, check that block with this hash is not in reorged fork
                found_block_hash
                    .map(|block_hash| b.header.hash() == block_hash)
                    .unwrap_or(true)
            })
            .map(|(b, _)| b.header.state_root),

        bank: None,
        block: block_id,
        block_timestamp: meta
            .get_evm_block_by_id(block_num)
            .await
            .map(|(block, _)| block.header.timestamp),
    }
}

#[instrument(skip(meta))]
async fn block_parse_confirmed_num(
    block: Option<BlockId>,
    meta: &JsonRpcRequestProcessor,
) -> Option<u64> {
    let block = block.unwrap_or_default();
    match block {
        BlockId::BlockHash { .. } => None,
        BlockId::RelativeId(BlockRelId::Earliest) => {
            Some(meta.get_first_available_evm_block().await)
        }
        BlockId::RelativeId(BlockRelId::Pending) | BlockId::RelativeId(BlockRelId::Latest) => {
            Some(meta.get_last_confirmed_evm_block().unwrap_or_else(|| {
                let bank = meta.bank(Some(CommitmentConfig::processed()));
                let evm = bank.evm_state.read().unwrap();
                evm.block_number().saturating_sub(1)
            }))
        }

        BlockId::Num(num) => Some(num.0),
    }
}

pub struct GeneralErpcImpl;
impl GeneralERPC for GeneralErpcImpl {
    type Metadata = Arc<JsonRpcRequestProcessor>;

    fn client_version(&self, _meta: Self::Metadata) -> Result<String, Error> {
        // same as `version` at /version/Cargo.toml
        Ok(format!(
            "velas-chain/v{}",
            solana_version::semver!().to_string()
        ))
    }

    fn sha3(&self, _meta: Self::Metadata, bytes: Bytes) -> Result<H256, Error> {
        // TODO: try `Ok(H256(Keccak256::digest(&bytes.0).try_into().unwrap()))`
        Ok(H256::from_slice(
            Keccak256::digest(bytes.0.as_slice()).as_slice(),
        ))
    }

    fn network_id(&self, meta: Self::Metadata) -> Result<String, Error> {
        let bank = meta.bank(None);
        Ok(format!("{}", bank.evm_chain_id))
    }

    // TODO: Add network info
    fn is_listening(&self, _meta: Self::Metadata) -> Result<bool, Error> {
        Ok(true)
    }

    fn peer_count(&self, _meta: Self::Metadata) -> Result<Hex<usize>, Error> {
        Ok(Hex(0))
    }

    fn chain_id(&self, meta: Self::Metadata) -> Result<Hex<u64>, Error> {
        let bank = meta.bank(None);
        Ok(Hex(bank.evm_chain_id))
    }

    fn protocol_version(&self, _meta: Self::Metadata) -> Result<String, Error> {
        Ok(solana_version::semver!().into())
    }

    fn is_syncing(&self, meta: Self::Metadata) -> Result<bool, Error> {
        Ok(!matches!(meta.get_health(), RpcHealthStatus::Ok))
    }

    fn coinbase(&self, _meta: Self::Metadata) -> Result<Address, Error> {
        Ok(Address::from_low_u64_be(0))
    }

    fn is_mining(&self, _meta: Self::Metadata) -> Result<bool, Error> {
        Ok(false)
    }

    fn hashrate(&self, _meta: Self::Metadata) -> Result<U256, Error> {
        Ok(0.into())
    }

    fn gas_price(&self, _meta: Self::Metadata) -> Result<Gas, Error> {
        Ok(solana_evm_loader_program::scope::evm::lamports_to_gwei(
            GAS_PRICE,
        ))
    }
}

pub struct ChainErpcImpl;
impl ChainERPC for ChainErpcImpl {
    type Metadata = Arc<JsonRpcRequestProcessor>;

    #[instrument(skip(self, meta))]
    fn block_number(&self, meta: Self::Metadata) -> BoxFuture<Result<Hex<usize>, Error>> {
        Box::pin(async move {
            let block = block_parse_confirmed_num(None, &meta).await.unwrap_or(0);
            Ok(Hex(block as usize))
        })
    }

    #[instrument(skip(self, meta))]
    fn balance(
        &self,
        meta: Self::Metadata,
        address: Address,
        block: Option<BlockId>,
    ) -> BoxFuture<Result<U256, Error>> {
        Box::pin(async move {
            let state = block_to_state_root(block, &meta).await;

            let account = state
                .get_account_state_at(&meta, address)?
                .unwrap_or_default();
            Ok(account.balance)
        })
    }

    #[instrument(skip(self, meta))]
    fn storage_at(
        &self,
        meta: Self::Metadata,
        address: Address,
        data: U256,
        block: Option<BlockId>,
    ) -> BoxFuture<Result<H256, Error>> {
        Box::pin(async move {
            let state = block_to_state_root(block, &meta).await;
            let mut bytes = [0u8; 32];
            data.to_big_endian(&mut bytes);
            let storage = state
                .get_storage_at(&meta, address, H256::from_slice(&bytes))?
                .unwrap_or_default();
            Ok(storage)
        })
    }

    #[instrument(skip(self, meta))]
    fn transaction_count(
        &self,
        meta: Self::Metadata,
        address: Address,
        block: Option<BlockId>,
    ) -> BoxFuture<Result<U256, Error>> {
        Box::pin(async move {
            let state = block_to_state_root(block, &meta).await;

            let account = state
                .get_account_state_at(&meta, address)?
                .unwrap_or_default();
            Ok(account.nonce)
        })
    }

    #[instrument(skip(self, meta))]
    fn block_transaction_count_by_number(
        &self,
        meta: Self::Metadata,
        block: BlockId,
    ) -> BoxFuture<Result<Hex<usize>, Error>> {
        Box::pin(async move {
            let (evm_block, _) = match block_parse_confirmed_num(Some(block), &meta).await {
                Some(num) => meta.get_evm_block_by_id(num).await,
                None => None,
            }
            .ok_or(Error::BlockNotFound { block })?;
            Ok(Hex(evm_block.transactions.len()))
        })
    }

    #[instrument(skip(self, meta))]
    fn block_transaction_count_by_hash(
        &self,
        meta: Self::Metadata,
        block_hash: H256,
    ) -> BoxFuture<Result<Hex<usize>, Error>> {
        Box::pin(async move {
            let (evm_block, _) = match meta.get_evm_block_id_by_hash(block_hash).await {
                Some(num) => meta.get_evm_block_by_id(num).await,
                None => None,
            }
            .ok_or(Error::BlockNotFound {
                block: BlockId::BlockHash { block_hash },
            })?;
            Ok(Hex(evm_block.transactions.len()))
        })
    }

    #[instrument(skip(self, meta))]
    fn code(
        &self,
        meta: Self::Metadata,
        address: Address,
        block: Option<BlockId>,
    ) -> BoxFuture<Result<Bytes, Error>> {
        Box::pin(async move {
            let state = block_to_state_root(block, &meta).await;

            let account = state
                .get_account_state_at(&meta, address)?
                .unwrap_or_default();
            Ok(Bytes(account.code.into()))
        })
    }

    #[instrument(skip(self, meta))]
    fn block_by_hash(
        &self,
        meta: Self::Metadata,
        block_hash: H256,
        full: bool,
    ) -> BoxFuture<Result<Option<RPCBlock>, Error>> {
        debug!("Requested hash = {:?}", block_hash);
        Box::pin(async move {
            let block = match meta.get_evm_block_id_by_hash(block_hash).await {
                None => {
                    error!("Not found block for hash:{}", block_hash);
                    return Ok(None);
                }
                Some(b) => match meta.get_evm_block_by_id(b).await {
                    // check that found block only in valid fork.
                    Some((block, _above_our_chain)) if block.header.hash() == block_hash => b,
                    _ => return Ok(None),
                },
            };
            debug!("Found block = {:?}", block);

            block_by_number(meta, block.into(), full).await
        })
    }

    #[instrument(skip(self, meta))]
    fn block_by_number(
        &self,
        meta: Self::Metadata,
        block: BlockId,
        full: bool,
    ) -> BoxFuture<Result<Option<RPCBlock>, Error>> {
        Box::pin(block_by_number(meta, block, full))
    }

    #[instrument(skip(self, meta))]
    fn transaction_by_hash(
        &self,
        meta: Self::Metadata,
        tx_hash: H256,
    ) -> BoxFuture<Result<Option<RPCTransaction>, Error>> {
        Box::pin(transaction_by_hash(meta, tx_hash))
    }

    #[instrument(skip(self, meta))]
    fn transaction_by_block_hash_and_index(
        &self,
        meta: Self::Metadata,
        block_hash: H256,
        tx_id: Hex<usize>,
    ) -> BoxFuture<Result<Option<RPCTransaction>, Error>> {
        let bank = meta.bank(None);
        let chain_id = bank.evm_chain_id;
        Box::pin(async move {
            let (evm_block, _) = match meta.get_evm_block_id_by_hash(block_hash).await {
                Some(num) => meta.get_evm_block_by_id(num).await,
                None => None,
            }
            .ok_or(Error::BlockNotFound {
                block: BlockId::BlockHash { block_hash },
            })?;
            match evm_block.transactions.get(tx_id.0) {
                Some((hash, receipt)) => Ok(Some(RPCTransaction::new_from_receipt(
                    receipt.clone(),
                    *hash,
                    evm_block.header.hash(),
                    chain_id,
                )?)),
                None => Ok(None),
            }
        })
    }

    #[instrument(skip(self, meta))]
    fn transaction_by_block_number_and_index(
        &self,
        meta: Self::Metadata,
        block: BlockId,
        tx_id: Hex<usize>,
    ) -> BoxFuture<Result<Option<RPCTransaction>, Error>> {
        let bank = meta.bank(None);
        let chain_id = bank.evm_chain_id;
        Box::pin(async move {
            let (evm_block, _) = match block_parse_confirmed_num(Some(block), &meta).await {
                Some(num) => meta.get_evm_block_by_id(num).await,
                None => None,
            }
            .ok_or(Error::BlockNotFound { block })?;
            match evm_block.transactions.get(tx_id.0) {
                Some((hash, receipt)) => Ok(Some(RPCTransaction::new_from_receipt(
                    receipt.clone(),
                    *hash,
                    evm_block.header.hash(),
                    chain_id,
                )?)),
                None => Ok(None),
            }
        })
    }

    #[instrument(skip(self, meta))]
    fn transaction_receipt(
        &self,
        meta: Self::Metadata,
        tx_hash: H256,
    ) -> BoxFuture<Result<Option<RPCReceipt>, Error>> {
        Box::pin(async move {
            Ok(match meta.get_evm_receipt_by_hash(tx_hash).await {
                Some(receipt) => {
                    let (block, _) =
                        meta.get_evm_block_by_id(receipt.block_number)
                            .await
                            .ok_or({
                                Error::BlockNotFound {
                                    block: receipt.block_number.into(),
                                }
                            })?;
                    let block_hash = block.header.hash();
                    Some(RPCReceipt::new_from_receipt(
                        receipt, tx_hash, block_hash, None,
                    )?)
                }
                None => None,
            })
        })
    }

    #[instrument(skip(self, meta))]
    fn call(
        &self,
        meta: Self::Metadata,
        tx: RPCTransaction,
        block: Option<BlockId>,
        meta_keys: Option<Vec<String>>,
    ) -> BoxFuture<Result<Bytes, Error>> {
        let meta_keys = match meta_keys
            .into_iter()
            .flatten()
            .map(|s| solana_sdk::pubkey::Pubkey::from_str(&s))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| into_native_error(e, false))
        {
            Ok(keys) => keys,
            Err(err) => return Box::pin(ready(Err(err))),
        };
        Box::pin(async move {
            let saved_state = block_to_state_root(block, &meta).await;

            let result = call(meta, tx, saved_state, meta_keys)?;
            Ok(Bytes(result.exit_data))
        })
    }

    #[instrument(skip(self, meta))]
    fn estimate_gas(
        &self,
        meta: Self::Metadata,
        tx: RPCTransaction,
        block: Option<BlockId>,
        meta_keys: Option<Vec<String>>,
    ) -> BoxFuture<Result<Gas, Error>> {
        Box::pin(async move {
            let meta_keys = meta_keys
                .into_iter()
                .flatten()
                .map(|s| solana_sdk::pubkey::Pubkey::from_str(&s))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| into_native_error(e, false))?;
            let saved_state = block_to_state_root(block, &meta).await;
            let result = call(meta, tx, saved_state, meta_keys)?;
            Ok(result.used_gas.into())
        })
    }

    #[instrument(skip(self, meta))]
    fn logs(
        &self,
        meta: Self::Metadata,
        log_filter: RPCLogFilter,
    ) -> BoxFuture<Result<Vec<RPCLog>, Error>> {
        Box::pin(async move {
            const MAX_NUM_BLOCKS: u64 = 2000;
            let block_num = meta
                .get_last_available_evm_block()
                .ok_or(Error::ArchiveNotSupported)?;
            let to = block_parse_confirmed_num(log_filter.to_block, &meta)
                .await
                .unwrap_or(block_num);
            let from = block_parse_confirmed_num(log_filter.from_block, &meta)
                .await
                .unwrap_or(block_num);
            if to > from + MAX_NUM_BLOCKS {
                warn!(
                    "Log filter, block range is too big, reducing, to={}, from={}",
                    to, from
                );
                return Err(Error::InvalidBlocksRange {
                    starting: from,
                    ending: to,
                    batch_size: Some(MAX_NUM_BLOCKS),
                });
            }

            let filter = LogFilter {
                address: log_filter
                    .address
                    .map(|k| match k {
                        Either::Left(v) => v,
                        Either::Right(k) => vec![k],
                    })
                    .unwrap_or_default(),
                topics: log_filter
                    .topics
                    .unwrap_or_else(|| vec![None])
                    .into_iter()
                    .map(RPCTopicFilter::into_topics)
                    .collect(),
                from_block: from,
                to_block: to,
            };
            debug!("filter = {:?}", filter);

            let logs = meta.filter_logs(filter).await.map_err(|e| {
                debug!("filter_logs error = {:?}", e);
                into_native_error(e, false)
            })?;
            Ok(logs.into_iter().map(|l| l.into()).collect())
        })
    }

    fn uncle_by_block_hash_and_index(
        &self,
        _meta: Self::Metadata,
        _block_hash: H256,
        _uncle_id: U256,
    ) -> Result<Option<RPCBlock>, Error> {
        Ok(None)
    }

    fn uncle_by_block_number_and_index(
        &self,
        _meta: Self::Metadata,
        _block: String,
        _uncle_id: U256,
    ) -> Result<Option<RPCBlock>, Error> {
        Ok(None)
    }

    fn block_uncles_count_by_hash(
        &self,
        _meta: Self::Metadata,
        _block_hash: H256,
    ) -> Result<Hex<usize>, Error> {
        Ok(Hex(0))
    }

    fn block_uncles_count_by_number(
        &self,
        _meta: Self::Metadata,
        _block: String,
    ) -> Result<Hex<usize>, Error> {
        Ok(Hex(0))
    }
}

pub struct TraceErpcImpl;
impl TraceERPC for TraceErpcImpl {
    type Metadata = Arc<JsonRpcRequestProcessor>;

    #[instrument(skip(self, meta))]
    fn trace_call(
        &self,
        meta: Self::Metadata,
        tx: RPCTransaction,
        traces: Vec<String>, //TODO: check trace = ["trace"]
        block: Option<BlockId>,
        meta_info: Option<TraceMeta>,
    ) -> BoxFuture<Result<evm_rpc::trace::TraceResultsWithTransactionHash, Error>> {
        Box::pin(async move {
            Ok(
                trace_call_many(meta, vec![(tx, traces, meta_info)], block, true)
                    .await?
                    .into_iter()
                    .next()
                    .expect("One item should be returned"),
            )
        })
    }

    #[instrument(skip(self, meta))]
    fn trace_call_many(
        &self,
        meta: Self::Metadata,
        tx_traces: Vec<(RPCTransaction, Vec<String>, Option<TraceMeta>)>,
        block: Option<BlockId>,
    ) -> BoxFuture<Result<Vec<evm_rpc::trace::TraceResultsWithTransactionHash>, Error>> {
        Box::pin(trace_call_many(meta, tx_traces, block, true))
    }

    #[instrument(skip(self, meta))]
    fn trace_replay_transaction(
        &self,
        meta: Self::Metadata,
        tx_hash: H256,
        traces: Vec<String>,
        meta_info: Option<TraceMeta>,
    ) -> BoxFuture<Result<Option<evm_rpc::trace::TraceResultsWithTransactionHash>, Error>> {
        let meta_info = meta_info.unwrap_or_default();
        Box::pin(async move {
            match transaction_by_hash(meta.clone(), tx_hash).await {
                Ok(Some(tx)) => {
                    let (tx_block, tx_index) = match (tx.block_number, tx.transaction_index) {
                        (Some(block), Some(index)) => (block.as_u64(), index.0),
                        _ => return Ok(None),
                    };
                    let base_block = tx_block.saturating_sub(1).into();
                    let tx_traces = match meta.get_evm_block_by_id(tx_block).await {
                        Some((block, _)) => {
                            let block_hash = block.header.hash();
                            let chain_id = meta.bank(None).evm_chain_id;
                            block
                                .transactions
                                .into_iter()
                                .take(tx_index)
                                .filter_map(|(hash, receipt)| {
                                    let tx = RPCTransaction::new_from_receipt(
                                        receipt, hash, block_hash, chain_id,
                                    )
                                    .ok()?;
                                    let mut meta_info = meta_info.clone();
                                    meta_info.transaction_hash = tx.hash;
                                    meta_info.transaction_index = tx.transaction_index.map(|v| v.0);
                                    meta_info.block_number = tx.block_number;
                                    meta_info.block_hash = tx.block_hash;
                                    Some((tx, traces.clone(), Some(meta_info)))
                                })
                                .collect()
                        }
                        None => return Ok(None),
                    };

                    let traces = trace_call_many(meta, tx_traces, Some(base_block), false).await?;
                    Ok(traces.get(tx_index - 1).cloned())
                }
                Ok(None) => Ok(None),
                Err(e) => Err(e),
            }
        })
    }

    #[instrument(skip(self, meta))]
    fn trace_replay_block(
        &self,
        meta: Self::Metadata,
        block_num: BlockId,
        traces: Vec<String>,
        meta_info: Option<TraceMeta>,
    ) -> BoxFuture<Result<Vec<evm_rpc::trace::TraceResultsWithTransactionHash>, Error>> {
        Box::pin(async move {
            let block = if let Some(block) = block_by_number(meta.clone(), block_num, true).await? {
                block
            } else {
                return Err(Error::StateNotFoundForBlock { block: block_num });
            };
            let txs = match block.transactions {
                Either::Right(txs) => txs,
                _ => return Err(Error::Unimplemented {}),
            };
            let meta_info = meta_info.unwrap_or_default();
            let transactions = txs
                .into_iter()
                .map(|tx| {
                    let mut meta_info = meta_info.clone();
                    meta_info.transaction_hash = tx.hash;
                    meta_info.transaction_index = tx.transaction_index.map(|v| v.0);
                    meta_info.block_number = tx.block_number;
                    meta_info.block_hash = tx.block_hash;
                    (tx, traces.clone(), Some(meta_info))
                })
                .collect();
            // execute on pervious block
            trace_call_many(
                meta,
                transactions,
                Some(block.number.as_u64().saturating_sub(1).into()),
                false,
            )
            .await
        })
    }

    fn recover_block_header(
        &self,
        meta: Arc<JsonRpcRequestProcessor>,
        txs: Vec<(RPCTransaction, Vec<String>)>,
        last_hashes: Vec<H256>,
        block_header: BlockHeader,
        state_root: H256,
        unsigned_tx_fix: bool,
        clear_logs_on_error: bool,
        accept_zero_gas_price_with_native_fee: bool,
        burn_gas_price: u64,
    ) -> BoxFuture<Result<(Block, Vec<H256>), Error>> {
        fn simulate_transaction(
            executor: &mut evm_state::Executor,
            tx: RPCTransaction,
            meta_keys: Vec<solana_sdk::pubkey::Pubkey>,
        ) -> Result<ExecutionResult, Error> {
            use solana_evm_loader_program::precompiles::*;
            macro_rules! unwrap_or_default {
                ($tx:ident . $name: ident) => {
                    $tx.$name.unwrap_or_else(|| {
                        log::warn!("Unable to find {} in tx, using default", stringify!($name));
                        Default::default()
                    })
                };
            }
            let caller = unwrap_or_default!(tx.from);

            let value = unwrap_or_default!(tx.value);
            let input = unwrap_or_default!(tx.input).0;
            let gas_limit = unwrap_or_default!(tx.gas);
            let gas_price = unwrap_or_default!(tx.gas_price);

            let nonce = unwrap_or_default!(tx.nonce);
            let tx_chain_id = executor.chain_id();
            let tx_hash = unwrap_or_default!(tx.hash);

            let evm_state_balance = u64::MAX - 1;

            let (user_accounts, action) = if let Some(address) = tx.to {
                debug!(
                    "Trying to execute tx = {:?}",
                    (caller, address, value, &input, gas_limit)
                );

                let mut meta_keys: Vec<_> = meta_keys
                    .into_iter()
                    .map(|pk| {
                        let user_account = RefCell::new(AccountSharedData::new(
                            u64::MAX,
                            0,
                            &solana_sdk::system_program::id(),
                        ));
                        (user_account, pk)
                    })
                    .collect();

                // Shortcut for swap tokens to native, will add solana account to transaction.
                if address == *ETH_TO_VLX_ADDR {
                    debug!("Found transferToNative transaction");
                    match ETH_TO_VLX_CODE.parse_abi(&input) {
                        Ok(pk) => {
                            info!("Adding account to meta = {}", pk);

                            let user_account = RefCell::new(AccountSharedData::new(
                                u64::MAX,
                                0,
                                &solana_sdk::system_program::id(),
                            ));
                            meta_keys.push((user_account, pk))
                        }
                        Err(e) => {
                            error!("Error in parsing abi = {}", e);
                        }
                    }
                }

                (meta_keys, TransactionAction::Call(address))
            } else {
                (vec![], TransactionAction::Create)
            };

            // system transfers always set s = 0x1
            let mut is_native_tx = false;
            if Some(U256::from(0x1)) == tx.s {
                // check if it native swap, then predeposit, amount, to pass transaction
                if caller == *ETH_TO_VLX_ADDR {
                    let amount = value + gas_limit * gas_price;
                    executor.deposit(caller, amount)
                }
                is_native_tx = true;
            }

            let user_accounts: Vec<_> = user_accounts
                .iter()
                .map(|(user_account, pk)| KeyedAccount::new(pk, false, user_account))
                .collect();
            let evm_account = RefCell::new(solana_evm_loader_program::create_state_account(
                evm_state_balance,
            ));
            let evm_keyed_account =
                KeyedAccount::new(&solana_sdk::evm_state::ID, false, &evm_account);

            let result = executor
                .transaction_execute_raw(
                    caller,
                    nonce,
                    gas_price,
                    gas_limit,
                    action,
                    input.clone(),
                    value,
                    Some(tx_chain_id),
                    tx_hash,
                    true,
                    simulation_entrypoint(
                        PrecompileSet::VelasClassic,
                        &evm_keyed_account,
                        &user_accounts,
                    ),
                )
                .with_context(|_err| EvmStateError)?;

            let mut bytes: [u8; 32] = [0; 32];
            tx.r.ok_or(Error::InvalidParams {})?
                .to_big_endian(&mut bytes);
            let r = H256::from_slice(&bytes);
            tx.s.ok_or(Error::InvalidParams {})?
                .to_big_endian(&mut bytes);
            let s = H256::from_slice(&bytes);
            let transaction = Transaction {
                nonce,
                gas_price,
                gas_limit,
                action,
                value,
                signature: TransactionSignature {
                    v: *tx.v.ok_or(Error::InvalidParams {})?,
                    r,
                    s,
                },
                input,
            };

            let full_fee = gas_price * result.used_gas;

            let burn_fee = executor.config().burn_gas_price * result.used_gas;

            if full_fee < burn_fee {
                log::error!(
                    "Transaction execution error: fee less than need to burn (burn_gas_price = {})",
                    executor.config().burn_gas_price
                );
            }
            // 2. Then we should burn some part of it.
            // This if only register burn to the deposit address, withdrawal is done in 1.
            if burn_fee > U256::zero() {
                trace!("Burning fee {}", burn_fee);
                // we already withdraw gas_price during transaction_execute,
                // if burn_fixed_fee is activated, we should deposit to burn addr (0x00..00)
                executor.deposit(BURN_ADDR, burn_fee);
            };

            let tx_hashes = executor.evm_backend.get_executed_transactions();
            assert!(!tx_hashes.contains(&tx_hash));

            let transaction = if is_native_tx {
                TransactionInReceipt::Unsigned(UnsignedTransactionWithCaller {
                    unsigned_tx: transaction.into(),
                    chain_id: tx_chain_id,
                    signed_compatible: true,
                    caller,
                })
            } else {
                TransactionInReceipt::Signed(transaction)
            };
            let receipt = TransactionReceipt::new(
                transaction,
                result.used_gas,
                executor.evm_backend.block_number(),
                tx_hashes.len() as u64 + 1,
                result.tx_logs.clone(),
                (result.exit_reason.clone(), result.exit_data.clone()),
            );
            executor
                .evm_backend
                .push_transaction_receipt(tx_hash, receipt);

            Ok(result)
        }

        Box::pin(async move {
            let mut evm_state = meta
                .evm_state_archive(Some(block_header.timestamp))
                .ok_or(Error::ArchiveNotSupported)?
                .new_incomming_for_root(state_root)
                .ok_or(Error::StateNotFoundForBlock {
                    block: BlockId::Num(Hex(block_header.block_number)),
                })?;
            evm_state.state.block_number = block_header.block_number;
            evm_state.state.timestamp = block_header.timestamp;
            evm_state.state.last_block_hash = block_header.parent_hash;

            let evm_config = evm_state::EvmConfig {
                chain_id: meta.bank(None).evm_chain_id,
                estimate: false,
                burn_gas_price: burn_gas_price.into(),
                ..Default::default()
            };

            let last_hashes = last_hashes
                .try_into()
                .map_err(|_| Error::InvalidParams {})?;

            let mut warn = vec![];
            debug!("running with evm_state = {:?}", evm_state);
            for (tx, meta_keys) in txs {
                let mut executor = evm_state::Executor::with_config(
                    evm_state.clone(),
                    evm_state::ChainContext::new(last_hashes),
                    evm_config,
                    evm_state::executor::FeatureSet::new(
                        unsigned_tx_fix,
                        clear_logs_on_error,
                        accept_zero_gas_price_with_native_fee,
                    ),
                );
                debug!("running on executor = {:?}", executor);
                let meta_keys = meta_keys
                    .iter()
                    .map(|s| solana_sdk::pubkey::Pubkey::from_str(s))
                    .collect::<Result<Vec<Pubkey>, _>>()
                    .map_err(|_| Error::InvalidParams {})?;
                match simulate_transaction(&mut executor, tx.clone(), meta_keys) {
                    Ok(_result) => {
                        evm_state = executor.deconstruct();
                    }
                    Err(err) => {
                        log::warn!("Tx {:?} simulation failed: {:?}", &tx.hash, &tx);
                        log::warn!("RPC Error: {:?}", &err);
                        warn.push(tx.hash.unwrap_or_default());
                        evm_state.apply_failed_update(&executor.deconstruct(), clear_logs_on_error)
                    }
                };
            }

            let Committed {
                block: header,
                committed_transactions: transactions,
            } = evm_state
                .commit_block(
                    block_header.native_chain_slot,
                    block_header.native_chain_hash,
                )
                .state;

            Ok((
                Block {
                    header,
                    transactions,
                },
                warn,
            ))
        })
    }
}

struct TxOutput {
    exit_reason: evm_state::ExitReason,
    exit_data: Vec<u8>,
    used_gas: u64,
    traces: Vec<evm_state::executor::Trace>,
}

#[instrument(skip(meta))]
fn call(
    meta: Arc<JsonRpcRequestProcessor>,
    tx: RPCTransaction,
    saved_state: StateRootWithBank,
    meta_keys: Vec<solana_sdk::pubkey::Pubkey>,
) -> Result<TxOutput, Error> {
    let outputs = call_many(meta, &[(tx, meta_keys)], saved_state, true)?;

    let TxOutput {
        exit_reason,
        exit_data,
        used_gas,
        traces,
    } = outputs
        .into_iter()
        .next()
        .expect("Should contain result for tx.");

    let (_, exit_data) = evm_rpc::handle_evm_exit_reason(exit_reason.clone(), exit_data)?;

    Ok(TxOutput {
        exit_reason,
        exit_data,
        used_gas,
        traces,
    })
}

#[instrument(skip(meta))]
fn call_many(
    meta: Arc<JsonRpcRequestProcessor>,
    txs: &[(RPCTransaction, Vec<solana_sdk::pubkey::Pubkey>)],
    saved_state: StateRootWithBank,
    estimate: bool,
) -> Result<Vec<TxOutput>, Error> {
    // if we already found bank with some root, or we just cannot find state_root - use latest.
    let use_latest_state = saved_state.bank.is_some() || saved_state.state_root.is_none();
    let bank = saved_state
        .bank
        .unwrap_or_else(|| meta.bank(Some(CommitmentConfig::processed())));

    let evm_state = if use_latest_state {
        // keep current bank to allow simulating on latest state without archive
        match bank.evm_state.read().unwrap().clone() {
            evm_state::EvmState::Incomming(i) => i,
            evm_state::EvmState::Committed(c) => {
                c.next_incomming(bank.clock().unix_timestamp as u64)
            }
        }
    } else {
        let root = saved_state.state_root.unwrap();
        meta.evm_state_archive(saved_state.block_timestamp)
            .ok_or(Error::ArchiveNotSupported)?
            .new_incomming_for_root(root)
            .ok_or(Error::StateNotFoundForBlock {
                block: saved_state.block,
            })?
    };

    let estimate_config = evm_state::EvmConfig {
        estimate,
        chain_id: bank.evm_chain_id,
        ..Default::default()
    };

    //TODO: Hashes actual to saved root
    let last_hashes = bank.evm_hashes();
    let mut executor = evm_state::Executor::with_config(
        evm_state,
        evm_state::ChainContext::new(last_hashes),
        estimate_config,
        evm_state::executor::FeatureSet::new(
            bank.feature_set
                .is_active(&solana_sdk::feature_set::velas::unsigned_tx_fix::id()),
            bank.feature_set
                .is_active(&solana_sdk::feature_set::velas::clear_logs_on_error::id()),
            bank.feature_set.is_active(
                &solana_sdk::feature_set::velas::accept_zero_gas_price_with_native_fee::id(),
            ),
        ),
    );

    debug!("running evm executor = {:?}", executor);
    let mut result = Vec::new();
    for (tx, meta_keys) in txs {
        result.push(call_inner(
            &mut executor,
            tx.clone(),
            meta_keys.clone(),
            &bank,
        )?)
    }
    Ok(result)
}

#[instrument(skip(executor, bank))]
fn call_inner(
    executor: &mut evm_state::Executor,
    tx: RPCTransaction,
    meta_keys: Vec<solana_sdk::pubkey::Pubkey>,
    bank: &Bank,
) -> Result<TxOutput, Error> {
    use solana_evm_loader_program::precompiles::*;
    let caller = tx.from.unwrap_or_default();

    let value = tx.value.unwrap_or_else(|| 0.into());
    let input = tx.input.map(|a| a.0).unwrap_or_else(Vec::new);
    let gas_limit = tx.gas.unwrap_or_else(|| u64::MAX.into());
    // On estimate set gas price to zero, to avoid out of funds errors.
    let gas_price = u64::MIN.into();

    let nonce = tx.nonce.unwrap_or_else(|| executor.nonce(caller));
    let tx_chain_id = executor.chain_id();
    let tx_hash = tx.hash.unwrap_or_else(H256::random);

    let evm_state_balance = bank
        .get_account(&solana_sdk::evm_state::id())
        .unwrap_or_default()
        .lamports();

    let (user_accounts, action) = if let Some(address) = tx.to {
        let address = address;
        debug!(
            "Trying to execute tx = {:?}",
            (caller, address, value, &input, gas_limit)
        );

        let mut meta_keys: Vec<_> = meta_keys
            .into_iter()
            .map(|pk| {
                let user_account = RefCell::new(bank.get_account(&pk).unwrap_or_default());
                (user_account, pk)
            })
            .collect();

        // Shortcut for swap tokens to native, will add solana account to transaction.
        if address == *ETH_TO_VLX_ADDR {
            debug!("Found transferToNative transaction");
            match ETH_TO_VLX_CODE.parse_abi(&input) {
                Ok(pk) => {
                    info!("Adding account to meta = {}", pk);

                    let user_account = RefCell::new(bank.get_account(&pk).unwrap_or_default());
                    meta_keys.push((user_account, pk))
                }
                Err(e) => {
                    error!("Error in parsing abi = {}", e);
                }
            }
        }

        (meta_keys, TransactionAction::Call(address))
    } else {
        (vec![], TransactionAction::Create)
    };

    // system transfers always set s = 0x1
    if Some(U256::from(0x1)) == tx.s {
        // check if it native swap, then predeposit, amount, to pass transaction
        if caller == *ETH_TO_VLX_ADDR {
            let amount = value + gas_limit * gas_price;
            executor.deposit(caller, amount)
        }
    }

    let user_accounts: Vec<_> = user_accounts
        .iter()
        .map(|(user_account, pk)| KeyedAccount::new(pk, false, user_account))
        .collect();

    // Simulation does not have access to real account structure, so only process immutable entrypoints
    let evm_account = RefCell::new(solana_evm_loader_program::create_state_account(
        evm_state_balance,
    ));
    let evm_keyed_account = KeyedAccount::new(&solana_sdk::evm_state::ID, false, &evm_account);

    let evm_state::executor::ExecutionResult {
        exit_reason,
        exit_data,
        used_gas,
        traces,
        ..
    } = executor
        .transaction_execute_raw(
            caller,
            nonce,
            gas_price,
            gas_limit,
            action,
            input,
            value,
            Some(tx_chain_id),
            tx_hash,
            true,
            simulation_entrypoint(
                PrecompileSet::VelasClassic,
                &evm_keyed_account,
                &user_accounts,
            ),
        )
        .with_context(|_| EvmStateError)?;

    Ok(TxOutput {
        exit_reason,
        exit_data,
        used_gas,
        traces,
    })
}

#[instrument(skip(meta))]
async fn block_by_number(
    meta: Arc<JsonRpcRequestProcessor>,
    block: BlockId,
    full: bool,
) -> Result<Option<RPCBlock>, Error> {
    let num = block_parse_confirmed_num(Some(block), &meta).await;
    let evm_block = match num {
        Some(block_num) => meta.get_evm_block_by_id(block_num).await,
        None => None,
    };
    // TODO: Inline evm_state lookups, and request only solana headers.
    let (block, confirmed) = match evm_block {
        None => {
            error!("Error requesting block:{:?} ({:?}) not found", block, num);
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
        let txs = block.transactions.into_iter().map(|(k, _v)| k).collect();
        Either::Left(txs)
    };

    Ok(Some(RPCBlock::new_from_head(
        block.header,
        confirmed,
        transactions,
    )))
}

#[instrument(skip(meta))]
async fn transaction_by_hash(
    meta: Arc<JsonRpcRequestProcessor>,
    tx_hash: H256,
) -> Result<Option<RPCTransaction>, Error> {
    let bank = meta.bank(None);
    let chain_id = bank.evm_chain_id;
    Ok(match meta.get_evm_receipt_by_hash(tx_hash).await {
        Some(receipt) => {
            let (block, _) = meta
                .get_evm_block_by_id(receipt.block_number)
                .await
                .ok_or({
                    Error::BlockNotFound {
                        block: receipt.block_number.into(),
                    }
                })?;
            let block_hash = block.header.hash();
            Some(RPCTransaction::new_from_receipt(
                receipt, tx_hash, block_hash, chain_id,
            )?)
        }
        None => None,
    })
}

#[instrument(skip(meta))]
async fn trace_call_many(
    meta: Arc<JsonRpcRequestProcessor>,
    tx_traces: Vec<(RPCTransaction, Vec<String>, Option<TraceMeta>)>,
    block: Option<BlockId>,
    estimate: bool,
) -> Result<Vec<evm_rpc::trace::TraceResultsWithTransactionHash>, Error> {
    let saved_state = block_to_state_root(block, &meta).await;

    let mut txs = Vec::new();
    let mut txs_meta = Vec::new();

    // TODO: Handle Vec<String> - traces array, check that it contain "trace" string.
    for (t, _, meta) in tx_traces {
        let meta = meta.unwrap_or_default();
        let meta_keys = meta
            .meta_keys
            .iter()
            .flatten()
            .map(|s| solana_sdk::pubkey::Pubkey::from_str(s))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| into_native_error(e, false))?;

        txs.push((t, meta_keys));
        txs_meta.push(meta);
    }

    let traces = call_many(meta, &txs, saved_state, estimate)?.into_iter();

    let mut result = Vec::new();
    for (output, meta_tx) in traces.zip(txs_meta) {
        result.push(evm_rpc::trace::TraceResultsWithTransactionHash {
            trace: output.traces.into_iter().map(From::from).collect(),
            output: output.exit_data.into(),
            transaction_hash: meta_tx.transaction_hash,
            transaction_index: meta_tx.transaction_index.map(Hex),
            block_hash: meta_tx.block_hash,
            block_number: meta_tx.block_number,
        })
    }
    Ok(result)
}
