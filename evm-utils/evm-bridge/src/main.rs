use log::*;
use std::str::FromStr;
use std::sync::Arc;
use std::thread::sleep;
use std::time::Duration;
use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
};
use txpool::VerifiedTransaction;

use evm_rpc::basic::BasicERPC;
use evm_rpc::bridge::BridgeERPC;
use evm_rpc::chain_mock::ChainMockERPC;
use evm_rpc::error::{Error, *};
use evm_rpc::trace::TraceMeta;
use evm_rpc::*;
use evm_state::*;
use sha3::{Digest, Keccak256};

use jsonrpc_http_server::jsonrpc_core::*;
use jsonrpc_http_server::*;

use serde_json::json;
use snafu::ResultExt;

use solana_evm_loader_program::scope::*;
use solana_sdk::{
    clock::MS_PER_TICK, fee_calculator::DEFAULT_TARGET_LAMPORTS_PER_SIGNATURE, pubkey::Pubkey,
    signers::Signers, transaction::TransactionError,
};

use solana_client::{
    client_error::{ClientError, ClientErrorKind},
    rpc_client::RpcClient,
    rpc_config::*,
    rpc_request::{RpcRequest, RpcResponseErrorData},
    rpc_response::Response as RpcResponse,
    rpc_response::*,
};

use ::tokio;

use pool::{worker_cleaner, worker_deploy, EthPool, PooledTransaction, SystemClock};

use std::result::Result as StdResult;
type EvmResult<T> = StdResult<T, evm_rpc::Error>;

mod pool;
mod sol_proxy;

const MAX_NUM_BLOCKS_IN_BATCH: u64 = 2000; // should be less or equal to const core::evm_rpc_impl::logs::MAX_NUM_BLOCKS

// A compatibility layer, to make software more fluently.
mod compatibility {
    use evm_rpc::Hex;
    use evm_state::{Gas, TransactionAction, H256, U256};
    use rlp::{Decodable, DecoderError, Rlp};

    #[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
    pub struct TransactionSignature {
        pub v: u64,
        pub r: U256,
        pub s: U256,
    }
    #[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
    pub struct Transaction {
        pub nonce: U256,
        pub gas_price: Gas,
        pub gas_limit: Gas,
        pub action: TransactionAction,
        pub value: U256,
        pub signature: TransactionSignature,
        pub input: Vec<u8>,
    }

    impl Decodable for Transaction {
        fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
            Ok(Self {
                nonce: rlp.val_at(0)?,
                gas_price: rlp.val_at(1)?,
                gas_limit: rlp.val_at(2)?,
                action: rlp.val_at(3)?,
                value: rlp.val_at(4)?,
                input: rlp.val_at(5)?,
                signature: TransactionSignature {
                    v: rlp.val_at(6)?,
                    r: rlp.val_at(7)?,
                    s: rlp.val_at(8)?,
                },
            })
        }
    }

    impl From<Transaction> for evm_state::Transaction {
        fn from(tx: Transaction) -> evm_state::Transaction {
            let mut r = [0u8; 32];
            let mut s = [0u8; 32];
            tx.signature.r.to_big_endian(&mut r);
            tx.signature.s.to_big_endian(&mut s);
            evm_state::Transaction {
                nonce: tx.nonce,
                gas_limit: tx.gas_limit,
                gas_price: tx.gas_price,
                action: tx.action,
                value: tx.value,
                input: tx.input,
                signature: evm_state::TransactionSignature {
                    v: tx.signature.v,
                    r: r.into(),
                    s: s.into(),
                },
            }
        }
    }

    pub fn patch_tx(mut tx: evm_rpc::RPCTransaction) -> evm_rpc::RPCTransaction {
        if tx.r.unwrap_or_default() == Hex(U256::zero()) {
            tx.r = Some(Hex(0x1.into()))
        }
        if tx.s.unwrap_or_default() == Hex(U256::zero()) {
            tx.s = Some(Hex(0x1.into()))
        }
        tx
    }

    pub fn patch_block(mut block: evm_rpc::RPCBlock) -> evm_rpc::RPCBlock {
        let txs_empty = match &block.transactions {
            evm_rpc::Either::Left(txs) => txs.is_empty(),
            evm_rpc::Either::Right(txs) => txs.is_empty(),
        };
        // if no tx, and its root == zero, return empty trie hash, to avoid panics in go client.
        if txs_empty && block.transactions_root.0 == H256::zero() {
            evm_rpc::RPCBlock {
                transactions_root: Hex(evm_state::empty_trie_hash()),
                receipts_root: Hex(evm_state::empty_trie_hash()),
                ..block
            }
        } else {
            // if txs exist, check that their signatures are not zero, and fix them if so.
            block.transactions = match block.transactions {
                evm_rpc::Either::Left(txs) => evm_rpc::Either::Left(txs),
                evm_rpc::Either::Right(txs) => {
                    evm_rpc::Either::Right(txs.into_iter().map(patch_tx).collect())
                }
            };
            block
        }
    }
}

macro_rules! proxy_evm_rpc {
    (@silent $rpc: expr, $rpc_call:ident $(, $calls:expr)*) => (
        {
            match RpcClient::send(&$rpc, RpcRequest::$rpc_call, json!([$($calls,)*])) {
                Err(e) => Err(from_client_error(e).into()),
                Ok(o) => Ok(o)
            }
        }
    );
    ($rpc: expr, $rpc_call:ident $(, $calls:expr)*) => (
        {
            debug!("evm proxy received {}", stringify!($rpc_call));
            proxy_evm_rpc!(@silent $rpc, $rpc_call $(, $calls)* )
        }
    )

}

pub struct EvmBridge {
    evm_chain_id: u64,
    key: solana_sdk::signature::Keypair,
    accounts: HashMap<evm_state::Address, evm_state::SecretKey>,
    rpc_client: RpcClient,
    verbose_errors: bool,
    simulate: bool,
    max_logs_blocks: u64,
    pool: EthPool<SystemClock>,
}

impl EvmBridge {
    fn new(
        evm_chain_id: u64,
        keypath: &str,
        evm_keys: Vec<SecretKey>,
        addr: String,
        verbose_errors: bool,
        simulate: bool,
        max_logs_blocks: u64,
    ) -> Self {
        info!("EVM chain id {}", evm_chain_id);

        let accounts = evm_keys
            .into_iter()
            .map(|secret_key| {
                let public_key =
                    evm_state::PublicKey::from_secret_key(evm_state::SECP256K1, &secret_key);
                let public_key = evm_state::addr_from_public_key(&public_key);
                (public_key, secret_key)
            })
            .collect();

        info!("Trying to create rpc client with addr: {}", addr);
        let rpc_client = RpcClient::new(addr);

        info!("Loading keypair from: {}", keypath);
        let key = solana_sdk::signature::read_keypair_file(&keypath).unwrap();

        info!("Creating mempool...");
        let pool = EthPool::new(SystemClock);

        Self {
            evm_chain_id,
            key,
            accounts,
            rpc_client,
            verbose_errors,
            simulate,
            max_logs_blocks,
            pool,
        }
    }

    /// Wrap evm tx into solana, optionally add meta keys, to solana signature.
    fn send_tx(&self, tx: evm::Transaction, meta_keys: HashSet<Pubkey>) -> EvmResult<Hex<H256>> {
        let tx = PooledTransaction::new(tx, meta_keys)
            .map_err(|source| evm_rpc::Error::EvmStateError { source })?;

        let pooled_tx = self.pool.import(tx);

        pooled_tx.map(|tx| Hex(*tx.hash())).map_err(|e| {
            warn!("Could not import tx to the pool");
            evm_rpc::Error::RuntimeError {
                details: format!("Mempool error: {:?}", e),
            }
        })
    }

    fn block_to_number(&self, block: Option<BlockId>) -> EvmResult<u64> {
        let block = block.unwrap_or_default();
        let block_num = match block {
            BlockId::Num(block) => block.0,
            BlockId::RelativeId(BlockRelId::Latest) => {
                proxy_evm_rpc!(self.rpc_client, EthBlockNumber)?
            }
            _ => return Err(Error::BlockNotFound { block }),
        };
        Ok(block_num)
    }
}

pub struct BridgeErpcImpl;

impl BridgeERPC for BridgeErpcImpl {
    type Metadata = Arc<EvmBridge>;

    fn accounts(&self, meta: Self::Metadata) -> EvmResult<Vec<Hex<Address>>> {
        Ok(meta.accounts.iter().map(|(k, _)| Hex(*k)).collect())
    }

    fn sign(
        &self,
        _meta: Self::Metadata,
        _address: Hex<Address>,
        _data: Bytes,
    ) -> EvmResult<Bytes> {
        Err(evm_rpc::Error::Unimplemented {})
    }

    fn send_transaction(
        &self,
        meta: Self::Metadata,
        tx: RPCTransaction,
        meta_keys: Option<Vec<String>>,
    ) -> EvmResult<Hex<H256>> {
        let address = tx.from.map(|a| a.0).unwrap_or_default();

        debug!("send_transaction from = {}", address);

        let meta_keys = meta_keys
            .into_iter()
            .flatten()
            .map(|s| solana_sdk::pubkey::Pubkey::from_str(&s))
            .collect::<StdResult<HashSet<_>, _>>()
            .map_err(|e| into_native_error(e, meta.verbose_errors))?;

        let secret_key = meta
            .accounts
            .get(&address)
            .ok_or(Error::KeyNotFound { account: address })?;

        let nonce = tx
            .nonce
            .map(|a| a.0)
            .or_else(|| meta.pool.transaction_count(&address))
            .or_else(|| meta.rpc_client.get_evm_transaction_count(&address).ok())
            .unwrap_or_default();

        let tx_create = evm::UnsignedTransaction {
            nonce,
            gas_price: tx.gas_price.map(|a| a.0).unwrap_or_else(|| 0.into()),
            gas_limit: tx.gas.map(|a| a.0).unwrap_or_else(|| 30000000.into()),
            action: tx
                .to
                .map(|a| evm::TransactionAction::Call(a.0))
                .unwrap_or(evm::TransactionAction::Create),
            value: tx.value.map(|a| a.0).unwrap_or_else(|| 0.into()),
            input: tx.input.map(|a| a.0).unwrap_or_default(),
        };

        let tx = tx_create.sign(secret_key, Some(meta.evm_chain_id));

        meta.send_tx(tx, meta_keys)
    }

    fn send_raw_transaction(
        &self,
        meta: Self::Metadata,
        bytes: Bytes,
        meta_keys: Option<Vec<String>>,
    ) -> EvmResult<Hex<H256>> {
        debug!("send_raw_transaction");
        let meta_keys = meta_keys
            .into_iter()
            .flatten()
            .map(|s| solana_sdk::pubkey::Pubkey::from_str(&s))
            .collect::<StdResult<HashSet<_>, _>>()
            .map_err(|e| into_native_error(e, meta.verbose_errors))?;

        let tx: compatibility::Transaction = rlp::decode(&bytes.0).with_context(|| RlpError {
            struct_name: "RawTransaction".to_string(),
            input_data: hex::encode(&bytes.0),
        })?;
        let tx: evm::Transaction = tx.into();

        // TODO: Check chain_id.
        // TODO: check gas price.

        let unsigned_tx: evm::UnsignedTransaction = tx.clone().into();
        let hash = unsigned_tx.signing_hash(Some(meta.evm_chain_id));
        debug!("loaded tx_hash = {}", hash);

        meta.send_tx(tx, meta_keys)
    }

    fn compilers(&self, _meta: Self::Metadata) -> EvmResult<Vec<String>> {
        Err(evm_rpc::Error::Unimplemented {})
    }
}

pub struct ChainMockErpcProxy;
impl ChainMockERPC for ChainMockErpcProxy {
    type Metadata = Arc<EvmBridge>;

    fn network_id(&self, meta: Self::Metadata) -> EvmResult<String> {
        // NOTE: also we can get chain id from meta, but expects the same value
        Ok(format!("{}", meta.evm_chain_id))
    }

    fn chain_id(&self, meta: Self::Metadata) -> EvmResult<Hex<u64>> {
        Ok(Hex(meta.evm_chain_id))
    }

    // TODO: Add network info
    fn is_listening(&self, _meta: Self::Metadata) -> EvmResult<bool> {
        Ok(true)
    }

    fn peer_count(&self, _meta: Self::Metadata) -> EvmResult<Hex<usize>> {
        Ok(Hex(0))
    }

    fn sha3(&self, _meta: Self::Metadata, bytes: Bytes) -> EvmResult<Hex<H256>> {
        Ok(Hex(H256::from_slice(
            Keccak256::digest(bytes.0.as_slice()).as_slice(),
        )))
    }

    fn client_version(&self, _meta: Self::Metadata) -> EvmResult<String> {
        Ok(String::from("SolanaEvm/v0.1.0"))
    }

    fn protocol_version(&self, _meta: Self::Metadata) -> EvmResult<String> {
        Ok(String::from("0"))
    }

    fn is_syncing(&self, _meta: Self::Metadata) -> EvmResult<bool> {
        Ok(false)
    }

    fn coinbase(&self, _meta: Self::Metadata) -> EvmResult<Hex<Address>> {
        Ok(Hex(Address::from_low_u64_be(0)))
    }

    fn is_mining(&self, _meta: Self::Metadata) -> EvmResult<bool> {
        Ok(false)
    }

    fn hashrate(&self, _meta: Self::Metadata) -> EvmResult<String> {
        Ok(String::from("0x00"))
    }

    fn block_transaction_count_by_number(
        &self,
        _meta: Self::Metadata,
        _block: String,
    ) -> EvmResult<Option<Hex<usize>>> {
        Ok(None)
    }

    fn block_transaction_count_by_hash(
        &self,
        _meta: Self::Metadata,
        _block_hash: Hex<H256>,
    ) -> EvmResult<Option<Hex<usize>>> {
        Err(evm_rpc::Error::Unimplemented {})
    }

    fn uncle_by_block_hash_and_index(
        &self,
        _meta: Self::Metadata,
        _block_hash: Hex<H256>,
        _uncle_id: Hex<U256>,
    ) -> EvmResult<Option<RPCBlock>> {
        Err(evm_rpc::Error::Unimplemented {})
    }

    fn uncle_by_block_number_and_index(
        &self,
        _meta: Self::Metadata,
        _block: String,
        _uncle_id: Hex<U256>,
    ) -> EvmResult<Option<RPCBlock>> {
        Err(evm_rpc::Error::Unimplemented {})
    }

    fn block_uncles_count_by_hash(
        &self,
        _meta: Self::Metadata,
        _block_hash: Hex<H256>,
    ) -> EvmResult<Option<Hex<usize>>> {
        Err(evm_rpc::Error::Unimplemented {})
    }

    fn block_uncles_count_by_number(
        &self,
        _meta: Self::Metadata,
        _block: String,
    ) -> EvmResult<Option<Hex<usize>>> {
        Err(evm_rpc::Error::Unimplemented {})
    }

    fn transaction_by_block_hash_and_index(
        &self,
        _meta: Self::Metadata,
        _block_hash: Hex<H256>,
        _tx_id: Hex<U256>,
    ) -> EvmResult<Option<RPCTransaction>> {
        Err(evm_rpc::Error::Unimplemented {})
    }

    fn transaction_by_block_number_and_index(
        &self,
        _meta: Self::Metadata,
        _block: String,
        _tx_id: Hex<U256>,
    ) -> EvmResult<Option<RPCTransaction>> {
        Err(evm_rpc::Error::Unimplemented {})
    }
}

pub struct BasicErpcProxy;
impl BasicERPC for BasicErpcProxy {
    type Metadata = Arc<EvmBridge>;

    // The same as get_slot
    fn block_number(&self, meta: Self::Metadata) -> EvmResult<Hex<usize>> {
        proxy_evm_rpc!(meta.rpc_client, EthBlockNumber)
    }

    fn balance(
        &self,
        meta: Self::Metadata,
        address: Hex<Address>,
        block: Option<BlockId>,
    ) -> EvmResult<Hex<U256>> {
        proxy_evm_rpc!(meta.rpc_client, EthGetBalance, address, block)
    }

    fn storage_at(
        &self,
        meta: Self::Metadata,
        address: Hex<Address>,
        data: Hex<H256>,
        block: Option<BlockId>,
    ) -> EvmResult<Hex<H256>> {
        proxy_evm_rpc!(meta.rpc_client, EthGetStorageAt, address, data, block)
    }

    fn transaction_count(
        &self,
        meta: Self::Metadata,
        address: Hex<Address>,
        block: Option<BlockId>,
    ) -> EvmResult<Hex<U256>> {
        if let Some(tx_count) = meta.pool.transaction_count(&address.0) {
            return Ok(Hex(tx_count));
        }

        proxy_evm_rpc!(meta.rpc_client, EthGetTransactionCount, address, block)
    }

    fn code(
        &self,
        meta: Self::Metadata,
        address: Hex<Address>,
        block: Option<BlockId>,
    ) -> EvmResult<Bytes> {
        proxy_evm_rpc!(meta.rpc_client, EthGetCode, address, block)
    }

    fn block_by_hash(
        &self,
        meta: Self::Metadata,
        block_hash: Hex<H256>,
        full: bool,
    ) -> EvmResult<Option<RPCBlock>> {
        if block_hash == Hex(H256::zero()) {
            Ok(Some(RPCBlock::default()))
        } else {
            proxy_evm_rpc!(meta.rpc_client, EthGetBlockByHash, block_hash, full)
                .map(|o: Option<_>| o.map(compatibility::patch_block))
        }
    }

    fn block_by_number(
        &self,
        meta: Self::Metadata,
        block: BlockId,
        full: bool,
    ) -> EvmResult<Option<RPCBlock>> {
        if block == BlockId::Num(0x0.into()) {
            Ok(Some(RPCBlock::default()))
        } else {
            proxy_evm_rpc!(meta.rpc_client, EthGetBlockByNumber, block, full)
                .map(|o: Option<_>| o.map(compatibility::patch_block))
        }
    }

    fn transaction_by_hash(
        &self,
        meta: Self::Metadata,
        tx_hash: Hex<H256>,
    ) -> EvmResult<Option<RPCTransaction>> {
        // TODO: chain all possible outcomes properly
        if let Some(tx) = meta.pool.transaction_by_hash(tx_hash) {
            if let Ok(tx) = RPCTransaction::from_transaction((**tx).clone().into()) {
                // TODO: shoud we `patch` tx?
                return Ok(Some(tx));
            }
        }
        proxy_evm_rpc!(meta.rpc_client, EthGetTransactionByHash, tx_hash)
            .map(|o: Option<_>| o.map(compatibility::patch_tx))
    }

    fn transaction_receipt(
        &self,
        meta: Self::Metadata,
        tx_hash: Hex<H256>,
    ) -> EvmResult<Option<RPCReceipt>> {
        proxy_evm_rpc!(meta.rpc_client, EthGetTransactionReceipt, tx_hash)
    }

    fn call(
        &self,
        meta: Self::Metadata,
        tx: RPCTransaction,
        block: Option<BlockId>,
        meta_keys: Option<Vec<String>>,
    ) -> EvmResult<Bytes> {
        proxy_evm_rpc!(meta.rpc_client, EthCall, tx, block, meta_keys)
    }

    fn trace_call(
        &self,
        meta: Self::Metadata,
        tx: RPCTransaction,
        traces: Vec<String>,
        block: Option<BlockId>,
        meta_info: Option<TraceMeta>,
    ) -> EvmResult<evm_rpc::trace::TraceResultsWithTransactionHash> {
        proxy_evm_rpc!(meta.rpc_client, EthTraceCall, tx, traces, block, meta_info)
    }

    fn trace_call_many(
        &self,
        meta: Self::Metadata,
        tx_traces: Vec<(RPCTransaction, Vec<String>, Option<TraceMeta>)>,
        block: Option<BlockId>,
    ) -> EvmResult<Vec<evm_rpc::trace::TraceResultsWithTransactionHash>> {
        proxy_evm_rpc!(meta.rpc_client, EthTraceCallMany, tx_traces, block)
    }

    fn trace_replay_transaction(
        &self,
        meta: Self::Metadata,
        tx_hash: Hex<H256>,
        traces: Vec<String>,
        meta_info: Option<TraceMeta>,
    ) -> EvmResult<Option<trace::TraceResultsWithTransactionHash>> {
        proxy_evm_rpc!(
            meta.rpc_client,
            EthTraceReplayTransaction,
            tx_hash,
            traces,
            meta_info
        )
    }

    fn trace_replay_block(
        &self,
        meta: Self::Metadata,
        block: BlockId,
        traces: Vec<String>,
        meta_info: Option<TraceMeta>,
    ) -> EvmResult<Vec<trace::TraceResultsWithTransactionHash>> {
        proxy_evm_rpc!(
            meta.rpc_client,
            EthTraceReplayBlock,
            block,
            traces,
            meta_info
        )
    }

    fn estimate_gas(
        &self,
        meta: Self::Metadata,
        tx: RPCTransaction,
        block: Option<BlockId>,
        meta_keys: Option<Vec<String>>,
    ) -> EvmResult<Hex<Gas>> {
        proxy_evm_rpc!(meta.rpc_client, EthEstimateGas, tx, block, meta_keys)
    }

    fn logs(&self, meta: Self::Metadata, mut log_filter: RPCLogFilter) -> EvmResult<Vec<RPCLog>> {
        let starting_block = meta.block_to_number(log_filter.from_block)?;
        let ending_block = meta.block_to_number(log_filter.to_block)?;

        if ending_block < starting_block {
            return Err(Error::InvalidBlocksRange {
                starting: starting_block,
                ending: ending_block,
                batch_size: None,
            });
        }

        // request more than we can provide
        if ending_block > starting_block + meta.max_logs_blocks {
            return Err(Error::InvalidBlocksRange {
                starting: starting_block,
                ending: ending_block,
                batch_size: Some(meta.max_logs_blocks),
            });
        }

        let mut starting = starting_block;

        let rt = tokio::runtime::Builder::new_multi_thread()
            .thread_name("get-logs-runner")
            .build()
            .map_err(|details| Error::RuntimeError {
                details: details.to_string(),
            })?;

        // make execution parallel
        rt.block_on(async {
            let mut collector = Vec::new();
            while starting <= ending_block {
                let ending = (starting.saturating_add(MAX_NUM_BLOCKS_IN_BATCH)).min(ending_block);
                log_filter.from_block = Some(starting.into());
                log_filter.to_block = Some(ending.into());

                let cloned_filter = log_filter.clone();
                let cloned_meta = meta.clone();
                // Parallel execution:
                collector.push(tokio::task::spawn_blocking(move || {
                    info!("filter = {:?}", cloned_filter);
                    let result: EvmResult<Vec<RPCLog>> =
                        proxy_evm_rpc!(@silent cloned_meta.rpc_client, EthGetLogs, cloned_filter);
                    info!("logs = {:?}", result);

                    result
                }));

                starting = starting.saturating_add(MAX_NUM_BLOCKS_IN_BATCH + 1);
            }
            // join all execution, fast fail on any error.
            let mut result = Vec::new();
            for collection in collector {
                result.extend(collection.await.map_err(|details| Error::RuntimeError {
                    details: details.to_string(),
                })??)
            }
            Ok(result)
        })
    }

    fn gas_price(&self, _meta: Self::Metadata) -> EvmResult<Hex<Gas>> {
        const GWEI: u64 = 1_000_000_000;
        //TODO: Add gas logic
        let gas_price = 21000 * solana_evm_loader_program::scope::evm::LAMPORTS_TO_GWEI_PRICE
            / DEFAULT_TARGET_LAMPORTS_PER_SIGNATURE; // 21000 is smallest call in evm

        let gas_price = gas_price - gas_price % GWEI; //round to gwei for metamask
        Ok(Hex(gas_price.into()))
    }
}

pub(crate) fn from_client_error(client_error: ClientError) -> evm_rpc::Error {
    let client_error_kind = client_error.kind();
    match client_error_kind {
        ClientErrorKind::RpcError(solana_client::rpc_request::RpcError::RpcResponseError {
            code,
            message,
            data,
            original_err,
        }) => {
            match data {
                // if transaction preflight, try to get last log messages, and return it as error.
                RpcResponseErrorData::SendTransactionPreflightFailure(
                    RpcSimulateTransactionResult {
                        err: Some(TransactionError::InstructionError(_, _)),
                        logs: Some(logs),
                        ..
                    },
                ) if !logs.is_empty() => {
                    let first_entry = logs.len().saturating_sub(2); // take two elements from logs
                    let last_log = logs[first_entry..].join(";");

                    return evm_rpc::Error::ProxyRpcError {
                        source: jsonrpc_core::Error {
                            code: (*code).into(),
                            message: last_log,
                            data: original_err.clone().into(),
                        },
                    };
                }
                _ => {}
            }
            evm_rpc::Error::ProxyRpcError {
                source: jsonrpc_core::Error {
                    code: (*code).into(),
                    message: message.clone(),
                    data: original_err.clone().into(),
                },
            }
        }
        _ => evm_rpc::Error::NativeRpcError {
            details: format!("{:?}", client_error),
            source: client_error.into(),
            verbose: false, // don't verbose native errors.
        },
    }
}

#[derive(Debug, structopt::StructOpt)]
struct Args {
    keyfile: Option<String>,
    #[structopt(default_value = "http://127.0.0.1:8899")]
    rpc_address: String,
    #[structopt(default_value = "127.0.0.1:8545")]
    binding_address: SocketAddr,
    #[structopt(default_value = "57005")] // 0xdead
    evm_chain_id: u64,
    #[structopt(long = "verbose-errors")]
    verbose_errors: bool,
    #[structopt(long = "no-simulate")]
    no_simulate: bool, // parse inverted to keep false default
    /// Maximum number of blocks to return in eth_getLogs rpc.
    #[structopt(long = "max-logs-block-count", default_value = "500")]
    max_logs_blocks: u64,
}

const SECRET_KEY_DUMMY: [u8; 32] = [1; 32];

#[paw::main]
fn main(args: Args) -> StdResult<(), Box<dyn std::error::Error>> {
    env_logger::init();

    let keyfile_path = args
        .keyfile
        .unwrap_or_else(|| solana_cli_config::Config::default().keypair_path);
    let server_path = args.rpc_address;
    let binding_address = args.binding_address;

    let meta = EvmBridge::new(
        args.evm_chain_id,
        &keyfile_path,
        vec![evm::SecretKey::from_slice(&SECRET_KEY_DUMMY).unwrap()],
        server_path,
        args.verbose_errors,
        !args.no_simulate, // invert argument
        args.max_logs_blocks,
    );
    let meta = Arc::new(meta);

    let mut io = MetaIoHandler::default();

    {
        use solana_core::rpc::rpc_minimal::Minimal;
        let minimal_rpc = sol_proxy::MinimalRpcSolProxy;
        io.extend_with(minimal_rpc.to_delegate());
    }
    {
        use solana_core::rpc::rpc_full::Full;
        let full_rpc = sol_proxy::FullRpcSolProxy;
        io.extend_with(full_rpc.to_delegate());
    }

    let ether_bridge = BridgeErpcImpl;
    io.extend_with(ether_bridge.to_delegate());
    let ether_basic = BasicErpcProxy;
    io.extend_with(ether_basic.to_delegate());
    let ether_mock = ChainMockErpcProxy;
    io.extend_with(ether_mock.to_delegate());

    info!("Creating worker thread...");
    let mempool_worker = worker_deploy(meta.clone());

    info!("Creating cleaner thread...");
    let cleaner = worker_cleaner(meta.clone());

    info!("Creating server with: {}", binding_address);
    let meta_clone = meta.clone();
    let server = ServerBuilder::with_meta_extractor(
        io.clone(),
        move |_req: &hyper::Request<hyper::Body>| meta_clone.clone(),
    )
    .cors(DomainsValidation::AllowOnly(vec![
        AccessControlAllowOrigin::Any,
    ]))
    .threads(4)
    .cors_max_age(86400)
    .start_http(&binding_address)
    .expect("Unable to start EVM bridge server");

    let ws_server = {
        let mut websocket_binding = binding_address;
        websocket_binding.set_port(binding_address.port() + 1);
        info!("Creating websocket server: {}", websocket_binding);
        jsonrpc_ws_server::ServerBuilder::with_meta_extractor(io, move |_: &_| meta.clone())
            .start(&websocket_binding)
            .expect("Unable to start EVM bridge server")
    };
    mempool_worker.join().unwrap();
    cleaner.join().unwrap();
    ws_server.wait().unwrap();
    server.wait();
    Ok(())
}

fn send_and_confirm_transactions<T: Signers>(
    rpc_client: &RpcClient,
    mut transactions: Vec<solana::Transaction>,
    signer_keys: &T,
) -> StdResult<(), anyhow::Error> {
    const SEND_RETRIES: usize = 5;
    const STATUS_RETRIES: usize = 15;

    for _ in 0..SEND_RETRIES {
        // Send all transactions
        let mut transactions_signatures = transactions
            .drain(..)
            .map(|transaction| {
                if cfg!(not(test)) {
                    // Delay ~1 tick between write transactions in an attempt to reduce AccountInUse errors
                    // when all the write transactions modify the same program account (eg, deploying a
                    // new program)
                    sleep(Duration::from_millis(MS_PER_TICK));
                }

                debug!("Sending {:?}", transaction.signatures);

                let signature = rpc_client
                    .send_transaction_with_config(
                        &transaction,
                        RpcSendTransactionConfig {
                            skip_preflight: true, // NOTE: was true
                            ..RpcSendTransactionConfig::default()
                        },
                    )
                    .map_err(|e| error!("Send transaction error: {:?}", e))
                    .ok();

                (transaction, signature)
            })
            .collect::<Vec<_>>();

        for _ in 0..STATUS_RETRIES {
            // Collect statuses for all the transactions, drop those that are confirmed

            if cfg!(not(test)) {
                // Retry twice a second
                sleep(Duration::from_millis(500));
            }

            transactions_signatures.retain(|(_transaction, signature)| {
                signature
                    .and_then(|signature| rpc_client.get_signature_statuses(&[signature]).ok())
                    .and_then(|RpcResponse { mut value, .. }| value.remove(0))
                    .and_then(|status| status.confirmations)
                    .map(|confirmations| confirmations == 0) // retain unconfirmed only
                    .unwrap_or(true)
            });

            if transactions_signatures.is_empty() {
                return Ok(());
            }
        }

        // Re-sign any failed transactions with a new blockhash and retry
        let (blockhash, _) = rpc_client
            .get_new_blockhash(&transactions_signatures[0].0.message().recent_blockhash)?;

        for (mut transaction, _) in transactions_signatures {
            transaction.try_sign(signer_keys, blockhash)?;
            debug!("Resending {:?}", transaction);
            transactions.push(transaction);
        }
    }
    Err(anyhow::Error::msg("Transactions failed"))
}
