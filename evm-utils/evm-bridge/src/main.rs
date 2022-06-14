mod middleware;
mod pool;
mod sol_proxy;

use log::*;
use std::future::ready;
use std::str::FromStr;
use std::sync::{Arc, atomic::{AtomicU64, Ordering}};
use std::time::{Duration, Instant};
use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
};

use evm_rpc::bridge::BridgeERPC;
use evm_rpc::chain::ChainERPC;
use evm_rpc::general::GeneralERPC;
use evm_rpc::trace::TraceERPC;
use evm_rpc::error::{Error, *};
use evm_rpc::trace::TraceMeta;
use evm_rpc::*;
use evm_state::*;
use sha3::{Digest, Keccak256};

use jsonrpc_core::BoxFuture;
use jsonrpc_http_server::jsonrpc_core::*;
use jsonrpc_http_server::*;

use reqwest::{
    header::{CONTENT_TYPE, RETRY_AFTER},
    StatusCode,
};

use serde::Deserialize;
use serde_json::json;
use snafu::ResultExt;

use derivative::*;
use solana_evm_loader_program::scope::*;
use solana_sdk::{
    clock::{DEFAULT_MS_PER_SLOT, MS_PER_TICK, Slot}, commitment_config::CommitmentConfig,
    fee_calculator::{DEFAULT_TARGET_LAMPORTS_PER_SIGNATURE, FeeCalculator}, hash::Hash,
    pubkey::Pubkey, signature::Signature, signers::Signers,
    transaction::{TransactionError, uses_durable_nonce},
};
use solana_transaction_status::{TransactionStatus, UiTransactionEncoding};

use solana_client::{
    client_error::{ClientError, ClientErrorKind, Result as ClientResult},
    rpc_client::{RpcClient, serialize_encode_transaction},
    rpc_config::*,
    rpc_custom_error,
    rpc_request::{RpcError, RpcRequest, RpcResponseErrorData},
    rpc_response::Response as RpcResponse,
    rpc_response::*,
};

use tracing_attributes::instrument;
use tracing_subscriber::prelude::*;
use tracing_subscriber::{
    filter::{LevelFilter, Targets},
    layer::{Layer, SubscriberExt},
};

use ::tokio;
use ::tokio::sync::mpsc;
use ::tokio::time::sleep;

use middleware::ProxyMiddleware;
use pool::{
    worker_cleaner, worker_deploy, worker_signature_checker, EthPool, PooledTransaction,
    SystemClock,
};

use rlp::Encodable;
use secp256k1::Message;
use std::result::Result as StdResult;
type EvmResult<T> = StdResult<T, evm_rpc::Error>;

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
            let response = $rpc
                .send_request(RpcRequest::$rpc_call, json!([$($calls,)*]))
                .await
                .map_err(|err| {
                    from_client_error(err.into_with_request(RpcRequest::$rpc_call))
                })?;
            serde_json::from_value(response).map_err(|err| {
                from_client_error(ClientError::new_with_request(err.into(), RpcRequest::$rpc_call))
            })
        }
    );
    ($rpc: expr, $rpc_call:ident $(, $calls:expr)*) => (
        {
            debug!("evm proxy received {}", stringify!($rpc_call));
            proxy_evm_rpc!(@silent $rpc, $rpc_call $(, $calls)* )
        }
    )

}

#[derive(Deserialize, Debug)]
struct RpcErrorObject {
    code: i64,
    message: String,
    #[serde(default)]
    data: Value,
}

pub struct AsyncRpcClient {
    client: Arc<reqwest::Client>,
    url: String,
    request_id: AtomicU64,
}

impl AsyncRpcClient {
    pub fn new(url: String) -> Self {
        Self::new_with_timeout(url, Duration::from_secs(30))
    }

    pub fn new_with_timeout(url: String, timeout: Duration) -> Self {
        let client = Arc::new(
            reqwest::Client::builder()
                .timeout(timeout)
                .build()
                .expect("build rpc client")
        );

        Self {
            client,
            url,
            request_id: AtomicU64::new(0),
        }
    }

    pub async fn send_request(&self, request: RpcRequest, params: Value) -> ClientResult<Value> {
        let request_id = self.request_id.fetch_add(1, Ordering::Relaxed);
        let request_json = request.build_request_json(request_id, params).to_string();
        self._send_request(request_json).await
    }

    pub async fn _send_request(&self, request_json: String) -> ClientResult<Value> {
        let mut too_many_requests_retries = 5;
        loop {
            let response = {
                let client = self.client.clone();
                let request_json = request_json.clone();
                client
                    .post(&self.url)
                    .header(CONTENT_TYPE, "application/json")
                    .body(request_json)
                    .send()
                    .await
            };

            match response {
                Ok(response) => {
                    if !response.status().is_success() {
                        if response.status() == StatusCode::TOO_MANY_REQUESTS
                            && too_many_requests_retries > 0
                        {
                            let mut duration = Duration::from_millis(500);
                            if let Some(retry_after) = response.headers().get(RETRY_AFTER) {
                                if let Ok(retry_after) = retry_after.to_str() {
                                    if let Ok(retry_after) = retry_after.parse::<u64>() {
                                        if retry_after < 120 {
                                            duration = Duration::from_secs(retry_after);
                                        }
                                    }
                                }
                            }

                            too_many_requests_retries -= 1;
                            debug!(
                                "Too many requests: server responded with {:?}, {} retries left, pausing for {:?}",
                                response, too_many_requests_retries, duration
                            );

                            sleep(duration).await;
                            continue;
                        }
                        return Err(response.error_for_status().unwrap_err().into());
                    }

                    let response_text = response.text().await?;

                    let json: serde_json::Value = serde_json::from_str(&response_text)?;
                    if json["error"].is_object() {
                        return match serde_json::from_value::<RpcErrorObject>(json["error"].clone())
                        {
                            Ok(rpc_error_object) => {
                                let data = match rpc_error_object.code {
                                    rpc_custom_error::JSON_RPC_SERVER_ERROR_SEND_TRANSACTION_PREFLIGHT_FAILURE => {
                                        match serde_json::from_value::<RpcSimulateTransactionResult>(json["error"]["data"].clone()) {
                                            Ok(data) => RpcResponseErrorData::SendTransactionPreflightFailure(data),
                                            Err(err) => {
                                                debug!("Failed to deserialize RpcSimulateTransactionResult: {:?}", err);
                                                RpcResponseErrorData::Empty
                                            }
                                        }
                                    },
                                    rpc_custom_error::JSON_RPC_SERVER_ERROR_NODE_UNHEALTHY => {
                                        match serde_json::from_value::<rpc_custom_error::NodeUnhealthyErrorData>(json["error"]["data"].clone()) {
                                            Ok(rpc_custom_error::NodeUnhealthyErrorData {num_slots_behind}) => RpcResponseErrorData::NodeUnhealthy {num_slots_behind},
                                            Err(_err) => {
                                                RpcResponseErrorData::Empty
                                            }
                                        }
                                    },
                                    _ => RpcResponseErrorData::Empty
                                };

                                Err(RpcError::RpcResponseError {
                                    code: rpc_error_object.code,
                                    message: rpc_error_object.message,
                                    data,
                                    original_err: json["error"]["data"].clone(),
                                }
                                    .into())
                            }
                            Err(err) => Err(RpcError::RpcRequestError(format!(
                                "Failed to deserialize RPC error response: {} [{}]",
                                serde_json::to_string(&json["error"]).unwrap(),
                                err
                            ))
                                .into()),
                        };
                    }
                    return Ok(json["result"].clone());
                }
                Err(err) => {
                    return Err(err.into());
                }
            }
        }
    }

    async fn get_evm_transaction_count(
        &self,
        address: &Address,
    ) -> ClientResult<U256> {
        self.send::<Hex<_>>(
            RpcRequest::EthGetTransactionCount,
            json!([evm_rpc::Hex(*address)]),
        )
            .await
            .map(|h| h.0)
    }

    async fn get_evm_transaction_receipt(&self, hash: &H256) -> ClientResult<Option<RPCReceipt>> {
        self.send::<Option<RPCReceipt>>(
            RpcRequest::EthGetTransactionReceipt,
            json!([evm_rpc::Hex(*hash)])
        )
            .await
    }

    async fn get_fee_calculator_for_blockhash_with_commitment(
        &self,
        blockhash: &Hash,
        commitment_config: CommitmentConfig,
    ) -> RpcResult<Option<FeeCalculator>> {
        let RpcResponse { context, value } = self.send::<RpcResponse<Option<RpcFeeCalculator>>>(
            RpcRequest::GetFeeCalculatorForBlockhash,
            json!([
                blockhash.to_string(),
                commitment_config
            ]),
        )
            .await?;

        Ok(RpcResponse {
            context,
            value: value.map(|rf| rf.fee_calculator),
        })
    }

    async fn get_signature_status_with_commitment(
        &self,
        signature: &Signature,
        commitment_config: CommitmentConfig,
    ) -> ClientResult<Option<solana_sdk::transaction::Result<()>>> {
        let result: RpcResponse<Vec<Option<TransactionStatus>>> = self.send(
            RpcRequest::GetSignatureStatuses,
            json!([[signature.to_string()]]),
        )
            .await?;
        Ok(result.value[0]
            .clone()
            .filter(|result| result.satisfies_commitment(commitment_config))
            .map(|status_meta| status_meta.status))
    }

    async fn get_signature_status(
        &self,
        signature: &Signature,
    ) -> ClientResult<Option<solana_sdk::transaction::Result<()>>> {
        self.get_signature_status_with_commitment(
            signature,
            CommitmentConfig::processed()
        ).await
    }

    async fn send_and_confirm_transaction_with_config(
        &self,
        transaction: &solana::Transaction,
        config: RpcSendTransactionConfig,
    ) -> ClientResult<Signature> {
        const SEND_RETRIES: usize = 20;
        const GET_STATUS_RETRIES: usize = 40;

        'sending: for _ in 0..SEND_RETRIES {
            let signature = self.send_transaction_with_config(transaction, config).await?;

            let recent_blockhash = if uses_durable_nonce(transaction).is_some() {
                let (recent_blockhash, ..) = self
                    .get_recent_blockhash_with_commitment(CommitmentConfig::processed())
                    .await?
                    .value;
                recent_blockhash
            } else {
                transaction.message.recent_blockhash
            };

            for status_retry in 0..GET_STATUS_RETRIES {
                match self.get_signature_status(&signature).await? {
                    Some(Ok(_)) => return Ok(signature),
                    Some(Err(e)) => return Err(e.into()),
                    None => {
                        let fee_calculator = self
                            .get_fee_calculator_for_blockhash_with_commitment(
                                &recent_blockhash,
                                CommitmentConfig::processed(),
                            )
                            .await?
                            .value;
                        if fee_calculator.is_none() {
                            // Block hash is not found by some reason
                            break 'sending;
                        } else if cfg!(not(test))
                            // Ignore sleep at last step.
                            && status_retry < GET_STATUS_RETRIES
                        {
                            // Retry twice a second
                            sleep(Duration::from_millis(500)).await;
                            continue;
                        }
                    }
                }
            }
        }

        Err(RpcError::ForUser(
            "unable to confirm transaction. \
             This can happen in situations such as transaction expiration \
             and insufficient fee-payer funds"
                .to_string(),
        )
            .into())
    }

    async fn send_transaction_with_config(
        &self,
        transaction: &solana::Transaction,
        config: RpcSendTransactionConfig,
    ) -> ClientResult<Signature> {
        let encoding = config.encoding.unwrap_or(UiTransactionEncoding::Base64);
        let preflight_commitment = CommitmentConfig {
            commitment: config.preflight_commitment.unwrap_or_default(),
        };
        let config = RpcSendTransactionConfig {
            encoding: Some(encoding),
            preflight_commitment: Some(preflight_commitment.commitment),
            ..config
        };
        let serialized_encoded = serialize_encode_transaction(transaction, encoding)?;
        let request = RpcRequest::SendTransaction;
        let response = match self.send_request(request, json!([serialized_encoded, config])).await {
            Ok(val) => serde_json::from_value(val)
                .map_err(|err| ClientError::new_with_request(err.into(), request)),
            Err(err) => Err(err.into_with_request(request)),
        };
        let signature_base58_str: String = match response {
            Ok(signature_base58_str) => signature_base58_str,
            Err(err) => {
                if let ClientErrorKind::RpcError(RpcError::RpcResponseError {
                                                     code,
                                                     message,
                                                     data,
                                                     original_err: _original_err,
                                                 }) = &err.kind
                {
                    debug!("{} {}", code, message);
                    if let RpcResponseErrorData::SendTransactionPreflightFailure(
                        RpcSimulateTransactionResult {
                            logs: Some(logs), ..
                        },
                    ) = data
                    {
                        for (i, log) in logs.iter().enumerate() {
                            debug!("{:>3}: {}", i + 1, log);
                        }
                        debug!("");
                    }
                }
                return Err(err);
            }
        };

        let signature = signature_base58_str
            .parse::<Signature>()
            .map_err(|err| Into::<ClientError>::into(RpcError::ParseError(err.to_string())))?;
        // A mismatching RPC response signature indicates an issue with the RPC node, and
        // should not be passed along to confirmation methods. The transaction may or may
        // not have been submitted to the cluster, so callers should verify the success of
        // the correct transaction signature independently.
        if signature != transaction.signatures[0] {
            Err(RpcError::RpcRequestError(format!(
                "RPC node returned mismatched signature {:?}, expected {:?}",
                signature, transaction.signatures[0]
            ))
                .into())
        } else {
            Ok(transaction.signatures[0])
        }
    }

    async fn get_signature_statuses(
        &self,
        signatures: &[Signature],
    ) -> RpcResult<Vec<Option<TransactionStatus>>> {
        let signatures: Vec<_> = signatures.iter().map(|s| s.to_string()).collect();
        let request = RpcRequest::GetSignatureStatuses;
        let response = self
            .send_request(request, json!([signatures]))
            .await
            .map_err(|err| err.into_with_request(request))?;
        serde_json::from_value(response)
            .map_err(|err| ClientError::new_with_request(err.into(), request))
    }

    async fn get_recent_blockhash_with_commitment(
        &self,
        commitment_config: CommitmentConfig,
    ) -> RpcResult<(Hash, FeeCalculator, Slot)> {
        let (context, blockhash, fee_calculator, last_valid_slot) = if let Ok(RpcResponse {
            context,
            value:
                RpcFees {
                    blockhash,
                    fee_calculator,
                    last_valid_slot,
                    ..
                },
        }) = self.send::<RpcResponse<RpcFees>>(
                RpcRequest::GetFees,
                json!([commitment_config]),
        )
            .await
        {
            (context, blockhash, fee_calculator, last_valid_slot)
        } else if let Ok(RpcResponse {
            context,
            value:
                DeprecatedRpcFees {
                    blockhash,
                    fee_calculator,
                    last_valid_slot,
                },
        }) = self.send::<RpcResponse<DeprecatedRpcFees>>(
            RpcRequest::GetFees,
            json!([commitment_config]),
        )
            .await
        {
            (context, blockhash, fee_calculator, last_valid_slot)
        } else if let Ok(RpcResponse {
            context,
            value:
                RpcBlockhashFeeCalculator {
                    blockhash,
                    fee_calculator,
                },
        }) = self.send::<RpcResponse<RpcBlockhashFeeCalculator>>(
            RpcRequest::GetRecentBlockhash,
            json!([commitment_config]),
        )
            .await
        {
            (context, blockhash, fee_calculator, 0)
        } else {
            return Err(ClientError::new_with_request(
                RpcError::ParseError("RpcBlockhashFeeCalculator or RpcFees".to_string()).into(),
                RpcRequest::GetRecentBlockhash,
            ));
        };

        let blockhash = blockhash.parse().map_err(|_| {
            ClientError::new_with_request(
                RpcError::ParseError("Hash".to_string()).into(),
                RpcRequest::GetRecentBlockhash,
            )
        })?;
        Ok(RpcResponse {
            context,
            value: (blockhash, fee_calculator, last_valid_slot),
        })
    }

    async fn get_recent_blockhash(&self) -> ClientResult<(Hash, FeeCalculator)> {
        let (blockhash, fee_calculator, _last_valid_slot) = self
            .get_recent_blockhash_with_commitment(CommitmentConfig::processed())
            .await?
            .value;
        Ok((blockhash, fee_calculator))
    }

    async fn get_new_blockhash(&self, blockhash: &Hash) -> ClientResult<(Hash, FeeCalculator)> {
        let mut num_retries = 0;
        let start = Instant::now();
        while start.elapsed().as_secs() < 5 {
            if let Ok((new_blockhash, fee_calculator)) = self.get_recent_blockhash().await {
                if new_blockhash != *blockhash {
                    return Ok((new_blockhash, fee_calculator));
                }
            }
            debug!("Got same blockhash ({:?}), will retry...", blockhash);

            // Retry ~twice during a slot
            sleep(Duration::from_millis(DEFAULT_MS_PER_SLOT / 2)).await;
            num_retries += 1;
        }
        Err(RpcError::ForUser(format!(
            "Unable to get new blockhash after {}ms (retried {} times), stuck at {}",
            start.elapsed().as_millis(),
            num_retries,
            blockhash
        ))
            .into())
    }

    async fn get_minimum_balance_for_rent_exemption(&self, data_len: usize) -> ClientResult<u64> {
        let request = RpcRequest::GetMinimumBalanceForRentExemption;
        let minimum_balance_json = self
            .send_request(request, json!([data_len]))
            .await
            .map_err(|err| err.into_with_request(request))?;

        let minimum_balance: u64 = serde_json::from_value(minimum_balance_json)
            .map_err(|err| ClientError::new_with_request(err.into(), request))?;
        trace!(
            "Response minimum balance {:?} {:?}",
            data_len,
            minimum_balance
        );
        Ok(minimum_balance)
    }

    async fn send<T>(&self, request: RpcRequest, params: Value) -> ClientResult<T>
        where
            T: serde::de::DeserializeOwned,
    {
        assert!(params.is_array() || params.is_null());
        let response = self
            .send_request(request, params)
            .await
            .map_err(|err| err.into_with_request(request))?;
        serde_json::from_value(response)
            .map_err(|err| ClientError::new_with_request(err.into(), request))
    }
}

#[derive(Derivative)]
#[derivative(Debug)]
pub struct EvmBridge {
    evm_chain_id: u64,
    key: solana_sdk::signature::Keypair,
    accounts: HashMap<evm_state::Address, evm_state::SecretKey>,

    #[derivative(Debug = "ignore")]
    rpc_client: RpcClient,
    #[derivative(Debug = "ignore")]
    rpc_client_async: AsyncRpcClient,
    verbose_errors: bool,
    simulate: bool,
    max_logs_blocks: u64,
    pool: EthPool<SystemClock>,
    min_gas_price: U256,
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
        min_gas_price: U256,
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
        let rpc_client = RpcClient::new_with_commitment(addr.clone(), CommitmentConfig::processed());
        let rpc_client_async = AsyncRpcClient::new(addr);

        info!("Loading keypair from: {}", keypath);
        let key = solana_sdk::signature::read_keypair_file(&keypath).unwrap();

        info!("Creating mempool...");
        let pool = EthPool::new(SystemClock);

        Self {
            evm_chain_id,
            key,
            accounts,
            rpc_client,
            rpc_client_async,
            verbose_errors,
            simulate,
            max_logs_blocks,
            pool,
            min_gas_price,
        }
    }

    /// Wrap evm tx into solana, optionally add meta keys, to solana signature.
    async fn send_tx(
        &self,
        tx: evm::Transaction,
        meta_keys: HashSet<Pubkey>,
    ) -> EvmResult<Hex<H256>> {
        let (sender, mut receiver) = mpsc::channel::<EvmResult<Hex<H256>>>(1);

        if tx.gas_price < self.min_gas_price {
            return Err(Error::GasPriceTooLow {
                need: self.min_gas_price,
            });
        }

        let tx = PooledTransaction::new(tx, meta_keys, sender)
            .map_err(|source| evm_rpc::Error::EvmStateError { source })?;
        let tx = match self.pool.import(tx) {
            // tx was already processed on this bridge, return hash.
            Err(txpool::Error::AlreadyImported(h)) => return Ok(Hex(h)),
            Ok(tx) => tx,
            Err(source) => {
                warn!("Could not import tx to the pool");
                return Err(evm_rpc::Error::RuntimeError {
                    details: format!("Mempool error: {:?}", source),
                });
            }
        };

        if self.simulate {
            receiver.recv().await.unwrap()
        } else {
            Ok(tx.inner.tx_id_hash().into())
        }
    }

    async fn block_to_number(&self, block: Option<BlockId>) -> EvmResult<u64> {
        let block = block.unwrap_or_default();
        let block_num = match block {
            BlockId::Num(block) => block.0,
            BlockId::RelativeId(BlockRelId::Latest) => {
                let num: Hex<u64> = proxy_evm_rpc!(self.rpc_client_async, EthBlockNumber)?;
                num.0
            }
            _ => return Err(Error::BlockNotFound { block }),
        };
        Ok(block_num)
    }

    pub async fn is_transaction_landed(&self, hash: &H256) -> Option<bool> {
        async fn is_receipt_exists(bridge: &EvmBridge, hash: &H256) -> Option<bool> {
            bridge
                .rpc_client_async
                .get_evm_transaction_receipt(hash)
                .await
                .ok()
                .flatten()
                .map(|_receipt| true)
        }

        async fn is_signature_exists(bridge: &EvmBridge, hash: &H256) -> Option<bool> {
            match bridge.pool.signature_of_cached_transaction(hash) {
                Some(signature) => bridge
                    .rpc_client_async
                    .get_signature_status(&signature)
                    .await
                    .ok()
                    .flatten()
                    .map(|result| result.ok())
                    .flatten()
                    .map(|()| true),
                None => None,
            }
        }

        match is_receipt_exists(self, hash).await {
            Some(b) => Some(b),
            None => is_signature_exists(self, hash).await
        }
    }
}

#[derive(Debug)]
pub struct BridgeErpcImpl;

impl BridgeERPC for BridgeErpcImpl {
    type Metadata = Arc<EvmBridge>;

    #[instrument]
    fn accounts(&self, meta: Self::Metadata) -> EvmResult<Vec<Hex<Address>>> {
        Ok(meta.accounts.iter().map(|(k, _)| Hex(*k)).collect())
    }

    #[instrument]
    fn sign(&self, meta: Self::Metadata, address: Hex<Address>, data: Bytes) -> EvmResult<Bytes> {
        let secret_key = meta
            .accounts
            .get(&address.0)
            .ok_or(Error::KeyNotFound { account: address.0 })?;
        let mut message_data =
            format!("\x19Ethereum Signed Message:\n{}", data.0.len()).into_bytes();
        message_data.extend_from_slice(&data.0);
        let hash_to_sign = solana_sdk::keccak::hash(&message_data);
        let msg: Message = Message::from_slice(&hash_to_sign.to_bytes()).unwrap();
        let sig = SECP256K1.sign_recoverable(&msg, &secret_key);
        let (rid, sig) = { sig.serialize_compact() };

        let mut sig_data_arr = [0; 65];
        sig_data_arr[0..64].copy_from_slice(&sig[0..64]);
        sig_data_arr[64] = rid.to_i32() as u8;
        Ok(sig_data_arr.to_vec().into())
    }

    #[instrument]
    fn sign_transaction(
        &self,
        meta: Self::Metadata,
        tx: RPCTransaction,
    ) -> BoxFuture<EvmResult<Bytes>> {
        let future = async move {
            let address = tx.from.map(|a| a.0).unwrap_or_default();

            debug!("sign_transaction from = {}", address);

            let secret_key = meta
                .accounts
                .get(&address)
                .ok_or(Error::KeyNotFound { account: address })?;

            let nonce = match tx
                .nonce
                .map(|a| a.0)
                .or_else(|| meta.pool.transaction_count(&address)) {
                Some(n) => n,
                None => meta
                    .rpc_client_async
                    .get_evm_transaction_count(&address)
                    .await
                    .unwrap_or_default(),
            };

            let tx = UnsignedTransaction {
                nonce,
                gas_price: tx
                    .gas_price
                    .map(|a| a.0)
                    .unwrap_or_else(|| meta.min_gas_price),
                gas_limit: tx.gas.map(|a| a.0).unwrap_or_else(|| 30000000.into()),
                action: tx
                    .to
                    .map(|a| TransactionAction::Call(a.0))
                    .unwrap_or(TransactionAction::Create),
                value: tx.value.map(|a| a.0).unwrap_or_else(|| 0.into()),
                input: tx.input.map(|a| a.0).unwrap_or_default(),
            };

            let tx = tx.sign(secret_key, Some(meta.evm_chain_id));
            Ok(tx.rlp_bytes().to_vec().into())
        };
        Box::pin(future)
    }

    #[instrument]
    fn send_transaction(
        &self,
        meta: Self::Metadata,
        tx: RPCTransaction,
        meta_keys: Option<Vec<String>>,
    ) -> BoxFuture<EvmResult<Hex<H256>>> {
        let future = async move {
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

            let nonce = match tx
                .nonce
                .map(|a| a.0)
                .or_else(|| meta.pool.transaction_count(&address)) {
                Some(n) => n,
                None => meta
                    .rpc_client_async
                    .get_evm_transaction_count(&address)
                    .await
                    .unwrap_or_default(),
            };

            let tx_create = evm::UnsignedTransaction {
                nonce,
                gas_price: tx
                    .gas_price
                    .map(|a| a.0)
                    .unwrap_or_else(|| meta.min_gas_price),
                gas_limit: tx.gas.map(|a| a.0).unwrap_or_else(|| 30000000.into()),
                action: tx
                    .to
                    .map(|a| evm::TransactionAction::Call(a.0))
                    .unwrap_or(evm::TransactionAction::Create),
                value: tx.value.map(|a| a.0).unwrap_or_else(|| 0.into()),
                input: tx.input.map(|a| a.0).unwrap_or_default(),
            };

            let tx = tx_create.sign(secret_key, Some(meta.evm_chain_id));

            meta.send_tx(tx, meta_keys).await
        };

        Box::pin(future)
    }

    #[instrument]
    fn send_raw_transaction(
        &self,
        meta: Self::Metadata,
        bytes: Bytes,
        meta_keys: Option<Vec<String>>,
    ) -> BoxFuture<EvmResult<Hex<H256>>> {
        let future = async move {
            debug!("send_raw_transaction");
            let meta_keys = meta_keys
                .into_iter()
                .flatten()
                .map(|s| solana_sdk::pubkey::Pubkey::from_str(&s))
                .collect::<StdResult<HashSet<_>, _>>()
                .map_err(|e| into_native_error(e, meta.verbose_errors))?;

            let tx: compatibility::Transaction =
                rlp::decode(&bytes.0).with_context(|| RlpError {
                    struct_name: "RawTransaction".to_string(),
                    input_data: hex::encode(&bytes.0),
                })?;
            let tx: evm::Transaction = tx.into();

            // TODO: Check chain_id.
            // TODO: check gas price.

            let unsigned_tx: evm::UnsignedTransaction = tx.clone().into();
            let hash = unsigned_tx.signing_hash(Some(meta.evm_chain_id));
            debug!("loaded tx_hash = {}", hash);

            meta.send_tx(tx, meta_keys).await
        };

        Box::pin(future)
    }

    #[instrument]
    fn compilers(&self, _meta: Self::Metadata) -> EvmResult<Vec<String>> {
        Ok(vec![])
    }
}

#[derive(Debug)]
pub struct GeneralErpcProxy;
impl GeneralERPC for GeneralErpcProxy {
    type Metadata = Arc<EvmBridge>;

    #[instrument]
    fn network_id(&self, meta: Self::Metadata) -> EvmResult<String> {
        // NOTE: also we can get chain id from meta, but expects the same value
        Ok(format!("{}", meta.evm_chain_id))
    }

    #[instrument]
    // TODO: Add network info
    fn is_listening(&self, _meta: Self::Metadata) -> EvmResult<bool> {
        Ok(true)
    }

    #[instrument]
    fn peer_count(&self, _meta: Self::Metadata) -> EvmResult<Hex<usize>> {
        Ok(Hex(0))
    }

    #[instrument]
    fn chain_id(&self, meta: Self::Metadata) -> EvmResult<Hex<u64>> {
        Ok(Hex(meta.evm_chain_id))
    }

    #[instrument]
    fn sha3(&self, _meta: Self::Metadata, bytes: Bytes) -> EvmResult<Hex<H256>> {
        Ok(Hex(H256::from_slice(
            Keccak256::digest(bytes.0.as_slice()).as_slice(),
        )))
    }

    #[instrument]
    fn client_version(&self, _meta: Self::Metadata) -> EvmResult<String> {
        Ok(String::from("VelasEvm/v0.5.0"))
    }

    #[instrument]
    fn protocol_version(&self, _meta: Self::Metadata) -> EvmResult<String> {
        Ok(solana_version::semver!().into())
    }

    #[instrument]
    fn is_syncing(&self, _meta: Self::Metadata) -> EvmResult<bool> {
        Ok(false)
    }

    #[instrument]
    fn coinbase(&self, _meta: Self::Metadata) -> EvmResult<Hex<Address>> {
        Ok(Hex(Address::from_low_u64_be(0)))
    }

    #[instrument]
    fn is_mining(&self, _meta: Self::Metadata) -> EvmResult<bool> {
        Ok(false)
    }

    #[instrument]
    fn hashrate(&self, _meta: Self::Metadata) -> EvmResult<Hex<U256>> {
        Ok(Hex(U256::zero()))
    }

    #[instrument]
    fn gas_price(&self, meta: Self::Metadata) -> EvmResult<Hex<Gas>> {
        Ok(Hex(meta.min_gas_price))
    }
}

#[derive(Debug)]
pub struct ChainErpcProxy;
impl ChainERPC for ChainErpcProxy {
    type Metadata = Arc<EvmBridge>;

    #[instrument(skip(self))]
    // The same as get_slot
    fn block_number(&self, meta: Self::Metadata) -> BoxFuture<EvmResult<Hex<usize>>> {
        Box::pin(async move { proxy_evm_rpc!(meta.rpc_client_async, EthBlockNumber) })
    }

    #[instrument(skip(self))]
    fn balance(
        &self,
        meta: Self::Metadata,
        address: Hex<Address>,
        block: Option<BlockId>,
    ) -> BoxFuture<EvmResult<Hex<U256>>> {
        Box::pin(async move {
            proxy_evm_rpc!(
                meta.rpc_client_async,
                EthGetBalance,
                address,
                block
            )
        })
    }

    #[instrument(skip(self))]
    fn storage_at(
        &self,
        meta: Self::Metadata,
        address: Hex<Address>,
        data: Hex<U256>,
        block: Option<BlockId>,
    ) -> BoxFuture<EvmResult<Hex<H256>>> {
        Box::pin(async move {
            proxy_evm_rpc!(
                meta.rpc_client_async,
                EthGetStorageAt,
                address,
                data,
                block
            )
        })
    }

    #[instrument(skip(self))]
    fn transaction_count(
        &self,
        meta: Self::Metadata,
        address: Hex<Address>,
        block: Option<BlockId>,
    ) -> BoxFuture<EvmResult<Hex<U256>>> {
        if matches!(block, Some(BlockId::RelativeId(BlockRelId::Pending))) {
            if let Some(tx_count) = meta.pool.transaction_count(&address.0) {
                return Box::pin(ready(Ok(Hex(tx_count))));
            }
        }

        Box::pin(async move {
            proxy_evm_rpc!(
                meta.rpc_client_async,
                EthGetTransactionCount,
                address,
                block
            )
        })
    }

    #[instrument(skip(self))]
    fn block_transaction_count_by_number(
        &self,
        meta: Self::Metadata,
        block: BlockId,
    ) -> BoxFuture<EvmResult<Hex<usize>>> {
        Box::pin(async move {
            proxy_evm_rpc!(
                meta.rpc_client_async,
                EthGetBlockTransactionCountByNumber,
                block
            )
        })
    }

    #[instrument(skip(self))]
    fn block_transaction_count_by_hash(
        &self,
        meta: Self::Metadata,
        block_hash: Hex<H256>,
    ) -> BoxFuture<EvmResult<Hex<usize>>> {
        Box::pin(async move {
            proxy_evm_rpc!(
                meta.rpc_client_async,
                EthGetBlockTransactionCountByHash,
                block_hash
            )
        })
    }

    #[instrument(skip(self))]
    fn code(
        &self,
        meta: Self::Metadata,
        address: Hex<Address>,
        block: Option<BlockId>,
    ) -> BoxFuture<EvmResult<Bytes>> {
        Box::pin(async move {
            proxy_evm_rpc!(
                meta.rpc_client_async,
                EthGetCode,
                address,
                block
            )
        })
    }

    #[instrument(skip(self))]
    fn block_by_hash(
        &self,
        meta: Self::Metadata,
        block_hash: Hex<H256>,
        full: bool,
    ) -> BoxFuture<EvmResult<Option<RPCBlock>>> {
        if block_hash == Hex(H256::zero()) {
            Box::pin(ready(Ok(Some(RPCBlock::default()))))
        } else {
            Box::pin(async move {
                proxy_evm_rpc!(
                    meta.rpc_client_async,
                    EthGetBlockByHash,
                    block_hash,
                    full
                )
                    .map(|o: Option<_>| o.map(compatibility::patch_block))
            })
        }
    }

    #[instrument(skip(self))]
    fn block_by_number(
        &self,
        meta: Self::Metadata,
        block: BlockId,
        full: bool,
    ) -> BoxFuture<EvmResult<Option<RPCBlock>>> {
        if block == BlockId::Num(0x0.into()) {
            Box::pin(ready(Ok(Some(RPCBlock::default()))))
        } else {
            Box::pin(async move {
                proxy_evm_rpc!(
                    meta.rpc_client_async,
                    EthGetBlockByNumber,
                    block,
                    full
                )
                    .map(|o: Option<_>| o.map(compatibility::patch_block))
            })
        }
    }

    #[instrument(skip(self))]
    fn transaction_by_hash(
        &self,
        meta: Self::Metadata,
        tx_hash: Hex<H256>,
    ) -> BoxFuture<EvmResult<Option<RPCTransaction>>> {
        // TODO: chain all possible outcomes properly
        if let Some(tx) = meta.pool.transaction_by_hash(tx_hash) {
            if let Ok(tx) = RPCTransaction::from_transaction((**tx).clone().into()) {
                // TODO: should we `patch` tx?
                return Box::pin(ready(Ok(Some(tx))));
            }
        }
        Box::pin(async move {
            proxy_evm_rpc!(
                meta.rpc_client_async,
                EthGetTransactionByHash,
                tx_hash
            )
                .map(|o: Option<_>| o.map(compatibility::patch_tx))
        })
    }

    #[instrument(skip(self))]
    fn transaction_by_block_hash_and_index(
        &self,
        meta: Self::Metadata,
        block_hash: Hex<H256>,
        tx_id: Hex<usize>,
    ) -> BoxFuture<EvmResult<Option<RPCTransaction>>> {
        Box::pin(async move {
            proxy_evm_rpc!(
                meta.rpc_client_async,
                EthGetTransactionByBlockHashAndIndex,
                block_hash,
                tx_id
            )
        })
    }

    #[instrument(skip(self))]
    fn transaction_by_block_number_and_index(
        &self,
        meta: Self::Metadata,
        block: BlockId,
        tx_id: Hex<usize>,
    ) -> BoxFuture<EvmResult<Option<RPCTransaction>>> {
        Box::pin(async move {
            proxy_evm_rpc!(
                meta.rpc_client_async,
                EthGetTransactionByBlockNumberAndIndex,
                block,
                tx_id
            )
        })
    }

    #[instrument(skip(self))]
    fn transaction_receipt(
        &self,
        meta: Self::Metadata,
        tx_hash: Hex<H256>,
    ) -> BoxFuture<EvmResult<Option<RPCReceipt>>> {
        Box::pin(async move {
            proxy_evm_rpc!(
                meta.rpc_client_async,
                EthGetTransactionReceipt,
                tx_hash
            )
        })
    }

    #[instrument(skip(self))]
    fn call(
        &self,
        meta: Self::Metadata,
        tx: RPCTransaction,
        block: Option<BlockId>,
        meta_keys: Option<Vec<String>>,
    ) -> BoxFuture<EvmResult<Bytes>> {
        Box::pin(async move {
            proxy_evm_rpc!(
                meta.rpc_client_async,
                EthCall,
                tx,
                block,
                meta_keys
            )
        })
    }

    #[instrument(skip(self))]
    fn estimate_gas(
        &self,
        meta: Self::Metadata,
        tx: RPCTransaction,
        block: Option<BlockId>,
        meta_keys: Option<Vec<String>>,
    ) -> BoxFuture<EvmResult<Hex<Gas>>> {
        Box::pin(async move {
            proxy_evm_rpc!(
                meta.rpc_client_async,
                EthEstimateGas,
                tx,
                block,
                meta_keys
            )
        })
    }

    #[instrument(skip(self, meta))]
    fn logs(
        &self,
        meta: Self::Metadata,
        mut log_filter: RPCLogFilter,
    ) -> BoxFuture<EvmResult<Vec<RPCLog>>> {
        Box::pin(async move {
            let starting_block = meta.block_to_number(log_filter.from_block).await?;
            let ending_block = meta.block_to_number(log_filter.to_block).await?;

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
            let mut collector = Vec::new();
            while starting <= ending_block {
                let ending = (starting.saturating_add(MAX_NUM_BLOCKS_IN_BATCH)).min(ending_block);
                log_filter.from_block = Some(starting.into());
                log_filter.to_block = Some(ending.into());

                let cloned_filter = log_filter.clone();
                let cloned_meta = meta.clone();
                // Parallel execution:
                collector.push(tokio::task::spawn(async move {
                    info!("filter = {:?}", cloned_filter);
                    let result: EvmResult<Vec<RPCLog>> =
                        proxy_evm_rpc!(@silent cloned_meta.rpc_client_async, EthGetLogs, cloned_filter);
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

    #[instrument]
    fn uncle_by_block_hash_and_index(
        &self,
        _meta: Self::Metadata,
        _block_hash: Hex<H256>,
        _uncle_id: Hex<U256>,
    ) -> EvmResult<Option<RPCBlock>> {
        Ok(None)
    }

    #[instrument]
    fn uncle_by_block_number_and_index(
        &self,
        _meta: Self::Metadata,
        _block: String,
        _uncle_id: Hex<U256>,
    ) -> EvmResult<Option<RPCBlock>> {
        Ok(None)
    }

    #[instrument]
    fn block_uncles_count_by_hash(
        &self,
        _meta: Self::Metadata,
        _block_hash: Hex<H256>,
    ) -> EvmResult<Hex<usize>> {
        Ok(Hex(0))
    }

    #[instrument]
    fn block_uncles_count_by_number(
        &self,
        _meta: Self::Metadata,
        _block: String,
    ) -> EvmResult<Hex<usize>> {
        Ok(Hex(0))
    }
}

#[derive(Debug)]
pub struct TraceErpcProxy;
impl TraceERPC for TraceErpcProxy {
    type Metadata = Arc<EvmBridge>;

    #[instrument(skip(self))]
    fn trace_call(
        &self,
        meta: Self::Metadata,
        tx: RPCTransaction,
        traces: Vec<String>,
        block: Option<BlockId>,
        meta_info: Option<TraceMeta>,
    ) -> BoxFuture<EvmResult<evm_rpc::trace::TraceResultsWithTransactionHash>> {
        Box::pin(async move {
            proxy_evm_rpc!(
                meta.rpc_client_async,
                EthTraceCall,
                tx,
                traces,
                block,
                meta_info
            )
        })
    }

    #[instrument(skip(self))]
    fn trace_call_many(
        &self,
        meta: Self::Metadata,
        tx_traces: Vec<(RPCTransaction, Vec<String>, Option<TraceMeta>)>,
        block: Option<BlockId>,
    ) -> BoxFuture<EvmResult<Vec<evm_rpc::trace::TraceResultsWithTransactionHash>>> {
        Box::pin(async move {
            proxy_evm_rpc!(
                meta.rpc_client_async,
                EthTraceCallMany,
                tx_traces,
                block
            )
        })
    }

    #[instrument(skip(self))]
    fn trace_replay_transaction(
        &self,
        meta: Self::Metadata,
        tx_hash: Hex<H256>,
        traces: Vec<String>,
        meta_info: Option<TraceMeta>,
    ) -> BoxFuture<EvmResult<Option<trace::TraceResultsWithTransactionHash>>> {
        Box::pin(async move {
            proxy_evm_rpc!(
                meta.rpc_client_async,
                EthTraceReplayTransaction,
                tx_hash,
                traces,
                meta_info
            )
        })
    }

    #[instrument(skip(self))]
    fn trace_replay_block(
        &self,
        meta: Self::Metadata,
        block: BlockId,
        traces: Vec<String>,
        meta_info: Option<TraceMeta>,
    ) -> BoxFuture<EvmResult<Vec<trace::TraceResultsWithTransactionHash>>> {
        Box::pin(async move {
            proxy_evm_rpc!(
                meta.rpc_client_async,
                EthTraceReplayBlock,
                block,
                traces,
                meta_info
            )
        })
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
    #[structopt(long = "min-gas-price")]
    min_gas_price: Option<String>,
    #[structopt(long = "verbose-errors")]
    verbose_errors: bool,
    #[structopt(long = "no-simulate")]
    no_simulate: bool, // parse inverted to keep false default
    /// Maximum number of blocks to return in eth_getLogs rpc.
    #[structopt(long = "max-logs-block-count", default_value = "500")]
    max_logs_blocks: u64,

    #[structopt(long = "jaeger-collector-url", short = "j")]
    jaeger_collector_url: Option<String>,
}

impl Args {
    fn min_gas_price_or_default(&self) -> U256 {
        let gwei: U256 = 1_000_000_000.into();
        fn min_gas_price() -> U256 {
            //TODO: Add gas logic
            (21000 * solana_evm_loader_program::scope::evm::LAMPORTS_TO_GWEI_PRICE
                / DEFAULT_TARGET_LAMPORTS_PER_SIGNATURE)
                .into() // 21000 is smallest call in evm
        }

        let mut gas_price = match self
            .min_gas_price
            .as_ref()
            .and_then(|gas_price| U256::from_dec_str(gas_price).ok())
        {
            Some(gas_price) => {
                info!(r#"--min-gas-price is set to {}"#, &gas_price);
                gas_price
            }
            None => {
                let default_price = min_gas_price();
                warn!(
                    r#"Value of "--min-gas-price" is not set or unable to parse. Default value is: {}"#,
                    default_price
                );
                default_price
            }
        };
        // ceil to gwei for metamask
        gas_price += gwei - 1;
        gas_price - gas_price % gwei
    }
}

const SECRET_KEY_DUMMY: [u8; 32] = [1; 32];

#[paw::main]
#[tokio::main]
async fn main(args: Args) -> StdResult<(), Box<dyn std::error::Error>> {
    env_logger::init();
    let min_gas_price = args.min_gas_price_or_default();
    let keyfile_path = args
        .keyfile
        .unwrap_or_else(|| solana_cli_config::Config::default().keypair_path);
    let server_path = args.rpc_address;
    let binding_address = args.binding_address;

    if let Some(collector) = args.jaeger_collector_url {
        // init tracer
        let fmt_filter = std::env::var("RUST_LOG")
            .ok()
            .and_then(|rust_log| match rust_log.parse::<Targets>() {
                Ok(targets) => Some(targets),
                Err(e) => {
                    eprintln!("failed to parse `RUST_LOG={:?}`: {}", rust_log, e);
                    None
                }
            })
            .unwrap_or_else(|| Targets::default().with_default(LevelFilter::WARN));

        let tracer = opentelemetry_jaeger::new_pipeline()
            .with_service_name("evm-bridge-tracer")
            .with_collector_endpoint(collector)
            .install_batch(opentelemetry::runtime::Tokio)
            .unwrap();
        let opentelemetry = tracing_opentelemetry::layer().with_tracer(tracer);
        let registry = tracing_subscriber::registry()
            .with(tracing_subscriber::fmt::layer().with_filter(fmt_filter))
            .with(opentelemetry);

        registry.try_init().unwrap();
    }

    let meta = EvmBridge::new(
        args.evm_chain_id,
        &keyfile_path,
        vec![evm::SecretKey::from_slice(&SECRET_KEY_DUMMY).unwrap()],
        server_path,
        args.verbose_errors,
        !args.no_simulate, // invert argument
        args.max_logs_blocks,
        min_gas_price,
    );
    let meta = Arc::new(meta);

    let mut io = MetaIoHandler::with_middleware(ProxyMiddleware {});

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
    let ether_chain = ChainErpcProxy;
    io.extend_with(ether_chain.to_delegate());
    let ether_general = GeneralErpcProxy;
    io.extend_with(ether_general.to_delegate());
    let ether_trace = TraceErpcProxy;
    io.extend_with(ether_trace.to_delegate());

    let mempool_worker = worker_deploy(meta.clone());

    let cleaner = worker_cleaner(meta.clone());

    let signature_checker = worker_signature_checker(meta.clone());

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

    let _cleaner = tokio::task::spawn(cleaner);
    let _signature_checker = tokio::task::spawn(signature_checker);
    let mempool_task = tokio::task::spawn(mempool_worker);
    let servers_waiter = tokio::task::spawn_blocking(|| {
        ws_server.wait().unwrap();
        server.wait();
    });

    // wait for any failure/stops.
    tokio::select! {
        _ = servers_waiter => {
            println!("Server exited.");
        }
        _ = mempool_task => {
            println!("Mempool task exited.");
        }
    };
    Ok(())
}

async fn send_and_confirm_transactions<T: Signers>(
    rpc_client: &AsyncRpcClient,
    mut transactions: Vec<solana::Transaction>,
    signer_keys: &T,
) -> StdResult<(), anyhow::Error> {
    const SEND_RETRIES: usize = 5;
    const STATUS_RETRIES: usize = 15;

    for _ in 0..SEND_RETRIES {
        // Send all transactions
        let mut transactions_signatures = vec![];
        for transaction in transactions.drain(..) {
            if cfg!(not(test)) {
                // Delay ~1 tick between write transactions in an attempt to reduce AccountInUse errors
                // when all the write transactions modify the same program account (eg, deploying a
                // new program)
                sleep(Duration::from_millis(MS_PER_TICK)).await;
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
                .await
                .map_err(|e| error!("Send transaction error: {:?}", e))
                .ok();

            transactions_signatures.push((transaction, signature));
        }

        for _ in 0..STATUS_RETRIES {
            // Collect statuses for all the transactions, drop those that are confirmed

            if cfg!(not(test)) {
                // Retry twice a second
                sleep(Duration::from_millis(500)).await;
            }

            let mut retained = vec![];
            for (transaction, signature) in transactions_signatures {
                if let Some(signature) = signature {
                    if rpc_client.get_signature_statuses(&[signature])
                        .await
                        .ok()
                        .and_then(|RpcResponse { mut value, .. }| value.remove(0))
                        .and_then(|status| status.confirmations)
                        .map(|confirmations| confirmations == 0) // retain unconfirmed only
                        .unwrap_or(true) {
                        retained.push((transaction, Some(signature)));
                    }
                } else {
                    retained.push((transaction, signature));
                }
            }
            transactions_signatures = retained;

            if transactions_signatures.is_empty() {
                return Ok(());
            }
        }

        // Re-sign any failed transactions with a new blockhash and retry
        let (blockhash, _) = rpc_client
            .get_new_blockhash(&transactions_signatures[0].0.message().recent_blockhash).await?;

        for (mut transaction, _) in transactions_signatures {
            transaction.try_sign(signer_keys, blockhash)?;
            debug!("Resending {:?}", transaction);
            transactions.push(transaction);
        }
    }
    Err(anyhow::Error::msg("Transactions failed"))
}

#[cfg(test)]
mod tests {
    use crate::{BridgeErpcImpl, EthPool, EvmBridge, AsyncRpcClient, SystemClock};
    use evm_rpc::{BridgeERPC, Hex};
    use evm_state::Address;
    use secp256k1::SecretKey;
    use solana_client::rpc_client::RpcClient;
    use solana_sdk::signature::Keypair;
    use std::str::FromStr;
    use std::sync::Arc;

    #[test]
    fn test_eth_sign() {
        let signing_key =
            SecretKey::from_str("c21020a52198632ae7d5c1adaa3f83da2e0c98cf541c54686ddc8d202124c086")
                .unwrap();
        let public_key = evm_state::PublicKey::from_secret_key(evm_state::SECP256K1, &signing_key);
        let public_key = evm_state::addr_from_public_key(&public_key);
        let bridge = Arc::new(EvmBridge {
            evm_chain_id: 111u64,
            key: Keypair::new(),
            accounts: vec![(public_key, signing_key)].into_iter().collect(),
            rpc_client: RpcClient::new("".to_string()),
            rpc_client_async: AsyncRpcClient::new("".to_string()),
            verbose_errors: true,
            simulate: false,
            max_logs_blocks: 0u64,
            pool: EthPool::new(SystemClock),
            min_gas_price: 0.into(),
        });

        let rpc = BridgeErpcImpl {};
        let address = Address::from_str("0x141a4802f84bb64c0320917672ef7D92658e964e").unwrap();
        let data = "qwe".as_bytes().to_vec();
        let res = rpc.sign(bridge, Hex(address), data.into()).unwrap();
        assert_eq!(res.to_string(), "0xb734e224f0f92d89825f3f69bf03924d7d2f609159d6ce856d37a58d7fcbc8eb6d224fd73f05217025ed015283133c92888211b238272d87ec48347f05ab42a000");
    }
}
