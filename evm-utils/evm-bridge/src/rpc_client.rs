use {
    evm_rpc::{BlockId, Hex, RPCBlock, RPCLog, RPCLogFilter, RPCReceipt, RPCTransaction},
    evm_state::{Address, H256, U256},
    log::*,
    reqwest::{
        header::{CONTENT_TYPE, RETRY_AFTER},
        StatusCode,
    },
    serde::Deserialize,
    serde_json::{json, Value},
    solana_client::{
        client_error::{ClientError, ClientErrorKind, Result as ClientResult},
        rpc_client::serialize_and_encode,
        rpc_config::RpcSendTransactionConfig,
        rpc_custom_error,
        rpc_request::{RpcError, RpcRequest, RpcResponseErrorData},
        rpc_response::{Response as RpcResponse, *},
    },
    solana_evm_loader_program::scope::solana,
    solana_sdk::{
        clock::{Slot, DEFAULT_MS_PER_SLOT},
        commitment_config::CommitmentConfig,
        fee_calculator::FeeCalculator,
        hash::Hash,
        message::Message,
        signature::Signature,
        transaction::uses_durable_nonce,
    },
    solana_transaction_status::{TransactionStatus, UiTransactionEncoding},
    std::{
        sync::{
            atomic::{AtomicU64, Ordering},
            Arc,
        },
        time::{Duration, Instant},
    },
    tokio::{sync::RwLock, time::sleep},
};

#[derive(Deserialize, Debug)]
struct RpcErrorObject {
    code: i64,
    message: String,
    #[allow(dead_code)]
    #[serde(default)]
    data: Value,
}

pub struct AsyncRpcClient {
    client: Arc<reqwest::Client>,
    url: String,
    request_id: AtomicU64,
    node_version: RwLock<Option<semver::Version>>,
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
                .expect("build rpc client"),
        );

        Self {
            client,
            url,
            request_id: AtomicU64::new(0),
            node_version: RwLock::new(None),
        }
    }

    pub async fn send_request(&self, request: RpcRequest, params: Value) -> ClientResult<Value> {
        let request_id = self.request_id.fetch_add(1, Ordering::Relaxed);
        let request_json = request.build_request_json(request_id, params).to_string();
        match self._send_request(request_json).await {
            Ok(response) => {
                let json: Value = response.json().await?;
                if json["error"].is_object() {
                    match serde_json::from_value::<RpcErrorObject>(json["error"].clone()) {
                        Ok(rpc_error_object) => {
                            let data = match rpc_error_object.code {
                                rpc_custom_error::JSON_RPC_SERVER_ERROR_SEND_TRANSACTION_PREFLIGHT_FAILURE => {
                                    match serde_json::from_value::<RpcSimulateTransactionResult>(json["error"]["data"].clone()) {
                                        Ok(data) => RpcResponseErrorData::SendTransactionPreflightFailure(data),
                                        Err(err) => {
                                            debug!("Failed to deserialize RpcSimulateTransactionResult: {}", err);
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
                    }
                } else {
                    Ok(json["result"].clone())
                }
            }
            Err(err) => Err(err.into()),
        }
    }

    pub(crate) async fn _send_request(
        &self,
        request_json: String,
    ) -> reqwest::Result<reqwest::Response> {
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
                        return response.error_for_status();
                    }
                    return Ok(response);
                }
                other => return other,
            }
        }
    }

    pub async fn get_evm_block_by_hash(
        &self,
        block_hash: H256,
        full: bool,
    ) -> ClientResult<Option<RPCBlock>> {
        self.send(RpcRequest::EthGetBlockByHash, json!([block_hash, full]))
            .await
    }

    pub async fn get_evm_block_by_number(
        &self,
        block: BlockId,
        full: bool,
    ) -> ClientResult<Option<RPCBlock>> {
        self.send(RpcRequest::EthGetBlockByNumber, json!([block, full]))
            .await
    }

    pub async fn get_evm_block_number(&self) -> ClientResult<u64> {
        self.send::<Hex<_>>(RpcRequest::EthBlockNumber, json!([]))
            .await
            .map(|h| h.0)
    }

    pub async fn get_evm_logs(&self, filter: &RPCLogFilter) -> ClientResult<Vec<RPCLog>> {
        self.send(RpcRequest::EthGetLogs, json!([filter])).await
    }

    pub async fn get_evm_transaction_by_hash(
        &self,
        tx_hash: H256,
    ) -> ClientResult<Option<RPCTransaction>> {
        self.send(RpcRequest::EthGetTransactionByHash, json!([tx_hash]))
            .await
    }

    pub async fn get_evm_transaction_count(&self, address: &Address) -> ClientResult<U256> {
        self.send(RpcRequest::EthGetTransactionCount, json!([*address]))
            .await
    }

    pub async fn get_evm_transaction_receipt(
        &self,
        hash: &H256,
    ) -> ClientResult<Option<RPCReceipt>> {
        self.send::<Option<RPCReceipt>>(RpcRequest::EthGetTransactionReceipt, json!([*hash]))
            .await
    }

    pub async fn get_version(&self) -> ClientResult<RpcVersionInfo> {
        self.send(RpcRequest::GetVersion, Value::Null).await
    }

    async fn get_node_version(&self) -> Result<semver::Version, RpcError> {
        let r_node_version = self.node_version.read().await;
        if let Some(version) = &*r_node_version {
            Ok(version.clone())
        } else {
            drop(r_node_version);
            let mut w_node_version = self.node_version.write().await;
            let node_version = self.get_version().await.map_err(|e| {
                RpcError::RpcRequestError(format!("cluster version query failed: {}", e))
            })?;
            let node_version = semver::Version::parse(&node_version.solana_core).map_err(|e| {
                RpcError::RpcRequestError(format!("failed to parse cluster version: {}", e))
            })?;
            *w_node_version = Some(node_version.clone());
            Ok(node_version)
        }
    }

    #[deprecated(
        since = "0.6.0",
        note = "Please `get_latest_blockhash_with_commitment` and `get_fee_for_message` instead"
    )]
    #[allow(deprecated)]
    pub async fn get_fee_calculator_for_blockhash_with_commitment(
        &self,
        blockhash: &Hash,
        commitment_config: CommitmentConfig,
    ) -> RpcResult<Option<FeeCalculator>> {
        let RpcResponse { context, value } = self
            .send::<RpcResponse<Option<RpcFeeCalculator>>>(
                RpcRequest::GetFeeCalculatorForBlockhash,
                json!([blockhash.to_string(), commitment_config]),
            )
            .await?;

        Ok(RpcResponse {
            context,
            value: value.map(|rf| rf.fee_calculator),
        })
    }

    #[allow(deprecated)]
    #[allow(dead_code)]
    pub async fn get_fee_for_message(&self, message: &Message) -> ClientResult<u64> {
        if self.get_node_version().await? < semver::Version::new(0, 6, 0) {
            let fee_calculator = self
                .get_fee_calculator_for_blockhash_with_commitment(
                    &message.recent_blockhash,
                    CommitmentConfig::default(),
                )
                .await?
                .value
                .ok_or_else(|| ClientErrorKind::Custom("Invalid blockhash".to_string()))?;
            Ok(fee_calculator
                .lamports_per_signature
                .saturating_mul(message.header.num_required_signatures as u64))
        } else {
            let serialized_encoded =
                serialize_and_encode::<Message>(message, UiTransactionEncoding::Base64)?;
            let result = self
                .send::<Response<Option<u64>>>(
                    RpcRequest::GetFeeForMessage,
                    json!([serialized_encoded, CommitmentConfig::default()]),
                )
                .await?;
            result
                .value
                .ok_or_else(|| ClientErrorKind::Custom("Invalid blockhash".to_string()).into())
        }
    }

    pub async fn get_signature_status_with_commitment(
        &self,
        signature: &Signature,
        commitment_config: CommitmentConfig,
    ) -> ClientResult<Option<solana_sdk::transaction::Result<()>>> {
        let result: RpcResponse<Vec<Option<TransactionStatus>>> = self
            .send(
                RpcRequest::GetSignatureStatuses,
                json!([[signature.to_string()]]),
            )
            .await?;
        Ok(result.value[0]
            .clone()
            .filter(|result| result.satisfies_commitment(commitment_config))
            .map(|status_meta| status_meta.status))
    }

    pub async fn get_signature_status(
        &self,
        signature: &Signature,
    ) -> ClientResult<Option<solana_sdk::transaction::Result<()>>> {
        self.get_signature_status_with_commitment(signature, CommitmentConfig::processed())
            .await
    }

    #[allow(deprecated)]
    pub async fn is_blockhash_valid(
        &self,
        blockhash: &Hash,
        commitment: CommitmentConfig,
    ) -> ClientResult<bool> {
        let result = if self.get_node_version().await? < semver::Version::new(0, 6, 0) {
            self.get_fee_calculator_for_blockhash_with_commitment(blockhash, commitment)
                .await?
                .value
                .is_some()
        } else {
            self.send::<Response<bool>>(
                RpcRequest::IsBlockhashValid,
                json!([blockhash.to_string(), commitment,]),
            )
            .await?
            .value
        };
        Ok(result)
    }

    pub async fn send_and_confirm_transaction_with_config(
        &self,
        transaction: &solana::Transaction,
        config: RpcSendTransactionConfig,
    ) -> ClientResult<Signature> {
        const SEND_RETRIES: usize = 20;
        const GET_STATUS_RETRIES: usize = 40;

        'sending: for _ in 0..SEND_RETRIES {
            let signature = self
                .send_transaction_with_config(transaction, config)
                .await?;

            let recent_blockhash = if uses_durable_nonce(transaction).is_some() {
                let (recent_blockhash, ..) = self
                    .get_latest_blockhash_with_commitment(CommitmentConfig::processed())
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
                        if !self
                            .is_blockhash_valid(&recent_blockhash, CommitmentConfig::processed())
                            .await?
                        {
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

    pub async fn send_transaction_with_config(
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
        let serialized_encoded =
            serialize_and_encode::<solana::Transaction>(transaction, encoding)?;
        let request = RpcRequest::SendTransaction;
        let response = match self
            .send_request(request, json!([serialized_encoded, config]))
            .await
        {
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

    pub async fn get_signature_statuses(
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

    #[allow(deprecated)]
    pub async fn get_latest_blockhash_with_commitment(
        &self,
        commitment_config: CommitmentConfig,
    ) -> RpcResult<(Hash, Slot)> {
        let (context, blockhash, last_valid_slot) = if let Ok(RpcResponse {
            context,
            value:
                RpcFees {
                    blockhash,
                    last_valid_slot,
                    ..
                },
        }) = self
            .send::<RpcResponse<RpcFees>>(RpcRequest::GetFees, json!([commitment_config]))
            .await
        {
            (context, blockhash, last_valid_slot)
        } else if let Ok(RpcResponse {
            context,
            value:
                DeprecatedRpcFees {
                    blockhash,
                    last_valid_slot,
                    ..
                },
        }) = self
            .send::<RpcResponse<DeprecatedRpcFees>>(RpcRequest::GetFees, json!([commitment_config]))
            .await
        {
            (context, blockhash, last_valid_slot)
        } else if let Ok(RpcResponse {
            context,
            value:
                RpcBlockhash {
                    blockhash,
                    last_valid_block_height: _,
                },
        }) = self
            .send::<RpcResponse<RpcBlockhash>>(
                RpcRequest::GetLatestBlockhash,
                json!([commitment_config]),
            )
            .await
        {
            (context, blockhash, 0)
        } else {
            return Err(ClientError::new_with_request(
                RpcError::ParseError("RpcBlockhashFeeCalculator or RpcFees".to_string()).into(),
                RpcRequest::GetLatestBlockhash,
            ));
        };

        let blockhash = blockhash.parse().map_err(|_| {
            ClientError::new_with_request(
                RpcError::ParseError("Hash".to_string()).into(),
                RpcRequest::GetLatestBlockhash,
            )
        })?;
        Ok(RpcResponse {
            context,
            value: (blockhash, last_valid_slot),
        })
    }

    pub async fn get_recent_blockhash(&self) -> ClientResult<Hash> {
        let (blockhash, _last_valid_slot) = self
            .get_latest_blockhash_with_commitment(CommitmentConfig::processed())
            .await?
            .value;
        Ok(blockhash)
    }

    pub async fn get_new_blockhash(&self, blockhash: &Hash) -> ClientResult<Hash> {
        let mut num_retries = 0;
        let start = Instant::now();
        while start.elapsed().as_secs() < 5 {
            if let Ok(new_blockhash) = self.get_recent_blockhash().await {
                if new_blockhash != *blockhash {
                    return Ok(new_blockhash);
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

    pub async fn get_minimum_balance_for_rent_exemption(
        &self,
        data_len: usize,
    ) -> ClientResult<u64> {
        let request = RpcRequest::GetMinimumBalanceForRentExemption;
        let minimum_balance_json = self
            .send_request(request, json!([data_len]))
            .await
            .map_err(|err| err.into_with_request(request))?;

        let minimum_balance: u64 = serde_json::from_value(minimum_balance_json)
            .map_err(|err| ClientError::new_with_request(err.into(), request))?;
        trace!("Response minimum balance {} {}", data_len, minimum_balance);
        Ok(minimum_balance)
    }

    pub(crate) async fn send<T>(&self, request: RpcRequest, params: Value) -> ClientResult<T>
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
