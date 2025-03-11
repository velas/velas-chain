use {
    crate::EvmBridge,
    evm_state::rand::{thread_rng, Rng},
    jsonrpc_core::{
        futures_util::future::{Either, FutureExt},
        Call, Error, ErrorCode, Failure, FutureOutput, FutureResponse, Id, Middleware, Output,
        Params, Request, Response, Success,
        Version::{self, V2},
    },
    log::{debug, error},
    serde_json::Value,
    solana_rpc::{
        middleware::{patch_calls, restore_original_call},
        rpc::BatchId,
    },
    std::{future::ready, sync::Arc, time::Instant},
};

async fn redirect(
    meta: Arc<EvmBridge>,
    call_json: String,
    jsonrpc: Option<Version>,
    id: Id,
) -> Option<Output> {
    debug!("Method not found! Redirecting to node...");
    let response = match meta.rpc_client._send_request(call_json).await {
        Ok(response) => response,
        Err(err) => {
            let mut error = Error::internal_error();
            error.message = err.to_string();
            return Some(Output::Failure(Failure { jsonrpc, error, id }));
        }
    };
    let json: Value = match response.json().await {
        Ok(json) => json,
        Err(err) => {
            error!("Node rpc call error: {}", err.to_string());
            let mut error = Error::internal_error();
            error.message = err.to_string();
            return Some(Output::Failure(Failure { jsonrpc, error, id }));
        }
    };
    debug!("Node response: {}", json);
    let output = if json["error"].is_null() {
        Output::Success(Success {
            jsonrpc,
            result: json["result"].clone(),
            id,
        })
    } else {
        Output::Failure(Failure {
            jsonrpc,
            error: serde_json::from_value(json["error"].clone()).ok()?,
            id,
        })
    };
    Some(output)
}

#[derive(Clone, Default)]
pub struct ProxyMiddleware;
impl Middleware<Arc<EvmBridge>> for ProxyMiddleware {
    type Future = FutureResponse;
    type CallFuture = FutureOutput;

    fn on_request<F, X>(
        &self,
        request: Request,
        meta: Arc<EvmBridge>,
        next: F,
    ) -> Either<Self::Future, X>
    where
        F: Fn(Request, Arc<EvmBridge>) -> X + Send + Sync,
        X: std::future::Future<Output = Option<Response>> + Send + 'static,
    {
        if let Request::Batch(calls) = request {
            let mut rng = thread_rng();
            let mut batch_id = rng.gen::<BatchId>();
            while !meta.batch_state_map.add_batch(batch_id) {
                batch_id = rng.gen();
            }
            debug!("Create batch {}", batch_id);
            let patched_request = Request::Batch(patch_calls(calls, batch_id));
            Either::Left(Box::pin(next(patched_request, meta.clone()).map(
                move |res| {
                    meta.batch_state_map.remove_batch(&batch_id);
                    res
                },
            )))
        } else {
            Either::Right(next(request, meta))
        }
    }

    fn on_call<F, X>(
        &self,
        call: Call,
        meta: Arc<EvmBridge>,
        next: F,
    ) -> Either<Self::CallFuture, X>
    where
        F: FnOnce(Call, Arc<EvmBridge>) -> X + Send,
        X: std::future::Future<Output = Option<Output>> + Send + 'static,
    {
        let (call, skip_redirect) = match patch_subchain_call(meta.clone(), call.clone()) {
            Some(subchain_call) => (subchain_call, false),
            // Skip redirect if method forced for subchain, but not found in the list
            None => (call, true),
        };

        let call_json = match serde_json::to_string(&call) {
            Ok(str) => str,
            Err(_) => {
                return Either::Left(Box::pin(ready(Some(Output::invalid_request(
                    Id::Null,
                    Some(V2),
                )))))
            }
        };

        let (original_call, batch_id) = match restore_original_call(call) {
            Ok((original_call, batch_id)) => (original_call, batch_id),
            Err(call) => {
                return Either::Left(Box::pin(next(call, meta.clone()).then(
                    move |res| async move {
                        match res {
                            Some(Output::Failure(Failure { jsonrpc, error, id }))
                                if error.code == ErrorCode::MethodNotFound && !skip_redirect =>
                            {
                                redirect(meta, call_json, jsonrpc, id).await
                            }
                            _ => res,
                        }
                    },
                )))
            }
        };
        let next_future = next(Call::MethodCall(original_call.clone()), meta.clone());
        Either::Left(Box::pin(async move {
            if let Err(error) = meta.check_batch_timeout(batch_id) {
                return Some(Output::Failure(Failure {
                    jsonrpc: Some(Version::V2),
                    error,
                    id: original_call.id,
                }));
            }
            let start = Instant::now();
            let meta_cloned = meta.clone();
            next_future
                .then(move |res| async move {
                    match res {
                        Some(Output::Failure(Failure { jsonrpc, error, id }))
                            if error.code == ErrorCode::MethodNotFound && !skip_redirect =>
                        {
                            redirect(meta_cloned, call_json, jsonrpc, id).await
                        }
                        _ => res,
                    }
                })
                .map(move |res| {
                    let total_duration = meta
                        .batch_state_map
                        .update_duration(batch_id, start.elapsed());
                    debug!("Batch total duration: {:?}", total_duration);
                    res
                })
                .await
        }))
    }
}

fn patch_subchain_call(meta: Arc<EvmBridge>, call: Call) -> Option<Call> {
    Some(match call {
        Call::MethodCall(method_call) => {
            let mut method_call = method_call.clone();

            if meta.subchain {
                let mut params = match method_call.params {
                    Params::Array(params) => params,
                    Params::None => vec![],
                    _ => {
                        log::warn!("Invalid params type for method call: {:?}", method_call);
                        return None;
                    }
                };
                log::debug!(
                    "method: {}, params: {}",
                    method_call.method,
                    serde_json::to_string(&params).unwrap()
                );
                if let Some(method) = subchain_methods_collector::ETH_METHODS
                    .get(&method_call.method)
                    .clone()
                {
                    method_call.method = method.clone();
                    // params as array insert at index 0
                    params = Some(Value::Number(meta.evm_chain_id.into()))
                        .into_iter()
                        .chain(params.into_iter())
                        .collect();
                } else {
                    log::warn!("Method not found in subchain: {:?}", method_call.method);
                    return None;
                }
                method_call.params = Params::Array(params);
                log::trace!("Patched method call: {:?}", method_call);
            }
            Call::MethodCall(method_call)
        }
        _ => call.clone(),
    })
}

mod subchain_methods_collector {
    use {evm_rpc::chain_id_rpc::ChainIDERPC, std::collections::HashMap};

    lazy_static::lazy_static! {
        pub static ref ETH_METHODS: HashMap<String, String> = {
            let mut map = HashMap::new();
            for method in methods() {
                let eth_method = method.replacen("vlx_", "eth_", 1);
                map.insert(eth_method, method);
            }
            map
        };
    }

    pub fn methods() -> Vec<String> {
        MockImpl
            .to_delegate()
            .into_iter()
            .map(|(method, _)| method)
            .collect()
    }
    struct MockImpl;
    impl ChainIDERPC for MockImpl {
        type Metadata = ();
        fn balance(
            &self,
            _meta: Self::Metadata,
            _chain: evm_rpc::EvmChain,
            _address: evm_state::Address,
            _block: Option<evm_rpc::BlockId>,
        ) -> jsonrpc_core::BoxFuture<Result<evm_state::U256, evm_rpc::Error>> {
            Box::pin(async move { Err(evm_rpc::Error::ProxyRequest) })
        }
        fn block_by_hash(
            &self,
            _meta: Self::Metadata,
            _chain: evm_rpc::EvmChain,
            _block_hash: evm_state::H256,
            _full: bool,
        ) -> jsonrpc_core::BoxFuture<Result<Option<evm_rpc::RPCBlock>, evm_rpc::Error>> {
            Box::pin(async move { Err(evm_rpc::Error::ProxyRequest) })
        }
        fn block_by_number(
            &self,
            _meta: Self::Metadata,
            _chain: evm_rpc::EvmChain,
            _block: evm_rpc::BlockId,
            _full: bool,
        ) -> jsonrpc_core::BoxFuture<Result<Option<evm_rpc::RPCBlock>, evm_rpc::Error>> {
            Box::pin(async move { Err(evm_rpc::Error::ProxyRequest) })
        }
        fn block_number(
            &self,
            _meta: Self::Metadata,
            _chain: evm_rpc::EvmChain,
        ) -> jsonrpc_core::BoxFuture<Result<evm_rpc::Hex<usize>, evm_rpc::Error>> {
            Box::pin(async move { Err(evm_rpc::Error::ProxyRequest) })
        }
        fn block_transaction_count_by_hash(
            &self,
            _meta: Self::Metadata,
            _chain: evm_rpc::EvmChain,
            _block_hash: evm_state::H256,
        ) -> jsonrpc_core::BoxFuture<Result<evm_rpc::Hex<usize>, evm_rpc::Error>> {
            Box::pin(async move { Err(evm_rpc::Error::ProxyRequest) })
        }
        fn block_transaction_count_by_number(
            &self,
            _meta: Self::Metadata,
            _chain: evm_rpc::EvmChain,
            _block: evm_rpc::BlockId,
        ) -> jsonrpc_core::BoxFuture<Result<evm_rpc::Hex<usize>, evm_rpc::Error>> {
            Box::pin(async move { Err(evm_rpc::Error::ProxyRequest) })
        }
        fn call(
            &self,
            _meta: Self::Metadata,
            _chain: evm_rpc::EvmChain,
            _tx: evm_rpc::RPCTransactionCall,
            _block: Option<evm_rpc::BlockId>,
            _meta_keys: Option<Vec<String>>,
        ) -> jsonrpc_core::BoxFuture<Result<evm_rpc::Bytes, evm_rpc::Error>> {
            Box::pin(async move { Err(evm_rpc::Error::ProxyRequest) })
        }
        fn code(
            &self,
            _meta: Self::Metadata,
            _chain: evm_rpc::EvmChain,
            _address: evm_state::Address,
            _block: Option<evm_rpc::BlockId>,
        ) -> jsonrpc_core::BoxFuture<Result<evm_rpc::Bytes, evm_rpc::Error>> {
            Box::pin(async move { Err(evm_rpc::Error::ProxyRequest) })
        }
        fn estimate_gas(
            &self,
            _meta: Self::Metadata,
            _chain: evm_rpc::EvmChain,
            _tx: evm_rpc::RPCTransactionCall,
            _block: Option<evm_rpc::BlockId>,
            _meta_keys: Option<Vec<String>>,
        ) -> jsonrpc_core::BoxFuture<Result<evm_state::Gas, evm_rpc::Error>> {
            Box::pin(async move { Err(evm_rpc::Error::ProxyRequest) })
        }
        fn logs(
            &self,
            _meta: Self::Metadata,
            _chain: evm_rpc::EvmChain,
            _log_filter: evm_rpc::RPCLogFilter,
        ) -> jsonrpc_core::BoxFuture<Result<Vec<evm_rpc::RPCLog>, evm_rpc::Error>> {
            Box::pin(async move { Err(evm_rpc::Error::ProxyRequest) })
        }
        fn storage_at(
            &self,
            _meta: Self::Metadata,
            _chain: evm_rpc::EvmChain,
            _address: evm_state::Address,
            _data: evm_state::U256,
            _block: Option<evm_rpc::BlockId>,
        ) -> jsonrpc_core::BoxFuture<Result<evm_state::H256, evm_rpc::Error>> {
            Box::pin(async move { Err(evm_rpc::Error::ProxyRequest) })
        }
        fn transaction_by_block_hash_and_index(
            &self,
            _meta: Self::Metadata,
            _chain: evm_rpc::EvmChain,
            _block_hash: evm_state::H256,
            _tx_id: evm_rpc::Hex<usize>,
        ) -> jsonrpc_core::BoxFuture<Result<Option<evm_rpc::RPCTransaction>, evm_rpc::Error>>
        {
            Box::pin(async move { Err(evm_rpc::Error::ProxyRequest) })
        }
        fn transaction_by_block_number_and_index(
            &self,
            _meta: Self::Metadata,
            _chain: evm_rpc::EvmChain,
            _block: evm_rpc::BlockId,
            _tx_id: evm_rpc::Hex<usize>,
        ) -> jsonrpc_core::BoxFuture<Result<Option<evm_rpc::RPCTransaction>, evm_rpc::Error>>
        {
            Box::pin(async move { Err(evm_rpc::Error::ProxyRequest) })
        }
        fn transaction_by_hash(
            &self,
            _meta: Self::Metadata,
            _chain: evm_rpc::EvmChain,
            _tx_hash: evm_state::H256,
        ) -> jsonrpc_core::BoxFuture<Result<Option<evm_rpc::RPCTransaction>, evm_rpc::Error>>
        {
            Box::pin(async move { Err(evm_rpc::Error::ProxyRequest) })
        }
        fn transaction_count(
            &self,
            _meta: Self::Metadata,
            _chain: evm_rpc::EvmChain,
            _address: evm_state::Address,
            _block: Option<evm_rpc::BlockId>,
        ) -> jsonrpc_core::BoxFuture<Result<evm_state::U256, evm_rpc::Error>> {
            Box::pin(async move { Err(evm_rpc::Error::ProxyRequest) })
        }
        fn transaction_receipt(
            &self,
            _meta: Self::Metadata,
            _chain: evm_rpc::EvmChain,
            _tx_hash: evm_state::H256,
        ) -> jsonrpc_core::BoxFuture<Result<Option<evm_rpc::RPCReceipt>, evm_rpc::Error>> {
            Box::pin(async move { Err(evm_rpc::Error::ProxyRequest) })
        }
    }
}
