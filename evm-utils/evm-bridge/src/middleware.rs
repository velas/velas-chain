use {
    crate::EvmBridge,
    evm_state::rand::{thread_rng, Rng},
    jsonrpc_core::{
        futures_util::future::{Either, FutureExt},
        Call, Error, ErrorCode, Failure, FutureOutput, FutureResponse, Id, Middleware, Output,
        Request, Response, Success,
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
                                if error.code == ErrorCode::MethodNotFound =>
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
                            if error.code == ErrorCode::MethodNotFound =>
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
