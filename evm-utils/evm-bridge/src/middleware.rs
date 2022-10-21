use std::future::ready;
use std::sync::Arc;
use std::time::Instant;

use jsonrpc_core::{
    futures_util::future::{Either, FutureExt},
    Call, Error, ErrorCode, Failure, FutureOutput, Id, Middleware, Output, Success,
    Version::V2,
};
use log::{debug, error};
use serde_json::Value;

use crate::EvmBridge;

#[derive(Clone, Default)]
pub struct ProxyMiddleware;
impl Middleware<Arc<EvmBridge>> for ProxyMiddleware {
    type Future = jsonrpc_core::middleware::NoopFuture;
    type CallFuture = FutureOutput;

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
        let start = Instant::now();
        let meta_cloned = meta.clone();
        let call_json = match serde_json::to_string(&call) {
            Ok(str) => str,
            Err(_) => {
                return Either::Left(Box::pin(ready(Some(Output::invalid_request(
                    Id::Null,
                    Some(V2),
                )))))
            }
        };
        Either::Left(Box::pin(next(call, meta).then(move |res| async move {
            let res = match res {
                Some(Output::Failure(Failure { jsonrpc, error, id }))
                    if error.code == ErrorCode::MethodNotFound =>
                {
                    debug!("Method not found! Redirecting to node...");
                    let response = match meta_cloned.rpc_client._send_request(call_json).await {
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
                _ => res,
            };
            debug!("Processing took: {:?}", start.elapsed());
            res
        })))
    }
}
