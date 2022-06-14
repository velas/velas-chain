use std::future::ready;
use std::sync::Arc;
use std::time::Instant;

use jsonrpc_core::{
    Call, FutureOutput, futures_util::future::{Either, FutureExt}, Middleware, Version::V2
};
use reqwest::header::CONTENT_TYPE;
use serde_json::Value;
use solana_client::client_error::{ClientError, ClientErrorKind};
use solana_client::rpc_request::RpcError;

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
            X: std::future::Future<Output = Option<jsonrpc_core::Output>> + Send + 'static,
    {
        let start = Instant::now();
        let meta_cloned = meta.clone();
        let call_json = match serde_json::to_string(&call) {
            Ok(str) => str,
            Err(_) => {
                return Either::Left(Box::pin(ready(Some(
                    jsonrpc_core::Output::invalid_request(jsonrpc_core::Id::Null, Some(V2))
                ))));
            }
        };
        Either::Left(Box::pin(next(call.clone(), meta).then(move |res| async move {
            let res = match res {
                Some(jsonrpc_core::Output::Failure(
                         jsonrpc_core::Failure { jsonrpc, error, id },
                     )) if error.code == jsonrpc_core::ErrorCode::MethodNotFound => {
                    println!("Proxy method called!");
                    let output = match meta_cloned.rpc_client_async._send_request(call_json).await {
                        Ok(result) => jsonrpc_core::Output::Success(jsonrpc_core::Success{
                            jsonrpc,
                            result,
                            id,
                        }),
                        Err(ClientError { kind: ClientErrorKind::RpcError(RpcError::RpcResponseError { code, message, original_err, ..}), .. }) =>
                            jsonrpc_core::Output::Failure(jsonrpc_core::Failure {
                                jsonrpc,
                                error: jsonrpc_core::Error { code: code.into(), message, data: Some(original_err) },
                                id,
                            }),
                        Err(err) => {
                            let mut error = jsonrpc_core::Error::internal_error();
                            error.message = format!("{}", err.kind);
                            jsonrpc_core::Output::Failure(jsonrpc_core::Failure {
                                jsonrpc,
                                error,
                                id
                            })
                        }
                    };
                    Some(output)
                }
                _ => res,
            };
            println!("Processing took: {:?}", start.elapsed());
            res
        })))
    }
}