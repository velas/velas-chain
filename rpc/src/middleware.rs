use jsonrpc_core::{
    futures_util::future::{Either, FutureExt},
    Call, Error, Failure, FutureOutput, FutureResponse, Middleware, Output, Request,
    Response, Version,
};
use log::*;

use crate::rpc::JsonRpcRequestProcessor;

#[derive(Clone, Default)]
pub struct BatchLimiter;
impl Middleware<JsonRpcRequestProcessor> for BatchLimiter {
    type Future = FutureResponse;
    type CallFuture = FutureOutput;

    fn on_request<F, X>(
        &self,
        request: Request,
        meta: JsonRpcRequestProcessor,
        next: F,
    ) -> Either<Self::Future, X>
    where
        F: Fn(Request, JsonRpcRequestProcessor) -> X + Send + Sync,
        X: std::future::Future<Output = Option<Response>> + Send + 'static,
    {
        if let Request::Batch(ref calls) = request {
            let batch_ids: Vec<_> = calls
                .iter()
                .filter_map(|call| match call {
                    Call::MethodCall(method_call) => Some(method_call.id.clone()),
                    _ => None,
                })
                .collect();
            debug!("Create batch {:?}", batch_ids);
            meta.add_batch(&batch_ids);
            Either::Left(Box::pin(next(request.clone(), meta.clone()).map(
                move |res| {
                    meta.remove_batch(&batch_ids);
                    res
                },
            )))
        } else {
            Either::Right(next(request.clone(), meta))
        }
    }

    fn on_call<F, X>(
        &self,
        call: Call,
        meta: JsonRpcRequestProcessor,
        next: F,
    ) -> Either<Self::CallFuture, X>
    where
        F: FnOnce(Call, JsonRpcRequestProcessor) -> X + Send,
        X: std::future::Future<Output = Option<Output>> + Send + 'static,
    {
        let next_future = next(call.clone(), meta.clone());
        Either::Left(Box::pin(async move {
            let start = std::time::Instant::now();
            let id = if let Call::MethodCall(ref method_call) = call {
                Some(method_call.id.clone())
            } else {
                None
            };

            if let Some(ref id) = id {
                let current = meta.get_duration(id.clone());
                debug!("Current batch ({:?}) duration {:?}", id.clone(), current);
                if matches!(meta.get_max_batch_duration(), Some(max_duration) if current > max_duration )
                {
                    let mut error = Error::internal_error();
                    error.message = "Batch is taking too long".to_string();
                    return Some(Output::Failure(Failure {
                        jsonrpc: Some(Version::V2),
                        error,
                        id: id.clone(),
                    }));
                }
            }
            next_future
                .map(move |res| {
                    if let Some(id) = id {
                        let total_duration = meta.update_duration(id, start.elapsed());
                        debug!("Batch total duration: {:?}", total_duration);
                    }
                    res
                })
                .await
        }))
    }
}
