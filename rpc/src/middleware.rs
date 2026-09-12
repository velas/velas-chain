use jsonrpc_core::{
    futures_util::future::{Either, FutureExt},
    Call, Failure, FutureOutput, FutureResponse, Id, MethodCall, Middleware, Output, Request,
    Response, Version,
};
use log::*;
use rand::{thread_rng, Rng};
use std::sync::Arc;

use crate::rpc::{BatchId, JsonRpcRequestProcessor};

// Expected batch id format 'b<generated batch id>:<original id type><original id>
// original id type can be either n (for numeric id) or s (for string id)
fn decode_batch_id(id: &Id) -> Option<(BatchId, Id)> {
    if let Id::Str(id_str) = id {
        let (&prefix, s) = id_str.as_bytes().split_first()?;
        if prefix == b'b' {
            let mut split = s.split(|&b| b == b':');
            let batch_id = std::str::from_utf8(split.next()?).ok()?;
            let batch_id: BatchId = batch_id.parse().ok()?;
            let rest = split.next()?;
            let (&t, id_str) = rest.split_first()?;
            let id_str = std::str::from_utf8(id_str).ok()?;
            return if t == b'n' {
                id_str.parse().ok().map(|num: u64| (batch_id, Id::Num(num)))
            } else if t == b's' {
                Some((batch_id, Id::Str(id_str.to_string())))
            } else {
                None
            };
        }
    }
    None
}

pub fn patch_calls(calls: impl IntoIterator<Item = Call>, id: BatchId) -> Vec<Call> {
    let id_str = id.to_string();
    calls
        .into_iter()
        .map(|call| {
            if let Call::MethodCall(mut method_call) = call {
                let new_id = match method_call.id.clone() {
                    Id::Num(num) => Id::Str(format!("b{}:n{}", id_str, num)),
                    Id::Str(s) => Id::Str(format!("b{}:s{}", id_str, s)),
                    Id::Null => Id::Null,
                };
                method_call.id = new_id;
                Call::MethodCall(method_call)
            } else {
                call
            }
        })
        .collect()
}

pub fn restore_original_call(call: Call) -> Result<(MethodCall, BatchId), Call> {
    match call {
        Call::MethodCall(mut method_call) => match decode_batch_id(&method_call.id) {
            Some((batch_id, id)) => {
                method_call.id = id;
                Ok((method_call, batch_id))
            }
            None => Err(Call::MethodCall(method_call)),
        },
        _ => Err(call),
    }
}

#[derive(Clone, Default)]
pub struct BatchLimiter;
impl Middleware<Arc<JsonRpcRequestProcessor>> for BatchLimiter {
    type Future = FutureResponse;
    type CallFuture = FutureOutput;

    fn on_request<F, X>(
        &self,
        request: Request,
        meta: Arc<JsonRpcRequestProcessor>,
        next: F,
    ) -> Either<Self::Future, X>
    where
        F: Fn(Request, Arc<JsonRpcRequestProcessor>) -> X + Send + Sync,
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
        meta: Arc<JsonRpcRequestProcessor>,
        next: F,
    ) -> Either<Self::CallFuture, X>
    where
        F: FnOnce(Call, Arc<JsonRpcRequestProcessor>) -> X + Send,
        X: std::future::Future<Output = Option<Output>> + Send + 'static,
    {
        let (original_call, batch_id) = match restore_original_call(call) {
            Ok((original_call, batch_id)) => (original_call, batch_id),
            Err(call) => return Either::Right(next(call, meta)),
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
            let start = std::time::Instant::now();
            next_future
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
