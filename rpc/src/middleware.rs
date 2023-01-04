use jsonrpc_core::{
    futures_util::future::{Either, FutureExt},
    Call, Failure, FutureOutput, FutureResponse, Id, MethodCall, Middleware, Output, Request,
    Response, Version,
};
use log::*;
use rand::{thread_rng, Rng};

use crate::rpc::JsonRpcRequestProcessor;

fn decode_batch_id(id: &Id) -> Option<(u64, Id)> {
    if let Id::Str(id_str) = id {
        let (&prefix, s) = id_str.as_bytes().split_first()?;
        if prefix == 'b' as u8 {
            let mut split = s.split(|&b| b == ':' as u8);
            let batch_id = std::str::from_utf8(split.next()?).ok()?;
            let batch_id: u64 = batch_id.parse().ok()?;
            let rest = split.next()?;
            let (&t, id_str) = rest.split_first()?;
            let id_str = std::str::from_utf8(id_str).ok()?;
            return if t == 'n' as u8 {
                id_str.parse().ok().map(|num: u64| (batch_id, Id::Num(num)))
            } else if t == 's' as u8 {
                Some((batch_id, Id::Str(id_str.to_string())))
            } else {
                None
            };
        }
    }
    None
}

fn patch_calls(calls: &Vec<Call>, id: u64) -> Vec<Call> {
    let id_str = id.to_string();
    calls
        .iter()
        .map(|call| {
            if let Call::MethodCall(method_call) = call {
                let mut patched_call = method_call.clone();
                let new_id = match method_call.id.clone() {
                    Id::Num(num) => Id::Str(format!("b{}:n{}", id_str, num)),
                    Id::Str(s) => Id::Str(format!("b{}:s{}", id_str, s)),
                    Id::Null => Id::Null,
                };
                patched_call.id = new_id;
                Call::MethodCall(patched_call)
            } else {
                call.clone()
            }
        })
        .collect()
}

fn restore_original_call(call: Call) -> Option<(MethodCall, u64)> {
    if let Call::MethodCall(mut method_call) = call {
        if let Some((batch_id, ref id)) = decode_batch_id(&method_call.id) {
            method_call.id = id.clone();
            return Some((method_call, batch_id));
        }
    }
    None
}

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
            let mut rng = thread_rng();
            let mut batch_id = rng.gen::<u64>();
            while !meta.add_batch(batch_id) {
                batch_id = rng.gen::<u64>();
            }
            debug!("Create batch {}", batch_id);
            let patched_request = Request::Batch(patch_calls(calls, batch_id));
            Either::Left(Box::pin(next(patched_request, meta.clone()).map(
                move |res| {
                    meta.remove_batch(&batch_id);
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
        meta: JsonRpcRequestProcessor,
        next: F,
    ) -> Either<Self::CallFuture, X>
    where
        F: FnOnce(Call, JsonRpcRequestProcessor) -> X + Send,
        X: std::future::Future<Output = Option<Output>> + Send + 'static,
    {
        let (original_call, batch_id) = match restore_original_call(call.clone()) {
            Some((original_call, batch_id)) => (original_call, batch_id),
            None => return Either::Right(next(call, meta)),
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
                    let total_duration = meta.update_duration(batch_id, start.elapsed());
                    debug!("Batch total duration: {:?}", total_duration);
                    res
                })
                .await
        }))
    }
}
