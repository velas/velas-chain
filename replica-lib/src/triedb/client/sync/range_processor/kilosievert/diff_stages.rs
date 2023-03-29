use std::time::Instant;

use backon::{ExponentialBuilder, Retryable};
use evm_state::{storage::account_extractor, H256};

use crate::triedb::{
    client::{
        proto::{
            app_grpc::{backend_client::BackendClient, GetStateDiffReply},
            helpers,
        },
        Client,
    },
    debug_elapsed,
    error::{
        ClientError, DiffRequest, StageOneError, StageOneRequestError, StageOneRequestFastError,
        StageOneRequestSlowError,
    },
    lock_root, RocksHandleA, MAX_TIMES, MIN_DELAY_SEC,
};

type ChildExtractorFn = fn(&[u8]) -> Vec<H256>;

#[cfg(feature = "(schematic stages description)")]
pub async fn get_and_apply_diff<'a, S>(
    client: &mut BackendClient<tonic::transport::Channel>,
    request: DiffRequest,
    state_rpc_address: &str,
    collection: &'a triedb::gc::TrieCollection<RocksHandleA<'a>>,
) -> Result<triedb::gc::RootGuard<'a, RocksHandleA<'a>, ChildExtractorFn>, ClientError> {
    let one_output = one::<S>(client, request, state_rpc_address).await?;
    two(one_output, collection).await
}

pub enum StageOneRequestResponse {
    Ok(GetStateDiffReply),
    FailFast(StageOneRequestFastError),
}
pub async fn get_diff_retried<S>(
    client: &BackendClient<tonic::transport::Channel>,
    request: DiffRequest,
    state_rpc_address: &str,
) -> Result<StageOneRequestResponse, StageOneRequestSlowError> {
    let mut count = 0;
    let fetch_cl = || {
        *(&mut count) += 1;
        let val = count;
        async move {
            log::trace!(
                "attempting try to get_diff {:?} {} ({})",
                request,
                state_rpc_address,
                val
            );

            let mut client = client.clone();
            let result = Client::<S>::get_diff(&mut client, request, state_rpc_address).await;
            match result {
                Ok(res) => Ok(StageOneRequestResponse::Ok(res)),
                Err(err) => match StageOneRequestError::from_with_metadata(err, request) {
                    StageOneRequestError::Fast(fast) => Ok(StageOneRequestResponse::FailFast(fast)),
                    StageOneRequestError::Slow(slow) => Err(slow),
                },
            }
        }
    };

    let res = fetch_cl
        .retry(
            &ExponentialBuilder::default()
                .with_min_delay(std::time::Duration::new(MIN_DELAY_SEC, 0))
                .with_max_times(MAX_TIMES),
        )
        .await;
    res
}

pub async fn one<S>(
    client: &mut BackendClient<tonic::transport::Channel>,
    request: DiffRequest,
    state_rpc_address: &str,
) -> Result<(DiffRequest, Vec<triedb::DiffChange>), StageOneError> {
    let mut start = Instant::now();

    let response = get_diff_retried::<S>(client, request, state_rpc_address).await;

    debug_elapsed("queried diff response over network", &mut start);
    let response = match response {
        Ok(StageOneRequestResponse::Ok(result)) => result,
        Ok(StageOneRequestResponse::FailFast(fast)) => Err(StageOneRequestError::Fast(fast))?,
        Err(slow) => Err(StageOneRequestError::Slow(slow))?,
    };

    let diff_changes = helpers::parse_diff_response(response)?;

    debug_elapsed("parsed diff response", &mut start);
    Ok((request, diff_changes))
}

pub async fn two<'a>(
    incoming: (DiffRequest, Vec<triedb::DiffChange>),
    collection: &'a triedb::gc::TrieCollection<RocksHandleA<'a>>,
) -> Result<triedb::gc::RootGuard<'a, RocksHandleA<'a>, ChildExtractorFn>, ClientError> {
    let mut start = Instant::now();
    let (request, diff_changes) = incoming;

    let diff_patch = triedb::verify_diff(
        &collection.database,
        request.expected_hashes.1,
        diff_changes,
        account_extractor,
        false,
    )?;
    debug_elapsed("verified diff response", &mut start);

    let _from_guard = lock_root(
        &collection.database,
        request.expected_hashes.0,
        account_extractor,
    )?;
    debug_elapsed("locked or checked root before diff", &mut start);

    let to_guard =
        collection.apply_diff_patch(diff_patch, account_extractor as ChildExtractorFn)?;
    debug_elapsed("applied diff response", &mut start);
    Ok(to_guard)
}

#[doc(hidden)]
#[cfg(feature = "(stage_three)")]
async fn stage_three() {
    // unfortunately, the fact of presence of stage_three means, that the project is impossible
    // to complete
}
