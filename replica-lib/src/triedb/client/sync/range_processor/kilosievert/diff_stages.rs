use std::time::{Duration, Instant};

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
        DiffRequest, StageOneNetworkError, StageOneNetworkFastError, StageOneNetworkSlowError,
        StageOneRequestError, StageTwoApplyError,
    },
    lock_root, retry_logged, RocksHandleA,
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

type StageOneRequestResponse = Result<GetStateDiffReply, StageOneNetworkFastError>;

pub async fn get_diff_retried<S>(
    client: &BackendClient<tonic::transport::Channel>,
    request: DiffRequest,
    state_rpc_address: &str,
) -> Result<StageOneRequestResponse, StageOneNetworkSlowError> {
    retry_logged(
        || {
            let mut client = client.clone();
            async move {
                let result = Client::<S>::get_diff(&mut client, request, state_rpc_address).await;
                match result {
                    Ok(res) => Ok(StageOneRequestResponse::Ok(res)),
                    Err(err) => match StageOneNetworkError::from_with_metadata(err, request) {
                        StageOneNetworkError::Fast(fast) => Ok(Err(fast)),
                        StageOneNetworkError::Slow(slow) => Err(slow),
                    },
                }
            }
        },
        format!("get_diff {:?} {}", request, state_rpc_address),
        log::Level::Trace,
    )
    .await
}

pub async fn one<S>(
    client: &BackendClient<tonic::transport::Channel>,
    request: DiffRequest,
    state_rpc_address: &str,
) -> Result<(Duration, DiffRequest, Vec<triedb::DiffChange>), StageOneRequestError> {
    let mut start = Instant::now();

    let response = get_diff_retried::<S>(client, request, state_rpc_address).await;

    let network_dur = debug_elapsed(&mut start);
    let response = match response {
        Ok(Ok(result)) => result,
        Ok(Err(fast)) => Err(StageOneNetworkError::Fast(fast))?,
        Err(slow) => Err(StageOneNetworkError::Slow(slow))?,
    };

    let diff_changes = helpers::parse_diff_response(response)?;

    let _ = debug_elapsed(&mut start);
    Ok((network_dur, request, diff_changes))
}

pub fn two<'a>(
    incoming: (DiffRequest, Vec<triedb::DiffChange>),
    collection: &'a triedb::gc::TrieCollection<RocksHandleA<'a>>,
) -> Result<
    (
        Duration,
        triedb::gc::RootGuard<'a, RocksHandleA<'a>, ChildExtractorFn>,
    ),
    StageTwoApplyError,
> {
    let mut start = Instant::now();
    let (request, diff_changes) = incoming;

    let diff_patch = triedb::verify_diff(
        &collection.database,
        request.expected_hashes.1,
        diff_changes,
        account_extractor,
        false,
    )?;
    // let _ = debug_elapsed(&mut start);

    let _from_guard = lock_root(
        &collection.database,
        request.expected_hashes.0,
        account_extractor,
    )?;
    // debug_elapsed(&mut start);

    let to_guard =
        collection.apply_diff_patch(diff_patch, account_extractor as ChildExtractorFn)?;
    let applied_dur = debug_elapsed(&mut start);
    Ok((applied_dur, to_guard))
}

#[doc(hidden)]
#[cfg(feature = "(stage_three)")]
async fn stage_three() {
    // unfortunately, the fact of presence of stage_three means, that the project is impossible
    // to complete
}
