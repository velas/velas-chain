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
    error::client::range_sync::stages,
    lock_root, retry_logged, DiffRequest, RocksHandleA,
};

type ChildExtractorFn = fn(&[u8]) -> Vec<H256>;

#[cfg(feature = "(schematic stages description)")]
pub async fn get_and_apply_diff<'a, S>(
    client: &mut BackendClient<tonic::transport::Channel>,
    request: DiffRequest,
    state_rpc_address: &str,
    collection: &'a triedb::gc::TrieCollection<RocksHandleA<'a>>,
) -> Result<triedb::gc::RootGuard<'a, RocksHandleA<'a>, ChildExtractorFn>, ClientError> {
    use crate::triedb::DiffRequest;

    let one_output = one::<S>(client, request, state_rpc_address).await?;
    two(one_output, collection).await
}

type OneResponse = Result<GetStateDiffReply, stages::one::request::network::FastError>;

pub async fn get_diff_retried<S>(
    client: &BackendClient<tonic::transport::Channel>,
    request: DiffRequest,
    state_rpc_address: &str,
) -> Result<OneResponse, stages::one::request::network::SlowError> {
    retry_logged(
        || {
            let mut client = client.clone();
            async move {
                let result = Client::<S>::get_diff(&mut client, request, state_rpc_address).await;
                match result {
                    Ok(res) => Ok(OneResponse::Ok(res)),
                    Err(err) => match err.into() {
                        stages::one::request::network::Error::Fast(fast) => Ok(Err(fast)),
                        stages::one::request::network::Error::Slow(slow) => Err(slow),
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
) -> Result<(Duration, DiffRequest, Vec<triedb::DiffChange>), stages::one::request::Error> {
    let mut start = Instant::now();

    let response = get_diff_retried::<S>(client, request, state_rpc_address).await;

    let network_dur = debug_elapsed(&mut start);
    let response = match response {
        Ok(Ok(result)) => result,
        Ok(Err(fast)) => {
            let err = stages::one::request::network::Error::Fast(fast);
            let err = stages::one::request::Error::Network(request, err);
            Err(err)
        }?,
        Err(slow) => {
            let err = stages::one::request::network::Error::Slow(slow);
            let err = stages::one::request::Error::Network(request, err);
            Err(err)
        }?,
    };

    let diff_changes = helpers::parse_diff_response(response)
        .map_err(|err| stages::one::request::Error::Proto(request, err))?;

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
    stages::two::apply::Error,
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
