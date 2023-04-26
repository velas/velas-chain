use std::time::Duration;

use proto::app_grpc::backend_client::BackendClient;

use super::range::RangeJSON;
use evm_state::Storage;
use log;

mod proto;
mod sync;

pub struct Client<S> {
    pub state_rpc_address: String,
    storage: Storage,
    client: BackendClient<tonic::transport::Channel>,
    range: RangeJSON,
    block_storage: S,
    request_workers: u32,
    db_workers: u32,
    max_height_gap: usize
}

impl<S> Client<S> {
    pub async fn connect(
        state_rpc_address: String,
        timeout_seconds: u64,
        range: RangeJSON,
        storage: Storage,
        block_storage: S,
        request_workers: u32,
        db_workers: u32,
        max_height_gap: usize,
    ) -> Result<Self, tonic::transport::Error> {
        log::info!("starting the client routine {}", state_rpc_address);

        let endpoint: tonic::transport::Endpoint = state_rpc_address.clone().try_into()?;

        // for getting 641_000 of nodes in single request 20 sec timeout has been seen
        // to be surpassed
        let endpoint = endpoint.timeout(Duration::new(timeout_seconds, 0));
        let client = BackendClient::connect(endpoint).await?;

        Ok(Self {
            client,
            range,
            state_rpc_address,
            storage,
            block_storage,
            request_workers,
            db_workers,
            max_height_gap,
        })
    }
}
