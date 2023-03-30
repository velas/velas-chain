use proto::app_grpc::backend_client::BackendClient;

use super::error::ClientError;
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
}

impl<S> Client<S> {
    pub async fn connect(
        state_rpc_address: String,
        range: RangeJSON,
        storage: Storage,
        block_storage: S,
        request_workers: u32,
        db_workers: u32,
    ) -> Result<Self, ClientError> {
        log::info!("starting the client routine {}", state_rpc_address);

        let client = BackendClient::connect(state_rpc_address.clone()).await?;

        Ok(Self {
            client,
            range,
            state_rpc_address,
            storage,
            block_storage,
            request_workers,
            db_workers,
        })
    }
}
