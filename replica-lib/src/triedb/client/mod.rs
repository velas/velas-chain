use proto::app_grpc::backend_client::BackendClient;

use super::error::ClientError;
use super::range::MasterRange;
use evm_state::Storage;
use log;

mod bootstrap;
mod extend_range;
mod proto;

pub struct Client<S> {
    pub state_rpc_address: String,
    storage: Storage,
    client: BackendClient<tonic::transport::Channel>,
    range: MasterRange,
    block_storage: S,
}

impl<S> Client<S> {
    pub async fn connect(
        state_rpc_address: String,
        range: MasterRange,
        storage: Storage,
        block_storage: S,
    ) -> Result<Self, ClientError> {
        log::info!("starting the client routine {}", state_rpc_address);
        let client = BackendClient::connect(state_rpc_address.clone()).await?;
        Ok(Self {
            client,
            range,
            state_rpc_address,
            storage,
            block_storage,
        })
    }
}
