use proto::app_grpc::backend_client::BackendClient;

use super::error::ClientError;
use super::range::RangeJSON;
use evm_state::Storage;
use log;

mod sync;
mod proto;

pub struct Client<S> {
    pub state_rpc_address: String,
    storage: Storage,
    client: BackendClient<tonic::transport::Channel>,
    workers_clients: Vec<BackendClient<tonic::transport::Channel>>,
    range: RangeJSON,
    block_storage: S,
}

const PARALLEL_SERVER_WORKERS: usize = 40;

impl<S> Client<S> {
    pub async fn connect(
        state_rpc_address: String,
        range: RangeJSON,
        storage: Storage,
        block_storage: S,
    ) -> Result<Self, ClientError> {
        log::info!("starting the client routine {}", state_rpc_address);

        let client = BackendClient::connect(state_rpc_address.clone()).await?;
        let mut clients = vec![];

        for _ in 0..PARALLEL_SERVER_WORKERS {
            
            let client = BackendClient::connect(state_rpc_address.clone()).await?;
            clients.push(client);
        }

        Ok(Self {
            client,
            workers_clients: clients,
            range,
            state_rpc_address,
            storage,
            block_storage,
        })
    }
}
