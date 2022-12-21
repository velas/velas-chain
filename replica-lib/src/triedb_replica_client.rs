use app_grpc::backend_client::BackendClient;

use evm_rpc::FormatHex;
use evm_state::{H256, Storage};
use log;
use std::net::SocketAddr;

pub mod app_grpc {
    tonic::include_proto!("triedb_repl");
}

pub async fn get_earliest_block(
) -> Result<String, solana_client::client_error::ClientError> {
    use serde_json::json;

    let addr = SocketAddr::from(([64, 52, 81, 175], 8899));
    let client = solana_client::rpc_client::RpcClient::new_socket(addr);

    let response = client.send::<Option<evm_rpc::RPCBlock>>(
        solana_client::rpc_request::RpcRequest::EthGetBlockByNumber,
        json!(["earliest", true]),
    )?;

    if let Some(block) = response {
        Ok(format!("{:?}", block))
    } else {
        Ok(String::from("NOT FOUND"))
    }
}

pub async fn get_next_block(
    _block_number: String,
) -> Result<String, solana_client::client_error::ClientError> {
    use serde_json::json;

    let client =
        solana_client::rpc_client::RpcClient::new("64.52.81.175:8899".to_string());

    let response = client.send::<Option<evm_rpc::RPCBlock>>(
        solana_client::rpc_request::RpcRequest::EthGetBlockByNumber,
        json!(["earliest", true]),
    )?;

    if let Some(block) = response {
        Ok(format!("{:?}", block))
    } else {
        Ok(String::from("NOT FOUND"))
    }
}

pub struct ClientOpts {
    state_rpc_address: String,
    storage: Storage, 
}

impl ClientOpts   {
    pub fn new(state_rpc_address: String, storage: Storage) -> Self {
        Self { state_rpc_address, storage }
    }
    
}

pub struct Client {
    client: BackendClient<tonic::transport::Channel>,
    storage: Storage, 
}
impl Client {

    pub async fn connect(opts: ClientOpts) -> Result<Self, tonic::transport::Error> {

        log::info!("starting the client routine {}", opts.state_rpc_address);
        let client = BackendClient::connect(opts.state_rpc_address).await?;
        Ok(Self { client , storage: opts.storage })

    }

    pub async fn ping(&mut self) -> Result<(), tonic::Status> {

        let request = tonic::Request::new(());
        let response = self.client.ping(request).await?;
        log::trace!("PING | RESPONSE={:?}", response);
        Ok(())

    }

    pub async fn get_raw_bytes(
        &mut self,
        hash: H256,
    ) -> Result<app_grpc::GetRawBytesReply, tonic::Status> {

        let request = tonic::Request::new(app_grpc::GetRawBytesRequest {
            hash: Some(app_grpc::Hash {
                value: hash.format_hex(),
            }),
        });
        let response = self.client.get_raw_bytes(request).await?;
        log::trace!("PING | RESPONSE={:?}", response);
        Ok(response.into_inner())

    }

    pub async fn get_state_diff(
        &mut self,
        from: H256,
        to: H256,
    ) -> Result<app_grpc::GetStateDiffReply, tonic::Status> {

        let request = tonic::Request::new(app_grpc::GetStateDiffRequest {
            first_root: Some(app_grpc::Hash {
                value: from.format_hex(),
            }),
            second_root: Some(app_grpc::Hash {
                value: to.format_hex(),
            }),
        });
        let response = self.client.get_state_diff(request).await?;
        Ok(response.into_inner())

    }

    pub async fn get_and_verify_state_diff(
        &mut self,
        from: H256,
        to: H256,
    ) -> Result<triedb::VerifiedPatch, Box<(dyn std::error::Error + 'static)>>  {

        let response = self.get_state_diff(from, to).await?;
        let diff_changes = parse_diff_response(response)?;
        let db_handle = self.storage.rocksdb_trie_handle();


        let diff_patch = triedb::verify_diff(&db_handle, to, diff_changes, evm_state::storage::account_extractor, false)?;
        Ok(diff_patch)

    }
}

fn parse_diff_response(
    in_: app_grpc::GetStateDiffReply,
) -> Result<Vec<triedb::DiffChange>, tonic::Status> {
    in_.changeset
        .into_iter()
        .map(|insert| {
            let result = insert.hash.ok_or_else(|| {
                tonic::Status::invalid_argument("insert with empty hash")
            });
            match result {
                Ok(hash) => match FormatHex::from_hex(&hash.value) {
                    Ok(hash) => Ok(triedb::DiffChange::Insert(hash, insert.data)),
                    Err(e) => Err(tonic::Status::invalid_argument(format!(
                        "could not parse hash {:?}",
                        e
                    ))),
                },
                Err(e) => Err(e),
            }
        })
        .collect()
}
