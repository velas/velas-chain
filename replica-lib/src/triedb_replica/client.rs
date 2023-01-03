use app_grpc::backend_client::BackendClient;


use super::{lock_root, debug_elapsed};
use evm_rpc::FormatHex;
use evm_state::{Storage, H256};
use log;
use std::net::SocketAddr;
use std::time::Instant;

pub mod app_grpc {
    tonic::include_proto!("triedb_repl");
}

type RocksHandleA<'a> = triedb::rocksdb::RocksHandle<'a, &'a triedb::rocksdb::DB>;

pub fn db_handles(
    storage: &Storage,
) -> (
    RocksHandleA<'_>,
    triedb::gc::TrieCollection<RocksHandleA<'_>>,
) {
    (
        storage.rocksdb_trie_handle(),
        triedb::gc::TrieCollection::new(storage.rocksdb_trie_handle()),
    )
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

pub struct Client {
    client: BackendClient<tonic::transport::Channel>,
}
impl Client {

    pub async fn connect(
        state_rpc_address: String,
    ) -> Result<Self, tonic::transport::Error> {

        log::info!("starting the client routine {}", state_rpc_address);
        let client = BackendClient::connect(state_rpc_address).await?;
        Ok(Self { client  })

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

    fn state_diff_request(
        from: H256,
        to: H256,
    ) -> tonic::Request<app_grpc::GetStateDiffRequest> {
        tonic::Request::new(app_grpc::GetStateDiffRequest {
            first_root: Some(app_grpc::Hash {
                value: from.format_hex(),
            }),
            second_root: Some(app_grpc::Hash {
                value: to.format_hex(),
            }),
        })
    }

    pub async fn download_and_apply_diff<'a, 'b, F>(
        &mut self,
        db_handle: &RocksHandleA<'a>,
        collection: &'b triedb::gc::TrieCollection<RocksHandleA<'b>>,
        from: H256,
        to: H256,
        func_extractor: F,
    ) -> Result<triedb::gc::RootGuard<'b, RocksHandleA<'b>, F>, anyhow::Error>
    where
        F: FnMut(&[u8]) -> Vec<H256> + Clone,
    {
        log::info!("download_and_apply_diff start");
        let start = Instant::now();
        let _from_guard = lock_root(db_handle, from, func_extractor.clone())?;
        debug_elapsed("locked root", &start);

        let response = self
            .client
            .get_state_diff(Self::state_diff_request(from, to))
            .await?;
        debug_elapsed("queried response over network", &start);

        let response = response.into_inner();
        log::info!(
            "changeset received {} -> {}, {}",
            from,
            to,
            response.changeset.len()
        );
        let diff_changes = parse_diff_response(response)?;
        debug_elapsed("parsed response", &start);

        let diff_patch = triedb::verify_diff(
            db_handle,
            to,
            diff_changes,
            func_extractor.clone(),
            false,
        )?;
        debug_elapsed("verified response", &start);

        let to_guard = collection.apply_diff_patch(diff_patch, func_extractor)?;
        debug_elapsed("applied response", &start);
        Ok(to_guard)
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
