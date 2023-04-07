use evm_rpc::FormatHex;
use evm_state::BlockNum;
use evm_state::H256;
use tonic::Code;

use std::ops::Range;

use crate::triedb::DiffRequest;

use self::app_grpc::backend_client::BackendClient;
use self::app_grpc::GetStateDiffReply;
pub(super) mod helpers;
mod retried;

pub mod app_grpc {
    tonic::include_proto!("triedb_repl");
}

impl From<app_grpc::GetBlockRangeReply> for std::ops::Range<BlockNum> {
    fn from(value: app_grpc::GetBlockRangeReply) -> Self {
        value.start..value.end
    }
}

impl<S> super::Client<S> {
    pub async fn ping(
        client: &mut BackendClient<tonic::transport::Channel>,
    ) -> Result<(), tonic::Status> {
        let request = tonic::Request::new(());
        let response = client.ping(request).await?;
        log::trace!("PING | RESPONSE={:?}", response);
        Ok(())
    }

    pub async fn get_array_of_nodes(
        client: &mut BackendClient<tonic::transport::Channel>,
        hashes: Vec<H256>,
    ) -> Result<app_grpc::GetArrayOfNodesReply, tonic::Status> {
        let request = tonic::Request::new(app_grpc::GetArrayOfNodesRequest {
            hashes: hashes
                .into_iter()
                .map(|h| app_grpc::Hash {
                    value: h.format_hex(),
                })
                .collect(),
        });
        let response = client.get_array_of_nodes(request).await?;
        log::trace!("PING | RESPONSE={:?}", response);
        Ok(response.into_inner())
    }

    pub async fn get_block_range(
        client: &mut BackendClient<tonic::transport::Channel>,
        state_rpc_address: &str,
    ) -> Result<app_grpc::GetBlockRangeReply, tonic::Status> {
        let request = tonic::Request::new(());
        let response = client.get_block_range(request).await?;

        let response = response.into_inner();
        log::info!(
            "block_range retrieved: {} -> {}, {}",
            response.start,
            response.end,
            state_rpc_address
        );
        Ok(response)
    }

    pub async fn prefetch_height(
        client: &mut BackendClient<tonic::transport::Channel>,
        height: BlockNum,
        state_rpc_address: &str,
    ) -> Result<Option<app_grpc::PrefetchHeightReply>, tonic::Status> {
        let request = tonic::Request::new(app_grpc::PrefetchHeightRequest { height });

        let response = client.prefetch_height(request).await;
        if let Err(ref err) = response {
            if err.code() == Code::NotFound {
                log::error!("not found {:?}", err);
                return Ok(None);
            }
        }
        let response = response?;

        let response = response.into_inner();
        log::info!(
            "prefetch_height response retrieved: {} -> {:?}, {}",
            height,
            response
                .hash
                .as_ref()
                .map(|hash| hash.value.clone())
                .unwrap_or_else(|| "empty".to_string()),
            state_rpc_address
        );
        Ok(Some(response))
    }

    pub async fn prefetch_range(
        client: &mut BackendClient<tonic::transport::Channel>,
        range: &Range<BlockNum>,
        state_rpc_address: &str,
    ) -> Result<(), tonic::Status> {
        let request = tonic::Request::new(app_grpc::PrefetchRangeRequest {
            start: range.start,
            end: range.end,
        });

        client.prefetch_range(request).await?;
        log::info!(
            "prefetch_range response retrieved: {:?}, {}",
            range,
            state_rpc_address,
        );
        Ok(())
    }

    pub async fn get_diff(
        client: &mut BackendClient<tonic::transport::Channel>,
        request: DiffRequest,
        state_rpc_address: &str,
    ) -> Result<GetStateDiffReply, tonic::Status> {
        let response = client
            .get_state_diff(helpers::state_diff_request(request))
            .await?;

        let response = response.into_inner();
        log::trace!(
            "changeset retrieved {:?} -> {:?} {}, {}",
            request.expected_hashes.0,
            request.expected_hashes.1,
            response.changeset.len(),
            state_rpc_address,
        );
        Ok(response)
    }
}
