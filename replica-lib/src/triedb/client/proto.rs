use evm_rpc::FormatHex;
use evm_state::H256;
use evm_state::{storage::account_extractor, BlockNum};
use tonic::Code;

use std::ops::Range;
use std::time::Instant;

use crate::triedb::{debug_elapsed, error::ClientError, lock_root, RocksHandleA};

use self::app_grpc::backend_client::BackendClient;
mod helpers;
mod retried;

pub mod app_grpc {
    tonic::include_proto!("triedb_repl");
}

type ChildExtractorFn = fn(&[u8]) -> Vec<H256>;

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

    pub async fn download_and_apply_diff<'a>(
        client: &mut BackendClient<tonic::transport::Channel>,
        collection: &'a triedb::gc::TrieCollection<RocksHandleA<'a>>,
        heights: (evm_state::BlockNum, evm_state::BlockNum),
        expected_hashes: (H256, H256),
    ) -> Result<triedb::gc::RootGuard<'a, RocksHandleA<'a>, ChildExtractorFn>, ClientError> {
        log::debug!("download_and_apply_diff start");
        let start = Instant::now();

        let _from_guard = lock_root(&collection.database, expected_hashes.0, account_extractor)?;
        debug_elapsed("locked root", &start);

        let response = client
            .get_state_diff(helpers::state_diff_request(heights, expected_hashes))
            .await?;
        debug_elapsed("queried response over network", &start);

        let response = response.into_inner();
        log::debug!(
            "changeset received {:?} -> {:?}, {}",
            expected_hashes.0,
            expected_hashes.1,
            response.changeset.len()
        );

        let diff_changes = helpers::parse_diff_response(response)?;
        debug_elapsed("parsed response", &start);

        let diff_patch = triedb::verify_diff(
            &collection.database,
            expected_hashes.1,
            diff_changes,
            account_extractor,
            false,
        )?;
        debug_elapsed("verified response", &start);

        let to_guard =
            collection.apply_diff_patch(diff_patch, account_extractor as ChildExtractorFn)?;
        debug_elapsed("applied response", &start);
        Ok(to_guard)
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
        match response {
            Err(ref err) => {
                if err.code() == Code::NotFound {
                    log::error!("not found {:?}", err);
                    return Ok(None);
                }
            }
            _ => {}
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
                .unwrap_or("empty".to_string()),
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

        let response = client.prefetch_range(request).await?;
        log::info!(
            "prefetch_height response retrieved: {:?}, {}",
            range,
            state_rpc_address,
        );
        Ok(response.into_inner())
    }
}
