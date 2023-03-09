use evm_rpc::FormatHex;
use evm_state::{storage::account_extractor, BlockNum};
use evm_state::H256;

use std::time::Instant;

use crate::triedb::{debug_elapsed, error::ClientError, lock_root, RocksHandleA};

use self::app_grpc::backend_client::BackendClient;
mod helpers;

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
    pub async fn ping(&mut self) -> Result<(), tonic::Status> {
        let request = tonic::Request::new(());
        let response = self.client.ping(request).await?;
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
            .get_state_diff(helpers::state_diff_request(heights))
            .await?;
        debug_elapsed("queried response over network", &start);

        let response = response.into_inner();
        log::debug!(
            "changeset received {:?} -> {:?}, {}",
            response.first_root,
            response.second_root,
            response.changeset.len()
        );
        helpers::check_hash(heights.0, response.first_root.clone(), expected_hashes.0)?;
        helpers::check_hash(heights.1, response.second_root.clone(), expected_hashes.1)?;

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

    pub async fn get_block_range(&mut self) -> Result<app_grpc::GetBlockRangeReply, tonic::Status> {
        let request = tonic::Request::new(());
        let response = self.client.get_block_range(request).await?;

        let response = response.into_inner();
        log::info!(
            "block_range received {} -> {}",
            response.start,
            response.end,
        );
        Ok(response)
    }
}
