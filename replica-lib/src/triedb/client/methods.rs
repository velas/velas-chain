use evm_rpc::FormatHex;
use evm_state::storage::account_extractor;
use evm_state::H256;

use std::time::Instant;

use crate::triedb::{debug_elapsed, lock_root, error::ClientError};

use self::app_grpc::backend_client::BackendClient;

pub mod app_grpc {
    tonic::include_proto!("triedb_repl");
}

type RocksHandleA<'a> = super::RocksHandleA<'a>;

type ChildExtractorFn = fn(&[u8]) -> Vec<H256>;

fn parse_diff_response(
    in_: app_grpc::GetStateDiffReply,
) -> Result<Vec<triedb::DiffChange>, ClientError> {
    in_.changeset
        .into_iter()
        .map(|insert| {
            let hash = insert
                .hash
                .ok_or(ClientError::EmptyHashGetStateDiffReply)?;
            match FormatHex::from_hex(&hash.value) {
                Ok(hash) => Ok(triedb::DiffChange::Insert(hash, insert.data.into())),
                Err(_e) => Err(ClientError::CouldNotParseHash(hash.value.clone())),
            }
        })
        .collect()
}

impl<S> super::Client<S> {
    pub async fn ping(&mut self) -> Result<(), tonic::Status> {
        let request = tonic::Request::new(());
        let response = self.client.ping(request).await?;
        log::trace!("PING | RESPONSE={:?}", response);
        Ok(())
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

    fn state_diff_request(
        heights: (evm_state::BlockNum, evm_state::BlockNum),
    ) -> tonic::Request<app_grpc::GetStateDiffRequest> {
        tonic::Request::new(app_grpc::GetStateDiffRequest {
            from: heights.0,
            to: heights.1,
        })
    }

    fn check_hash(
        height: evm_state::BlockNum,
        actual: Option<app_grpc::Hash>,
        expected: H256,
    ) -> Result<(), ClientError> {
        if actual.is_none() {
            return Err(ClientError::EmptyHashGetStateDiffReply);
        }
        let actual = actual.unwrap();

        let actual: H256 = FormatHex::from_hex(&actual.value).map_err(|_e|{
            ClientError::CouldNotParseHash(actual.value.clone())
        })?;

        if actual != expected {
            return Err(ClientError::HashMismatch {
                height,
                expected,
                actual,
            });
        }
        Ok(())
    }

    pub async fn download_and_apply_diff<'a, 'b>(
        client: &mut BackendClient<tonic::transport::Channel>,
        db_handle: &RocksHandleA<'a>,
        collection: &'b triedb::gc::TrieCollection<RocksHandleA<'b>>,
        heights: (evm_state::BlockNum, evm_state::BlockNum),
        expected_hashes: (H256, H256),
    ) -> Result<triedb::gc::RootGuard<'b, RocksHandleA<'b>, ChildExtractorFn>, ClientError> {
        log::debug!("download_and_apply_diff start");
        let start = Instant::now();
        let _from_guard = lock_root(db_handle, expected_hashes.0, account_extractor)?;
        debug_elapsed("locked root", &start);

        let response = client
            .get_state_diff(Self::state_diff_request(heights))
            .await?;
        debug_elapsed("queried response over network", &start);

        let response = response.into_inner();
        log::debug!(
            "changeset received {:?} -> {:?}, {}",
            response.first_root,
            response.second_root,
            response.changeset.len()
        );
        Self::check_hash(heights.0, response.first_root.clone(), expected_hashes.0)?;
        Self::check_hash(heights.1, response.second_root.clone(), expected_hashes.1)?;

        let diff_changes = parse_diff_response(response)?;
        debug_elapsed("parsed response", &start);

        let diff_patch = triedb::verify_diff(
            db_handle,
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
}
