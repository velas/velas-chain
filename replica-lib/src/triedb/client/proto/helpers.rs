use evm_rpc::FormatHex;
use evm_state::H256;

use crate::triedb::error::{ClientError, ClientProtoError};

use super::app_grpc;

pub(super) fn parse_diff_response(
    in_: app_grpc::GetStateDiffReply,
) -> Result<Vec<triedb::DiffChange>, ClientError> {
    let mut result: Vec<triedb::DiffChange> = vec![];
    for insert in in_.changeset {
        let hash = insert.hash.ok_or(ClientProtoError::EmptyHash)?;
        let hash = FormatHex::from_hex(&hash.value)
            .map_err(|_err| ClientProtoError::CouldNotParseHash(hash.value.clone()))?;
        result.push(triedb::DiffChange::Insert(hash, insert.data.into()));
    }
    Ok(result)
}

pub(super) fn state_diff_request(
    heights: (evm_state::BlockNum, evm_state::BlockNum),
    expected_hashes: (H256, H256),
) -> tonic::Request<app_grpc::GetStateDiffRequest> {
    tonic::Request::new(app_grpc::GetStateDiffRequest {
        from: heights.0,
        to: heights.1,
        first_root: Some(app_grpc::Hash {
            value: expected_hashes.0.format_hex(),
        }),
        second_root: Some(app_grpc::Hash {
            value: expected_hashes.1.format_hex(),
        }),
    })
}
