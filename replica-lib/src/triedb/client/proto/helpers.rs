use evm_rpc::FormatHex;
use evm_state::H256;

use crate::triedb::error::ClientError;

use super::app_grpc;


pub(super) fn parse_diff_response(
    in_: app_grpc::GetStateDiffReply,
) -> Result<Vec<triedb::DiffChange>, ClientError> {
    in_.changeset
        .into_iter()
        .map(|insert| {
            let hash = insert.hash.ok_or(ClientError::EmptyHashGetStateDiffReply)?;
            match FormatHex::from_hex(&hash.value) {
                Ok(hash) => Ok(triedb::DiffChange::Insert(hash, insert.data.into())),
                Err(_e) => Err(ClientError::CouldNotParseHash(hash.value.clone())),
            }
        })
        .collect()
}

pub(super) fn state_diff_request(
    heights: (evm_state::BlockNum, evm_state::BlockNum),
) -> tonic::Request<app_grpc::GetStateDiffRequest> {
    tonic::Request::new(app_grpc::GetStateDiffRequest {
        from: heights.0,
        to: heights.1,
    })
}

pub(super) fn check_hash(
    height: evm_state::BlockNum,
    actual: Option<app_grpc::Hash>,
    expected: H256,
) -> Result<(), ClientError> {
    if actual.is_none() {
        return Err(ClientError::EmptyHashGetStateDiffReply);
    }
    let actual = actual.unwrap();

    let actual: H256 = FormatHex::from_hex(&actual.value)
        .map_err(|_e| ClientError::CouldNotParseHash(actual.value.clone()))?;

    if actual != expected {
        return Err(ClientError::HashMismatch {
            height,
            expected,
            actual,
        });
    }
    Ok(())
}
