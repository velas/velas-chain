use evm_rpc::FormatHex;
use evm_state::H256;

use crate::triedb::{error::client, DiffRequest, TryConvert};

use super::app_grpc;

impl TryConvert<Option<app_grpc::Hash>> for H256 {
    type Error = client::proto::Error;

    fn try_from(hash: Option<app_grpc::Hash>) -> Result<Self, Self::Error> {
        let hash = hash.ok_or(client::proto::Error::EmptyHash)?;
        let res = H256::from_hex(&hash.value)
            .map_err(|_| client::proto::Error::ParseHash(hash.value.clone()))?;
        Ok(res)
    }
}

pub(in crate::triedb::client) fn parse_diff_response(
    in_: app_grpc::GetStateDiffReply,
) -> Result<Vec<triedb::DiffChange>, client::proto::Error> {
    let mut result: Vec<triedb::DiffChange> = vec![];
    for insert in in_.changeset {
        let hash = <H256 as TryConvert<_>>::try_from(insert.hash)?;
        result.push(triedb::DiffChange::Insert(hash, insert.data.into()));
    }
    Ok(result)
}

pub(super) fn state_diff_request(
    request: DiffRequest,
) -> tonic::Request<app_grpc::GetStateDiffRequest> {
    tonic::Request::new(app_grpc::GetStateDiffRequest {
        from: request.heights.0,
        to: request.heights.1,
        first_root: Some(app_grpc::Hash {
            value: request.expected_hashes.0.format_hex(),
        }),
        second_root: Some(app_grpc::Hash {
            value: request.expected_hashes.1.format_hex(),
        }),
    })
}
