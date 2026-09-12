use std::time::Instant;

use evm_rpc::FormatHex;
use evm_state::H256;
use triedb::DiffChange;

use crate::triedb::{
    debug_elapsed,
    error::{evm_height, server},
    server::Server,
    TryConvert,
};

use super::app_grpc;

impl TryConvert<app_grpc::Hash> for H256 {
    type Error = server::Error;

    fn try_from(hash: app_grpc::Hash) -> Result<Self, Self::Error> {
        let res = H256::from_hex(&hash.value)
            .map_err(|_| server::proto::Error::HashParse(hash.value.clone()))?;
        Ok(res)
    }
}

pub(super) fn check_hash(
    height: evm_state::BlockNum,
    actual: Option<app_grpc::Hash>,
    expected: H256,
) -> Result<(), server::Error> {
    let actual = match actual {
        Some(val) => val,
        None => {
            return Err(server::proto::Error::HashEmpty)?;
        }
    };

    let actual: H256 = FormatHex::from_hex(&actual.value)
        .map_err(|_e| server::proto::Error::HashParse(actual.value.clone()))?;

    if actual != expected {
        return Err(server::Error::HashMismatch {
            height,
            expected,
            actual,
        });
    }
    Ok(())
}

pub(super) fn map_changeset(changeset: Vec<DiffChange>) -> Vec<app_grpc::Insert> {
    let mut reply_changeset = vec![];

    for change in changeset {
        match change {
            triedb::DiffChange::Insert(hash, data) => {
                let raw_insert = app_grpc::Insert {
                    hash: Some(app_grpc::Hash {
                        value: hash.format_hex(),
                    }),
                    data: data.into(),
                };
                reply_changeset.push(raw_insert);
            }
            triedb::DiffChange::Removal(..) => {
                // skip
                // no need to transfer it over the wire
            }
        }
    }
    reply_changeset
}
impl Server {
    pub(super) async fn fetch_state_roots(
        &self,
        from_height: evm_state::BlockNum,
        to_height: evm_state::BlockNum,
    ) -> Result<(H256, H256), server::Error> {
        let mut start = Instant::now();
        let from = self
            .block_storage
            .get_evm_confirmed_state_root(from_height)
            .await?;

        let from = match from {
            Some(from) => from,
            None => Err(evm_height::Error::NoHeightFound(from_height))
                .map_err(Into::<server::Error>::into)?,
        };
        let to = self
            .block_storage
            .get_evm_confirmed_state_root(to_height)
            .await?;

        let to = match to {
            Some(to) => to,
            None => Err(evm_height::Error::NoHeightFound(to_height))
                .map_err(Into::<server::Error>::into)?,
        };

        let _ = debug_elapsed(&mut start);
        Ok((from, to))
    }
}
