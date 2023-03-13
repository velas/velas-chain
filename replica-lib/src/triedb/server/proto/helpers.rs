use evm_rpc::FormatHex;
use evm_state::H256;
use triedb::DiffChange;

use crate::triedb::{
     error::{ServerError, ServerProtoError}, server::Server, EvmHeightIndex,
};

use super::{app_grpc, TryConvert};

impl TryConvert<app_grpc::Hash> for H256 {
    type Error = ServerError;

    fn try_from(hash: app_grpc::Hash) -> Result<Self, Self::Error> {
        let res = H256::from_hex(&hash.value).map_err(|_| {
            ServerProtoError::CouldNotParseHash(hash.value.clone())
        })?;
        Ok(res)
    }
}

pub(super) fn check_hash(
    height: evm_state::BlockNum,
    actual: Option<app_grpc::Hash>,
    expected: H256,
) -> Result<(), ServerError> {
    if actual.is_none() {
        return Err(ServerProtoError::EmptyHash)?;
    }
    let actual = actual.unwrap();

    let actual: H256 = FormatHex::from_hex(&actual.value)
        .map_err(|_e| ServerProtoError::CouldNotParseHash(actual.value.clone()))?;

    if actual != expected {
        return Err(ServerError::HashMismatch {
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
impl<S> Server<S>
where
    S: EvmHeightIndex + Send + Sync + 'static,
{
    pub(super) async fn fetch_state_roots(
        &self,
        from: evm_state::BlockNum,
        to: evm_state::BlockNum,
    ) -> Result<(H256, H256), ServerError> {
        let from = self
            .block_storage
            .get_evm_confirmed_state_root(from)
            .await?;
        let to = self.block_storage.get_evm_confirmed_state_root(to).await?;
        Ok((from, to))
    }
}
