use evm_state::{BlockNum, H256};

use crate::triedb::{client::Client, error::ClientError, EvmHeightIndex, TryConvert};

impl<S> Client<S>
where
    S: EvmHeightIndex + Sync,
{
    pub(super) async fn check_height(
        &mut self,
        expected_hash: H256,
        kickstart_point: BlockNum,
    ) -> Result<H256, ClientError> {
        let prefetch = self.prefetch_height_retried(kickstart_point).await;

        let hash = match prefetch {
            Ok(reply) => {
                let reply = reply.ok_or(ClientError::PrefetchHeightAbsent {
                    height: kickstart_point,
                })?;
                let hash = <H256 as TryConvert<_>>::try_from(reply.hash);
                hash.map_err(Into::<ClientError>::into)
            }
            Err(err) => Err(err.into()),
        }?;

        if hash != expected_hash {
            return Err(ClientError::PrefetchHeightMismatch {
                actual: hash,
                expected: expected_hash,
                height: kickstart_point,
            });
        }
        Ok(hash)
    }
}
