use evm_state::{BlockNum, H256};

use crate::triedb::{client::Client, error::client, EvmHeightIndex, TryConvert};

impl<S> Client<S>
where
    S: EvmHeightIndex + Sync,
{
    pub(super) async fn check_height(
        &mut self,
        expected_hash: H256,
        kickstart_point: BlockNum,
    ) -> Result<H256, client::check_height::Error> {
        let prefetch = self.prefetch_height_retried(kickstart_point).await;

        let hash = match prefetch {
            Ok(reply) => {
                let reply = reply.ok_or(client::check_height::Error::HeightAbsent {
                    height: kickstart_point,
                })?;
                let hash = <H256 as TryConvert<_>>::try_from(reply.hash);
                hash.map_err(Into::<client::check_height::Error>::into)
            }
            Err(err) => Err(err.into()),
        }?;

        if hash != expected_hash {
            return Err(client::check_height::Error::HashMismatch {
                actual: hash,
                expected: expected_hash,
                height: kickstart_point,
            });
        }
        Ok(hash)
    }
}
