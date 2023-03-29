use std::{ops::Range, time::Duration};

use evm_state::BlockNum;
use tokio::time::sleep;

use crate::triedb::{client::Client, error::ClientError, EvmHeightIndex, MAX_PREFETCH_RANGE_CHUNK};

use self::{chunked_range::ChunkedRange, kickstart_point::KickStartPoint};
mod chunked_range;
mod kickstart_point;
mod kilosievert;

impl<S> Client<S>
where
    S: EvmHeightIndex + Sync,
{
    pub(super) async fn process_ranges(
        &mut self,
        ranges: Vec<Range<BlockNum>>,
        kickstart_point: BlockNum,
    ) -> Result<(), ClientError> {
        let expected_hash = self
            .block_storage
            .get_evm_confirmed_state_root_retried(kickstart_point)
            .await?;

        let hash = match self.check_height(expected_hash, kickstart_point).await {
            Ok(hash) => hash,
            Err(err) => match err {
                mismatch @ ClientError::PrefetchHeightMismatch { .. } => {
                    panic!("different chains {:?}", mismatch);
                }
                other @ _ => {
                    return Err(other);
                }
            },
        };

        let ranges = ranges
            .into_iter()
            .map(|range| {
                ChunkedRange {
                    range,
                    chunk_size: MAX_PREFETCH_RANGE_CHUNK,
                }
                .into_iter()
            })
            .flatten()
            .collect::<Vec<_>>();

        let mut kick = KickStartPoint::new(kickstart_point, hash, true);
        for range in ranges {
            kick = self.process_range(range, kick).await?;
        }
        Ok(())
    }

    pub(super) async fn process_range(
        &mut self,
        range: Range<BlockNum>,
        kickstart_point: KickStartPoint,
    ) -> Result<KickStartPoint, ClientError> {
        self.block_storage.prefetch_roots_retried(&range).await?;

        self.prefetch_range_retried(&range).await?;

        sleep(Duration::new(20, 0)).await;
        Ok(kickstart_point)
    }
}
