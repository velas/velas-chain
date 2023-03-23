use std::ops::Range;

use backon::{ExponentialBuilder, Retryable};
use evm_state::BlockNum;

use crate::triedb::client::Client;

use super::app_grpc;

const MAX_TIMES: usize = 8;
const MIN_DELAY_SEC: u64 = 1;

impl<S> Client<S> {
    pub(crate) async fn get_server_range_retried(&self) -> Result<Range<BlockNum>, tonic::Status> {
        let mut count = 0;
        let fetch_cl = || {
            *(&mut count) += 1;
            let val = count;
            async move {
                log::trace!(
                    "attempting try to fetch servers_range {} ({})",
                    self.state_rpc_address,
                    val,
                );
                let mut client = self.client.clone();

                Self::get_block_range(&mut client).await
            }
        };

        let res = fetch_cl
            .retry(
                &ExponentialBuilder::default()
                    .with_min_delay(std::time::Duration::new(MIN_DELAY_SEC, 0))
                    .with_max_times(MAX_TIMES),
            )
            .await?;
        Ok(res.into())
    }

    pub(crate) async fn prefetch_height_retried(
        &self,
        height: BlockNum,
    ) -> Result<Option<app_grpc::PrefetchHeightReply>, tonic::Status> {
        let mut count = 0;
        let fetch_cl = || {
            *(&mut count) += 1;
            let val = count;
            async move {
                log::trace!(
                    "attempting try to fetch servers_range {} ({})",
                    self.state_rpc_address,
                    val,
                );
                let mut client = self.client.clone();

                Self::prefetch_height(&mut client, height).await
            }
        };

        let res = fetch_cl
            .retry(
                &ExponentialBuilder::default()
                    .with_min_delay(std::time::Duration::new(MIN_DELAY_SEC, 0))
                    .with_max_times(MAX_TIMES),
            )
            .await?;
        Ok(res)
    }
}
