use std::{ops::Range, time::Duration};

use evm_state::BlockNum;
use tokio::{sync::mpsc, time::sleep};

use crate::triedb::{
    client::Client, error::client, EvmHeightIndex, WriteRange, MAX_PREFETCH_RANGE_CHUNK,
};

use self::{chunked_range::ChunkedRange, kickstart_point::KickStartPoint};
mod chunked_range;
mod kickstart_point;
mod kilosievert;

impl<S> Client<S>
where
    S: EvmHeightIndex + Clone + Sync + Send + 'static,
{
    pub(super) async fn process_ranges(
        &mut self,
        ranges: Vec<Range<BlockNum>>,
        kickstart_point: BlockNum,
    ) -> Result<(), client::range_sync::Error> {
        let expected_hash = self
            .block_storage
            .get_evm_confirmed_state_root_retried(kickstart_point)
            .await?;

        let hash = match self.check_height(expected_hash, kickstart_point).await {
            Ok(hash) => hash,
            Err(err) => match err {
                mismatch @ client::check_height::Error::HashMismatch { .. } => {
                    panic!("different chains {:?}", mismatch);
                }
                other => {
                    return Err(other)?;
                }
            },
        };

        let ranges = ranges
            .into_iter()
            .flat_map(|range| ChunkedRange {
                range,
                chunk_size: MAX_PREFETCH_RANGE_CHUNK,
            })
            .collect::<Vec<_>>();

        let mut kick = KickStartPoint::new(kickstart_point, hash);
        for range in ranges {
            kick = self.process_range(range, kick).await?;
        }
        if kick.get().height - kickstart_point < 10 {
            sleep(Duration::new(3, 0)).await;
            
        }
        Ok(())
    }

    pub(super) async fn process_range(
        &mut self,
        range: Range<BlockNum>,
        kickstart_point: KickStartPoint,
    ) -> Result<KickStartPoint, client::range_sync::Error> {
        log::warn!("start range {:?}", range);
        self.block_storage.prefetch_roots_retried(&range).await?;

        self.prefetch_range_retried(&range).await?;

        let (stage_one_output, stage_two_input) = mpsc::channel(STAGE_TWO_CHANNEL_CAPACITY);
        let _jh_stage_one = tokio::task::spawn({
            let block_storage = self.block_storage.clone();
            let rpc_address = self.state_rpc_address.to_owned();
            let request_workers = self.request_workers;

            let range = range.clone();
            let kickstart_point = kickstart_point.clone();
            let client = self.client.clone();

            async move {
                kilosievert::concrete_chamber::process(
                    &client,
                    &block_storage,
                    range,
                    kickstart_point,
                    rpc_address,
                    stage_one_output,
                    request_workers,
                )
                .await;
            }
        });

        let (stage_two_output, mut stage_three_input) = mpsc::channel(STAGE_THREE_CHANNEL_CAPACITY);
        let _jh_stage_two = tokio::task::spawn({
            let kickstart_point = kickstart_point.clone();
            let storage = self.storage.clone();
            let db_workers = self.db_workers;

            async move {
                kilosievert::concrete_chamber::steel_container::process(
                    kickstart_point,
                    storage,
                    stage_two_input,
                    stage_two_output,
                    db_workers,
                )
                .await;
            }
        });

        let mut count_total_nodes = 0;
        let mut thousands_count = 0;
        let mut count_total_errs = 0;
        let mut err_hundrends_count = 0;
        while let Some(result) = stage_three_input.recv().await {
            match result {
                Err(err) => {
                    log::debug!("{:#?}", err);
                    count_total_errs += 1;
                    if count_total_errs / 100 > err_hundrends_count {
                        err_hundrends_count = count_total_errs / 100;
                        log::info!(
                            "running total nodes {}, errs {}",
                            count_total_nodes,
                            count_total_errs
                        );
                    }
                }
                Ok(result) => {
                    log::debug!("{:#?}", result);
                    count_total_nodes += result.changeset_len;
                    if count_total_nodes / 100_000 > thousands_count {
                        thousands_count = count_total_nodes / 100_000;
                        log::info!(
                            "running total nodes {}, errs {}",
                            count_total_nodes,
                            count_total_errs
                        );
                    }
                    self.range
                        .update(result.request.heights.1)
                        .expect("persist range");
                }
            }
        }

        log::warn!("done range {:?}", range);
        self.range.flush().expect("persist range");
        Ok(kickstart_point)
    }
}

const STAGE_TWO_CHANNEL_CAPACITY: usize = 50;

const STAGE_THREE_CHANNEL_CAPACITY: usize = 10000;
