use std::{ops::Range, time, thread};

use evm_state::BlockNum;

use crate::triedb::{client::Client, error::ClientError, EvmHeightIndex};

impl<S> Client<S>
where
    S: EvmHeightIndex + Sync,
{
    pub(super) async fn process_ranges(
        &mut self,
        ranges: Vec<Range<BlockNum>>,
        kickstart_point: BlockNum,
    ) {
        for range in ranges {
            self.process_range(range, kickstart_point).await;
        }
    }

    pub(super) async fn process_range(
        &mut self,
        ranges: Range<BlockNum>,
        kickstart_point: BlockNum,
    ) {
        let expected_hash = self
            .block_storage
            .get_evm_confirmed_state_root_retried(kickstart_point)
            .await;

        let expected_hash = match expected_hash {
            Ok(val) => val,
            val @ Err(..) => {
                
                log::error!("prefetch_height {:?}", val);
                return;
            }
            
        };
        let hash = match self
            .check_height(expected_hash, kickstart_point)
            .await
        {
            Ok(hash) => hash,
            Err(err) => match err {
                mismatch @ ClientError::PrefetchHeightMismatch { .. } => {
                    panic!("different chains {:?}", mismatch);
                }
                other @ _ => {
                    log::error!("prefetch_height {:?}", other);
                    thread::sleep(time::Duration::new(30,0));
                    return;
                }
            },
        };
        todo!("drive into happiness");
    }
}
