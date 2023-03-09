use std::time::Duration;

use evm_state::{BlockNum, H256};

use crate::triedb::{error::{ClientAdvanceError, EvmHeightError, source_matches_type, ClientError}, range::Advance, EvmHeightIndex, collection};
use triedb::gc::DbCounter;

use super::Client;

const MAX_CHUNK: u64 = 10;

impl<S> Client<S> {
    fn compute_advance(&self, server_offer: std::ops::Range<BlockNum>) -> Advance {
        self.range.compute_advance(MAX_CHUNK, server_offer)
    }
}

impl<S> Client<S>
where
    S: EvmHeightIndex,
{
    async fn fetch_state_roots(
        &self,
        heights: (BlockNum, BlockNum),
    ) -> Result<(H256, H256), EvmHeightError> {
        let from = self
            .block_storage
            .get_evm_confirmed_state_root(heights.0)
            .await?;
        let to = self
            .block_storage
            .get_evm_confirmed_state_root(heights.1)
            .await?;
        Ok((from, to))
    }

    async fn iterate_advance(
        &mut self,
        mut advance: Advance,
        address: String,
    ) -> Result<(), ClientAdvanceError> {
        let collection = collection(&self.storage);
        let mut start = advance.start;
        log::warn!("attempting to advance {:?}", advance);

        while let Some(next) = advance.next_bidirectional() {
            log::warn!("next height {}", next);
            if self.range.get().contains(&next) {
                log::warn!("skipping height {} as already present", next);
                continue;
            }
            let heights = (start, next);
            let hashes = self.fetch_state_roots(heights).await?;
            let diff_response =
                Self::download_and_apply_diff(&mut self.client, &collection, heights, hashes).await;
            match diff_response {
                Err(e) => {
                    let _match = source_matches_type::<tonic::transport::Error>(&e);
                    return Err(ClientAdvanceError::ClientErrorWithContext {
                        heights: Some(heights),
                        hashes: Some(hashes),
                        state_rpc_address: address,
                        error: e,
                    });
                }
                Ok(guard) => {
                    let to = hashes.1;
                    log::debug!("persisted root {}", guard.leak_root());
                    collection.database.gc_pin_root(to);
                    log::debug!(
                        "persisted root count after leak {}",
                        collection.database.gc_count(to)
                    );
                    self.range.update(next).expect("persist range update");
                }
            }
            start = next;
        }
        Ok(())
    }

    async fn iteration(&mut self) -> Result<Advance, (ClientAdvanceError, Duration)> {
        let block_range = self.get_block_range().await.map_err(|status| {
            let err: ClientError = status.into();
            err
        });
        if let Err(e) = block_range {
            return Err((
                ClientAdvanceError::ClientErrorWithContext {
                    heights: None,
                    hashes: None,
                    state_rpc_address: self.state_rpc_address.clone(),
                    error: e,
                },
                Duration::new(1, 0),
            ));
        }
        let block_range: std::ops::Range<BlockNum> = block_range.unwrap().into();

        let advance = self.compute_advance(block_range.clone());
        if advance.is_empty() {
            return Err((
                ClientAdvanceError::EmptyAdvance {
                    state_rpc_address: self.state_rpc_address.clone(),
                    self_range: self.range.get(),
                    server_offer: block_range,
                },
                Duration::new(3, 0),
            ));
        }
        let result = self
            .iterate_advance(advance.clone(), self.state_rpc_address.clone())
            .await;
        if let Err(e) = result {
            Err((e, Duration::new(5, 0)))
        } else {
            Ok(advance)
        }
    }

    pub async fn routine(&mut self) {
        assert!(!self.range.get().is_empty());
        loop {
            match self.iteration().await {
                Err((err, dur)) => {
                    log::error!("main loop {:?}", err);
                    tokio::time::sleep(dur).await;
                }
                Ok(advance) => {
                    log::warn!("success on advance {:?}", advance);
                }
            }
        }
    }
}
