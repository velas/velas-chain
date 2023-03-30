use std::{
    collections::HashMap,
    ops::Range,
    sync::{Arc, Mutex},
};

use evm_state::{BlockNum, H256};

use async_trait::async_trait;
use solana_storage_bigtable::LedgerStorage;

use crate::triedb::{error::EvmHeightError, EvmHeightIndex, MAX_PREFETCH_RANGE_CHUNK};

#[derive(Clone)]
pub struct CachedRootsLedgerStorage {
    bigtable: LedgerStorage,
    cache: Arc<Mutex<HashMap<BlockNum, H256>>>,
}

impl CachedRootsLedgerStorage {
    pub fn new(bigtable: LedgerStorage) -> Self {
        Self {
            bigtable,
            cache: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

#[async_trait]
impl EvmHeightIndex for CachedRootsLedgerStorage {
    async fn get_evm_confirmed_state_root(
        &self,
        block_num: evm_state::BlockNum,
    ) -> Result<H256, EvmHeightError> {
        if block_num == 0 {
            return Err(EvmHeightError::ZeroHeightForbidden);
        }
        match self.cache.lock().expect("poison").get(&block_num) {
            Some(result) => {
                return Ok(*result);
            }
            None => {}
        }
        let block = self
            .bigtable
            .get_evm_confirmed_full_block(block_num)
            .await?;
        let result = block.header.state_root;

        self.cache.lock().expect("poison").insert(block_num, result);
        Ok(result)
    }

    async fn prefetch_roots(
        &self,
        range: &Range<evm_state::BlockNum>,
    ) -> Result<(), EvmHeightError> {
        log::info!("issuing prefetch roots request to bt: {:?}", range);
        if (range.end - range.start) > MAX_PREFETCH_RANGE_CHUNK {
            return Err(EvmHeightError::MaxBlockChunkExceeded {
                max: MAX_PREFETCH_RANGE_CHUNK,
                actual: range.end - range.start,
            });
        }
        let block_res = self
            .bigtable
            .get_evm_confirmed_full_blocks(range.start, range.end - 1)
            .await?;

        log::info!(
            "prefetch roots response retrieved from bt: {}",
            block_res.len()
        );
        let mut map = self.cache.lock().expect("poison");
        for block in block_res {
            let bn = block.header.block_number;
            let hash = block.header.state_root;

            map.insert(bn, hash);
        }
        Ok(())
    }
}
