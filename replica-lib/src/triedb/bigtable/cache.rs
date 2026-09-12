use std::{
    collections::HashMap,
    ops::Range,
    sync::{Arc, Mutex},
};

use evm_state::{BlockNum, H256};

use async_trait::async_trait;
use solana_storage_bigtable::LedgerStorage;

use crate::triedb::{error::evm_height, EvmHeightIndex, ReadRange, MAX_PREFETCH_RANGE_CHUNK};

#[derive(Clone)]
struct Inner {
    map: HashMap<BlockNum, H256>,
    last_hint: BlockNum,
}

#[derive(Clone)]
pub struct CachedRootsLedgerStorage {
    bigtable: LedgerStorage,
    cache: Arc<Mutex<Inner>>,
}

impl CachedRootsLedgerStorage {
    pub fn new(bigtable: LedgerStorage, hint: BlockNum) -> Self {
        let inner = Inner {
            map: HashMap::new(),
            last_hint: hint,
        };
        Self {
            bigtable,
            cache: Arc::new(Mutex::new(inner)),
        }
    }

    pub async fn get_first_available_block(&self) -> Result<BlockNum, evm_height::Error> {
        let first = self.bigtable.get_evm_first_available_block().await?;

        match first {
            Some(height) => Ok(height),
            None => Err(evm_height::Error::NoFirst),
        }
    }

    pub async fn get_last_available_block(&self) -> Result<BlockNum, evm_height::Error> {
        let hint = self.cache.lock().expect("poison").last_hint;

        let vec = self
            .bigtable
            .get_evm_confirmed_full_blocks_nums(hint, 0)
            .await?;

        match vec.len() {
            0 => Err(evm_height::Error::NoLast),
            _ => {
                let result = vec[vec.len() - 1];
                self.cache.lock().expect("poison").last_hint = result;
                Ok(result)
            }
        }
    }
}

#[async_trait]
impl ReadRange for CachedRootsLedgerStorage {
    async fn get(&self) -> Result<std::ops::Range<BlockNum>, evm_height::Error> {
        let start = self.get_first_available_block().await?;
        let end = self.get_last_available_block().await? + 1;

        Ok(start..end)
    }
}

#[async_trait]
impl EvmHeightIndex for CachedRootsLedgerStorage {
    async fn get_evm_confirmed_state_root(
        &self,
        block_num: evm_state::BlockNum,
    ) -> Result<Option<H256>, evm_height::Error> {
        if block_num == 0 {
            return Err(evm_height::Error::ForbidZero);
        }
        if let Some(result) = self.cache.lock().expect("poison").map.get(&block_num) {
            return Ok(Some(*result));
        }
        let block = self.bigtable.get_evm_confirmed_full_block(block_num).await;
        let block = match block {
            Err(solana_storage_bigtable::Error::BlockNotFound(..)) => {
                return Ok(None);
            }
            Err(err) => Err(err)?,
            Ok(block) => block,
        };
        let result = block.header.state_root;

        self.cache
            .lock()
            .expect("poison")
            .map
            .insert(block_num, result);
        Ok(Some(result))
    }

    async fn prefetch_roots(
        &self,
        range: &Range<evm_state::BlockNum>,
    ) -> Result<(), evm_height::Error> {
        if (range.end - range.start) > MAX_PREFETCH_RANGE_CHUNK {
            return Err(evm_height::Error::ExceedMaxChunk {
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
        let mut inner = self.cache.lock().expect("poison");
        for block in block_res {
            let bn = block.header.block_number;
            let hash = block.header.state_root;

            inner.map.insert(bn, hash);
        }
        Ok(())
    }
}
