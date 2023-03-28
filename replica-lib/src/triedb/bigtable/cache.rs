use std::{
    collections::HashMap,
    sync::{Arc, Mutex}, ops::Range,
};

use evm_state::{BlockNum, H256};

use solana_storage_bigtable::LedgerStorage;
use async_trait::async_trait;

use crate::triedb::{error::EvmHeightError, EvmHeightIndex};

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
            Some(result) => return Ok(*result),
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
        let block_res = self
            .bigtable
            .get_evm_confirmed_full_blocks(range.start, range.end - 1)
            .await?;

        let mut map = self.cache.lock().expect("poison");
        for block in block_res {
            let bn = block.header.block_number;
            let hash = block.header.state_root;

            map.insert(bn, hash);
        }
        Ok(())
    }
}


