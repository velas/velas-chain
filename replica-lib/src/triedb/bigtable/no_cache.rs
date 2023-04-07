use std::ops::Range;

use async_trait::async_trait;
use evm_state::{BlockNum, H256};
use solana_storage_bigtable::LedgerStorage;

use crate::triedb::{error::evm_height, EvmHeightIndex};

pub struct LedgerStorageWrapped {
    inner: LedgerStorage,
    len_hint: BlockNum,
}

#[allow(unused)]
impl LedgerStorageWrapped {
    pub fn new(bigtable: LedgerStorage, hint: BlockNum) -> Self {
        Self {
            inner: bigtable,
            len_hint: hint,
        }
    }

    pub async fn get_first_available_block(&self) -> Result<BlockNum, evm_height::Error> {
        let first = self.inner.get_evm_first_available_block().await?;

        match first {
            Some(height) => Ok(height),
            None => Err(evm_height::Error::NoFirst),
        }
    }

    pub async fn get_last_available_block(&self) -> Result<BlockNum, evm_height::Error> {
        let vec = self
            .inner
            .get_evm_confirmed_full_blocks_nums(self.len_hint, 0)
            .await?;

        match vec.len() {
            0 => Err(evm_height::Error::NoLast),
            _ => Ok(vec[vec.len() - 1]),
        }
    }
}

#[async_trait]
impl EvmHeightIndex for LedgerStorageWrapped {
    async fn get_evm_confirmed_state_root(
        &self,
        block_num: evm_state::BlockNum,
    ) -> Result<Option<H256>, evm_height::Error> {
        if block_num == 0 {
            return Err(evm_height::Error::ForbidZero);
        }
        let block = self.inner.get_evm_confirmed_full_block(block_num).await;

        let block = match block {
            Err(solana_storage_bigtable::Error::BlockNotFound(..)) => {
                return Ok(None);
            }
            Err(err) => Err(err)?,
            Ok(block) => block,
        };

        Ok(Some(block.header.state_root))
    }

    async fn prefetch_roots(
        &self,
        _range: &Range<evm_state::BlockNum>,
    ) -> Result<(), evm_height::Error> {
        Ok(())
    }
}
