use std::{ops::Range, sync::Arc};

use async_trait::async_trait;
use evm_state::{BlockNum, H256};
use solana_ledger::{blockstore::Blockstore, blockstore_db::BlockstoreError};

use super::{error::evm_height, EvmHeightIndex, ReadRange};

#[async_trait]
impl ReadRange for Arc<Blockstore> {
    async fn get(&self) -> Result<std::ops::Range<BlockNum>, evm_height::Error> {
        let start = self.get_first_available_evm_block()?;
        let end = self.get_last_available_evm_block()?;

        let end = end.ok_or(evm_height::Error::NoLast)?;

        Ok(start..end + 1)
    }
}

#[async_trait]
impl EvmHeightIndex for Arc<Blockstore> {
    async fn get_evm_confirmed_state_root(
        &self,
        block_num: evm_state::BlockNum,
    ) -> Result<Option<H256>, evm_height::Error> {
        if block_num == 0 {
            return Err(evm_height::Error::ForbidZero);
        }

        let result = self.get_evm_block(block_num);
        let (block, confirmed) = match result {
            Ok((block, confirmed)) => (block, confirmed),
            Err(BlockstoreError::SlotCleanedUp) => {
                return Ok(None);
            }
            Err(err) => {
                return Err(err)?;
            }
        };

        if !confirmed {
            return Ok(None);
        }
        Ok(Some(block.header.state_root))
    }

    async fn prefetch_roots(
        &self,
        _range: &Range<evm_state::BlockNum>,
    ) -> Result<(), evm_height::Error> {
        Ok(())
    }
}
