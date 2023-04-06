use std::ops::Range;

use async_trait::async_trait;
use evm_state::H256;
use solana_storage_bigtable::LedgerStorage;

use crate::triedb::{error::evm_height, EvmHeightIndex};

#[async_trait]
impl EvmHeightIndex for LedgerStorage {
    async fn get_evm_confirmed_state_root(
        &self,
        block_num: evm_state::BlockNum,
    ) -> Result<H256, evm_height::Error> {
        if block_num == 0 {
            return Err(evm_height::Error::ForbidZero);
        }
        let block = self.get_evm_confirmed_full_block(block_num).await?;

        Ok(block.header.state_root)
    }

    async fn prefetch_roots(
        &self,
        _range: &Range<evm_state::BlockNum>,
    ) -> Result<(), evm_height::Error> {
        Ok(())
    }
}
