use std::ops::Range;

use async_trait::async_trait;
use evm_state::H256;
use solana_storage_bigtable::LedgerStorage;

use super::{error::EvmHeightError, EvmHeightIndex};

#[async_trait]
impl EvmHeightIndex for LedgerStorage {
    async fn get_evm_confirmed_state_root(
        &self,
        block_num: evm_state::BlockNum,
    ) -> Result<H256, EvmHeightError> {
        if block_num == 0 {
            return Err(EvmHeightError::ZeroHeightForbidden);
        }
        let block = self.get_evm_confirmed_full_block(block_num).await?;

        Ok(block.header.state_root)
    }

    async fn prefetch_roots(
        &self,
        _range: &Range<evm_state::BlockNum>,
    ) -> Result<(), EvmHeightError> {
        Ok(())
    }

}