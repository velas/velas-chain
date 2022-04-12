use anyhow::*;
use solana_storage_bigtable::LedgerStorage;

use super::find::BlockRange;

pub async fn restore_chain(ledger: &LedgerStorage, evm_missing: BlockRange) -> Result<()> {
    let evm_header_left = ledger.get_evm_confirmed_block_header(evm_missing.first - 1)
        .await
        .context(format!("Unable to get EVM block header {}", evm_missing.first))?;
    
    let evm_header_right = ledger.get_evm_confirmed_block_header(evm_missing.last + 1)
        .await
        .context(format!("Unable to get EVM block header {}", evm_missing.last))?;

    let mut native_blocks = vec![];

    for slot in evm_header_left.native_chain_slot..=evm_header_right.native_chain_slot {
        let native_block = ledger.get_confirmed_block(slot)
            .await
            .context(format!("Unable to get Native Block {}", slot))?;
        native_blocks.push(native_block);
    }
    Ok(())
}

// async fn get_native_boundary_blocks(ledger: &LedgerStorage, missing: &BlockRange) -> Result<BlockRange> {

// }