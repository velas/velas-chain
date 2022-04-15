use anyhow::*;
use evm_state::BlockNum;
use solana_storage_bigtable::LedgerStorage;

pub async fn check_evm(ledger: &LedgerStorage, block: BlockNum) -> Result<()> {
    let evm_block = ledger.get_evm_confirmed_full_block(block).await.unwrap();

    log::info!(
        "EVM Block {block}, timestamp {} with hash {}:\n{:?}",
        evm_block.header.timestamp,
        evm_block.header.hash(),
        &evm_block
    );
    Ok(())
}
