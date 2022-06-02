use anyhow::Result;
use evm_state::BlockNum;
use solana_storage_bigtable::LedgerStorage;

pub async fn check_evm(ledger: LedgerStorage, block: BlockNum) -> Result<()> {
    let evm_block = ledger.get_evm_confirmed_full_block(block).await;

    match evm_block {
        Ok(evm_block) => log::info!(
            "EVM Block {block}, timestamp {} with hash {}:\n{:?}",
            evm_block.header.timestamp,
            evm_block.header.hash(),
            &evm_block
        ),
        Err(err) => log::warn!(r#"EVM Block {block} at "evm-full-blocks" not found: {err:?}"#),
    }

    let evm_header = ledger.get_evm_confirmed_block_header(block).await;

    match evm_header {
        Ok(evm_header) => log::info!("EVM Header {block}, timestamp {}", evm_header.timestamp),
        Err(err) => log::warn!(r#"EVM Header {block} at "evm-blocks" not found: {err:?}"#),
    }

    Ok(())
}
