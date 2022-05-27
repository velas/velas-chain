use anyhow::*;
use evm_state::Block;
use solana_storage_bigtable::LedgerStorage;

use crate::routines::write_block;

pub async fn upload(ledger: &LedgerStorage, collection_path: String) -> Result<()> {
    log::info!("Reading file: '{}'...", &collection_path);
    let content = std::fs::read_to_string(&collection_path)
        .context(format!("unable to read file '{}'", &collection_path))?;
    log::info!("{} length string read.", content.len());
    
    log::info!("Deserializing data...");
    let blocks: Vec<Block> = serde_json::from_str(&content)
        .context(format!("unable to deserialize string into vector:\n{}", &content))?;
    
    if blocks.is_empty() {
        log::warn!("Blocks collection is empty, nothing to upload, exiting...");
        return Ok(())
    }

    log::info!("Blocks in collection: {}", blocks.len());

    let block_ids = blocks
        .iter()
        .map(|b| b.header.block_number)
        .collect::<Vec<_>>();
    log::info!("Block numbers: {:?}", &block_ids);

    // TODO: ask user confirmation before actually write blocks

    for block in blocks {
        write_block(ledger, block).await?;
    }

    Ok(())
}
