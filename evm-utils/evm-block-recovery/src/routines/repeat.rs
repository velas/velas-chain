use anyhow::*;
use solana_storage_bigtable::LedgerStorage;

pub async fn repeat(block_number: u64, src: LedgerStorage, dst: LedgerStorage) -> Result<()> {
    log::info!("Repeating block {}", block_number);
    // TODO: implement meaningful display printing
    // log::info!("Source Ledger: {:?}", &src);
    // log::info!("Destination Ledger: {:?}", &dst);

    log::info!("Reading block {} from the Source Ledger", block_number);
    let block = src.get_evm_confirmed_full_block(block_number).await
        .context(format!("Unable to read block {} from the Source Ledger", block_number))?;

    // TODO: add additional checks and logging

    log::info!("Uploading block {} to the Destination Ledger", block_number);
    dst.upload_evm_block(block_number, block).await
        .context(format!("Unable to read block {} from the Source Ledger", block_number))?;

    Ok(())
}
