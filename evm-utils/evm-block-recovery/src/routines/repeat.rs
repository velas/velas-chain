use anyhow::*;
use solana_storage_bigtable::LedgerStorage;

pub async fn repeat(
    block_number: u64,
    limit: u64,
    src: LedgerStorage,
    dst: LedgerStorage,
) -> Result<()> {
    if limit == 1 {
        log::info!("Repeat EVM Block {}", block_number)
    } else {
        log::info!(
            "Repeat EVM Blocks from {} to {}. Total iterations: {}",
            block_number,
            block_number + limit - 1,
            limit
        )
    }

    for (idx, block_number) in (block_number..block_number + limit).enumerate() {
        log::info!("[{}] Repeating block {}", idx, block_number);
        // TODO: implement meaningful display printing
        // log::info!("[{}] Source Ledger: {:?}", idx, &src);
        // log::info!("[{}] Destination Ledger: {:?}", idx, &dst);

        log::info!(
            "[{}] Reading block {} from the Source Ledger",
            idx,
            block_number
        );
        let block = src
            .get_evm_confirmed_full_block(block_number)
            .await
            .context(format!(
                "Unable to read block {} from the Source Ledger",
                block_number
            ))?;

        // TODO: add additional checks
        // TODO: log and display context details in case of early return
        log::info!(
            "[{}] Uploading block {} to the Destination Ledger",
            idx,
            block_number
        );
        dst.upload_evm_block(block_number, block)
            .await
            .context(format!(
                "Unable to read block {} from the Source Ledger",
                block_number
            ))?;
    }

    Ok(())
}
