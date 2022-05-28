pub(crate) mod check_evm;
pub(crate) mod check_native;
pub(crate) mod find;
pub(crate) mod restore_chain;
pub(crate) mod upload;

pub use check_evm::check_evm;
pub use check_native::check_native;
pub use find::find;
pub use restore_chain::restore_chain;
pub use upload::upload;

use anyhow::*;

async fn write_blocks_collection(
    ledger: &solana_storage_bigtable::LedgerStorage,
    blocks: Vec<evm_state::Block>,
) -> Result<()> {
    for block in blocks {
        log::info!(
            "Writing block {} with hash {} to the Ledger...",
            block.header.block_number,
            block.header.hash()
        );

        let block_num = block.header.block_number;

        // TODO: informative message if early-return
        ledger
            .upload_evm_block(block_num, block)
            .await
            .context(format!("Unable to write block {block_num} to bigtable"))?;
    }

    Ok(())
}
