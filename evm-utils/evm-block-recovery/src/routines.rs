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

async fn write_block(ledger: &solana_storage_bigtable::LedgerStorage, full_block: evm_state::Block) -> Result<()> {
    log::info!(
        "Writing block {} with hash {} to the Ledger...",
        full_block.header.block_number,
        full_block.header.hash()
    );

    let block_num = full_block.header.block_number;

    ledger
        .upload_evm_block(block_num, full_block)
        .await
        .context(format!("Unable to write block {block_num} to bigtable"))?;

    Ok(())
}