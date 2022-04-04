use anyhow::*;
use evm_state::{BlockHeader, BlockNum, H256};
use solana_storage_bigtable::LedgerStorage;

use crate::extensions::NativeBlockExt;

pub async fn restore(ledger: &LedgerStorage, restoring_block: BlockNum, dry_run: bool) -> Result<()> {
    let state_block_id = restoring_block - 1;
    let block_header = ledger
        .get_evm_confirmed_block_header(state_block_id)
        .await?;

    let native_block_id = block_header.native_chain_slot + 1;
    let native_block = ledger.get_confirmed_block(native_block_id).await.unwrap();

    let txs = native_block.parse_trivial_transactions()
        .context(format!("Native block {native_block_id} contains non-trivial EVM instructions"))?;
    let last_hashes: Vec<H256> = vec![];
    let state_root = block_header.state_root;

    let params = serde_json::json!([
        txs,
        last_hashes,
        block_header,
        state_root
    ]);

    log::info!("{}", serde_json::to_string_pretty(&params).unwrap());

    if dry_run {
        return Ok(());
    }

    // write_header(&ledger, header).await?;

    Ok(())
}

async fn write_header(ledger: &LedgerStorage, header: BlockHeader) -> Result<()> {
    // write header to bigtable
    todo!()
}
