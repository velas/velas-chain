use anyhow::*;
use solana_storage_bigtable::LedgerStorage;

pub async fn repeat(block_number: u64, src: LedgerStorage, dst: LedgerStorage) -> Result<()> {
    println!("Repeating block {}", block_number);

    Ok(())
}
