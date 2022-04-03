pub(crate) mod _csv;
pub(crate) mod _sanity;
pub(crate) mod find;
pub(crate) mod restore;

pub use find::find;
pub use restore::restore;

use evm_state::BlockNum;
use solana_storage_bigtable::LedgerStorage;

pub async fn temp(ledger: &LedgerStorage, block_num: BlockNum) {
    // last evm block 29354812 (dec) == 0x1bfeb3c (hex)
    let block = ledger
        .get_evm_confirmed_block_header(block_num)
        .await
        .unwrap();
    println!("Block {block_num}:\n{block:?}");
}
