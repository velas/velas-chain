use solana_storage_bigtable::LedgerStorage;

use crate::data::EvmContent;

async fn print_native_to_csv(ledger: &LedgerStorage) {
    let mut results = String::new();
    results.push_str("Slot,EvmTransaction,SwapNativeToEther,FreeOwnership,EvmBigTransaction,EvmAuthorizedTransaction\n");

    let mut native_blocks = vec![];
    native_blocks.extend(53183621..=53183644);
    native_blocks.extend(53414856..=53414871);
    native_blocks.extend(54832538..=54832540);

    for slot in native_blocks {
        let native_block = ledger.get_confirmed_block(slot as u64).await.unwrap();
        let evm_content = EvmContent::from_native_block(native_block);

        results.push_str(&format!(
            "{},{},{},{},{},{}",
            slot,
            evm_content.instr_evm_transaction(),
            evm_content.instr_evm_swap_to_native(),
            evm_content.instr_evm_free_ownership(),
            evm_content.instr_evm_big_transaction(),
            evm_content.instr_evm_authorized_transaction()
        ));
        results.push('\n');

        std::fs::write("/home/maksimv/Desktop/block_result.csv", &results).unwrap();
    }
}