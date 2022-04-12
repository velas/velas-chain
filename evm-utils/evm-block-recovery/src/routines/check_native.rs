use anyhow::*;
use solana_sdk::clock::Slot;
use solana_storage_bigtable::LedgerStorage;

use crate::extensions::NativeBlockExt;

pub async fn check_native(ledger: &LedgerStorage, block: Slot) -> Result<()> {
    let native_block = ledger
        .get_confirmed_block(block)
        .await
        .context(format!("Unable to get Native block {block}"))?;
    let txs = native_block.parse_instructions();

    log::info!("Native block {block} contains instructions:");
    log::info!("EvmTransaction: {}", txs.instr_evm_transaction());
    log::info!("SwapNativeToEther: {}", txs.instr_evm_swap_to_native());
    log::info!("FreeOwnership: {}", txs.instr_evm_free_ownership());
    log::info!("EvmBigTransaction: {}", txs.instr_evm_big_transaction());
    log::info!(
        "EvmAuthorizedTransaction: {}",
        txs.instr_evm_authorized_transaction()
    );

    Ok(())
}

// Commands::CheckEvm { block } => {
//     let evm_block_header = ledger.get_evm_confirmed_block_header(block).await.unwrap();
//     println!("EVM Block ID: {}", block);
//     println!("Native Chain Slot: {}", evm_block_header.native_chain_slot);
//     println!("Evm Block Header:");
//     println!(
//         "{}",
//         serde_json::to_string_pretty(&evm_block_header).unwrap()
//     );
// }
