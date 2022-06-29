use anyhow::*;
use solana_sdk::clock::Slot;
use solana_storage_bigtable::LedgerStorage;

use crate::extensions::NativeBlockExt;

pub async fn check_native(ledger: LedgerStorage, slot: Slot) -> Result<()> {
    let native_block = ledger.get_confirmed_block(slot).await.context(format!(
        r#"Unable to get Native block {slot} from table "blocks""#
    ))?;

    let txs = native_block.parse_instructions();

    log::info!(
        "Native block {slot} timstamp {} contains instructions:",
        native_block.block_time.unwrap()
    );
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
