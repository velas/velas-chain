use anyhow::*;
use solana_sdk::clock::Slot;
use solana_storage_bigtable::LedgerStorage;

use crate::extensions::NativeBlockExt;

pub async fn check_native(ledger: LedgerStorage, slot: Slot) -> Result<()> {
    let native_block = ledger.get_confirmed_block(slot).await.context(format!(
        r#"Unable to get Native block {slot} from table "blocks""#
    ))?;

    let txs = native_block.parse_instructions();

    crate::log(
        log::Level::Info,
        format!(
            "Native block {slot} with timstamp {} contains instructions:",
            native_block.block_time.unwrap()
        ),
    );
    crate::log(
        log::Level::Info,
        format!("EvmTransaction: {}", txs.instr_evm_transaction()),
    );
    crate::log(
        log::Level::Info,
        format!("SwapNativeToEther: {}", txs.instr_evm_swap_to_native()),
    );
    crate::log(
        log::Level::Info,
        format!("FreeOwnership: {}", txs.instr_evm_free_ownership()),
    );
    crate::log(
        log::Level::Info,
        format!("EvmBigTransaction: {}", txs.instr_evm_big_transaction()),
    );
    crate::log(
        log::Level::Info,
        format!(
            "EvmAuthorizedTransaction: {}",
            txs.instr_evm_authorized_transaction()
        ),
    );

    Ok(())
}
