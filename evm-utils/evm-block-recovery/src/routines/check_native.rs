use std::collections::HashMap;

use anyhow::*;
use solana_sdk::clock::Slot;
use solana_storage_bigtable::LedgerStorage;

use crate::extensions::NativeBlockExt;

pub async fn check_native(
    ledger: LedgerStorage,
    first_block: Slot,
    last_block: Slot,
) -> Result<()> {
    let limit = (last_block - first_block + 1) as usize;
    let mut natives = ledger.get_confirmed_blocks(first_block, limit).await?;
    natives.retain(|slot| *slot <= last_block);

    let mut tricky_blocks = HashMap::new();
    for n in natives {
        let native_block = ledger.get_confirmed_block(n).await.context(format!(
            r#"Unable to get Native block {first_block} from table "blocks""#
        ))?;

        let txs = native_block.parse_instructions();

        log::info!(
            "Native block {first_block} with timstamp {} contains instructions:",
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

        if !txs.only_trivial_instructions {
            tricky_blocks.insert(n, native_block).unwrap();
        }
    }

    if tricky_blocks.is_empty() {
        log::info!("No \"tricky\" native blocks were found!")
    } else {
        log::info!("Some native blocks contain non-trivial transactions");
        log::info!("{:?}", tricky_blocks);
    }

    Ok(())
}
