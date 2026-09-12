use crate::{
    cli::CheckNativeArgs,
    error::{AppError, RoutineResult},
    extensions::NativeBlockExt,
    ledger,
};

pub async fn check_native(
    creds: Option<String>,
    instance: String,
    args: CheckNativeArgs,
) -> RoutineResult {
    let CheckNativeArgs { slot } = args;
    let ledger = ledger::with_params(creds, instance).await?;

    let native_block =
        ledger
            .get_confirmed_block(slot)
            .await
            .map_err(|source| AppError::GetNativeBlock {
                source,
                block: slot,
            })?;

    let txs = native_block.parse_instructions();

    log::info!(
        "Native block {slot} with timstamp {} contains instructions:",
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
