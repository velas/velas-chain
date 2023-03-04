use crate::{
    cli::CheckEvmArgs,
    error::RoutineResult,
    ledger,
};

pub async fn check_evm(
    creds: Option<String>,
    instance: String,
    args: CheckEvmArgs,
) -> RoutineResult {
    let CheckEvmArgs { block_number } = args;

    let ledger = ledger::with_params(creds, instance).await?;

    let evm_block = ledger.get_evm_confirmed_full_block(block_number).await;

    match evm_block {
        Ok(evm_block) => log::info!(
            "EVM Block {block_number}, timestamp {} with hash {}:\n{:?}",
            evm_block.header.timestamp,
            evm_block.header.hash(),
            &evm_block
        ),
        Err(err) => {
            log::warn!(r#"EVM Block {block_number} at "evm-full-blocks" not found: {err:?}"#)
        }
    }

    let evm_header = ledger.get_evm_confirmed_block_header(block_number).await;

    match evm_header {
        Ok(evm_header) => log::info!(
            "EVM Header {block_number}, timestamp {}",
            evm_header.timestamp
        ),
        Err(err) => log::warn!(r#"EVM Header {block_number} at "evm-blocks" not found: {err:?}"#),
    }

    Ok(())
}
