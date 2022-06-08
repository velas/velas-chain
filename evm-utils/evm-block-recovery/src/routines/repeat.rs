use anyhow::{Context, Result};
use evm_state::Block;
use solana_storage_bigtable::LedgerStorage;
use tokio::sync::mpsc;

#[derive(Debug)]
struct BlockMessage<B> {
    idx: usize,
    block: B,
}

pub async fn repeat_evm(
    block_number: u64,
    limit: u64,
    src: LedgerStorage,
    dst: LedgerStorage,
) -> Result<()> {
    if limit == 1 {
        log::info!("Repeat EVM Block {}", block_number)
    } else {
        log::info!(
            "Repeat EVM Blocks from {} to {}. Total iterations: {}",
            block_number,
            block_number + limit - 1,
            limit
        )
    }

    let (sender, mut receiver) = mpsc::unbounded_channel::<BlockMessage<Block>>();
    let writer = tokio::spawn(async move {
        log::info!("Writer task started");

        while let Some(message) = receiver.recv().await {
            log::info!(
                "[{}] Uploading block {} to the Destination Ledger",
                message.idx,
                block_number
            );

            let uploaded = dst
                .upload_evm_block(block_number, message.block)
                .await
                .context(format!(
                    "Unable to upload block {} to the Destination Ledger",
                    block_number
                ));

            match uploaded {
                Ok(()) => {
                    log::info!(
                        "[{}] Block {} uploaded successfully",
                        message.idx,
                        block_number
                    )
                }
                Err(_) => {
                    log::error!(
                        "[{}] Failed to upload block {} to the Destination Ledger",
                        message.idx,
                        block_number
                    )
                }
            }

            uploaded.unwrap(); // NOTICE: early return on error
        }

        log::info!("Writer task ended");
    });

    for (idx, block_number) in (block_number..block_number + limit).enumerate() {
        log::info!(
            "[{}] Reading block {} from the Source Ledger",
            idx,
            block_number
        );
        let block = src
            .get_evm_confirmed_full_block(block_number)
            .await
            .context(format!(
                "Unable to read block {} from the Source Ledger",
                block_number
            ))?;

        sender.send(BlockMessage { idx, block })?;
    }

    drop(sender);

    let _result1 = writer.await;

    Ok(())
}

pub async fn repeat_native(
    block_number: u64,
    _limit: u64,
    src: LedgerStorage,
    dst: LedgerStorage,
) -> Result<()> {
    log::info!("TODO: `repeat-native` command");

    let block = src.get_confirmed_block(block_number).await.unwrap();
    dst.upload_confirmed_block(block_number, block)
        .await
        .unwrap();

    Ok(())
}
