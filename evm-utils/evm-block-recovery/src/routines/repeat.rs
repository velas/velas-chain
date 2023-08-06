use {
    crate::{
        cli::{RepeatEvmArgs, RepeatNativeArgs},
        error::{AppError, RoutineResult},
        ledger,
    },
    evm_state::Block,
    solana_sdk::hash::Hash,
    solana_transaction_status::{
        ConfirmedBlock, VersionedConfirmedBlock, VersionedTransactionWithStatusMeta,
    },
    tokio::sync::mpsc,
};

#[derive(Debug, Default)]
struct History {
    oks: Vec<u64>,
    upload_failures: Vec<(u64, String)>,
    missing_metas: Vec<(u64, Hash)>,
}

impl History {
    pub fn collect_ok(&mut self, block_number: u64) {
        self.oks.push(block_number)
    }

    pub fn collect_upload_failure(&mut self, block_number: u64, error_msg: String) {
        self.upload_failures.push((block_number, error_msg))
    }

    pub fn collect_missing_meta(&mut self, block_number: u64, tx_msg_hash: Hash) {
        self.missing_metas.push((block_number, tx_msg_hash))
    }
}

#[derive(Debug)]
pub struct BlockMessage<B> {
    idx: usize,
    block: B,
    block_number: u64,
}

pub async fn repeat_evm(args: RepeatEvmArgs) -> RoutineResult {
    let RepeatEvmArgs {
        block_number,
        limit,
        src_creds,
        src_instance,
        dst_creds,
        dst_instance,
    } = args;

    let src = ledger::with_params(Some(src_creds), src_instance).await?;

    let dst = ledger::with_params(Some(dst_creds), dst_instance).await?;

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

        let mut success = vec![];
        let mut error = vec![];

        while let Some(message) = receiver.recv().await {
            let uploaded = dst
                .upload_evm_block(message.block_number, message.block)
                .await
                .map_err(AppError::UploadEvmBlock);

            match uploaded {
                Ok(()) => {
                    log::info!(
                        "[{}] Block {} uploaded successfully",
                        message.idx,
                        message.block_number
                    );
                    success.push(message.block_number);
                }
                Err(_) => {
                    log::error!(
                        "[{}] Failed to upload block {} to the Destination Ledger",
                        message.idx,
                        message.block_number
                    );
                    error.push(message.block_number);
                }
            }
        }

        log::info!("Writer task ended.");
        log::info!(
            "Successful writes: {}. Erroneous writes: {}",
            success.len(),
            error.len()
        );
        if !error.is_empty() {
            log::warn!("Erroneous block numbers: {:?}", error);
        }
    });

    for (idx, block_number) in (block_number..block_number + limit).enumerate() {
        let idx = idx + 1;

        log::info!(
            "[{}] Reading block {} from the Source Ledger",
            idx,
            block_number
        );

        let block = src
            .get_evm_confirmed_full_block(block_number)
            .await
            .map_err(AppError::GetEvmBlock)?;

        sender
            .send(BlockMessage {
                idx,
                block,
                block_number,
            })
            .map_err(AppError::SendAsyncEVM)?;
    }

    drop(sender);

    log::info!("Reading complete, awaiting tasks to finish...");

    writer.await.map_err(AppError::TokioTaskJoin)
}

pub async fn repeat_native(args: RepeatNativeArgs) -> RoutineResult {
    let RepeatNativeArgs {
        start_slot,
        end_slot,
        src_creds,
        src_instance,
        dst_creds,
        dst_instance,
    } = args;

    let src = ledger::with_params(Some(src_creds), src_instance).await?;

    let dst = ledger::with_params(Some(dst_creds), dst_instance).await?;

    if end_slot < start_slot {
        return Err(AppError::EndSlotLessThanStartSlot);
    }

    let limit = end_slot as usize - start_slot as usize + 1;

    if limit == 1 {
        log::info!("Repeat Native Block {}", start_slot)
    } else {
        log::info!("Repeat Native Blocks from {} to {}", start_slot, end_slot)
    }

    log::info!("Requesting confirmed blocks: start slot = {start_slot}, limit = {limit}");

    let mut blocks_to_repeat: Vec<u64> = src
        .get_confirmed_blocks(start_slot, limit)
        .await
        .map_err(|source| AppError::GetNativeBlocks {
            source,
            start_block: start_slot,
            limit,
        })?
        .into_iter()
        .filter(|slot| *slot <= end_slot)
        .collect();

    log::info!("Response: {} blocks, trimming...", blocks_to_repeat.len());

    blocks_to_repeat.retain(|x| x <= &end_slot);

    log::info!(
        "Blocks to repeat: start slot = {}, end slot = {}, total = {}",
        blocks_to_repeat[0],
        blocks_to_repeat.last().unwrap(),
        blocks_to_repeat.len()
    );

    let (sender, mut receiver) = mpsc::unbounded_channel::<BlockMessage<ConfirmedBlock>>();

    let writer = tokio::spawn(async move {
        log::info!("Writer task started");

        let mut history = History::default();

        while let Some(message) = receiver.recv().await {
            let ConfirmedBlock {
                previous_blockhash,
                blockhash,
                parent_slot,
                transactions,
                rewards,
                block_time,
                block_height,
            } = message.block;

            let transactions = transactions.into_iter().map(|tx| {
                let transaction = tx.get_transaction();
                let meta = tx.get_status_meta();

                let meta = meta.unwrap_or_else(|| {
                    let block_number = message.block_number;
                    let message_hash = transaction.message.hash();

                    log::warn!("Block {block_number} contains transaction with no meta. Message hash = {message_hash}");

                    history.collect_missing_meta(block_number, message_hash);

                    Default::default()
                });
                VersionedTransactionWithStatusMeta {
                    meta,
                    transaction
                }
            }).collect::<Vec<_>>();

            let block = VersionedConfirmedBlock {
                previous_blockhash,
                blockhash,
                parent_slot,
                transactions,
                rewards,
                block_time,
                block_height,
            };

            let uploaded = dst
                .upload_confirmed_block(message.block_number, block)
                .await;

            match uploaded {
                Ok(()) => {
                    log::trace!(
                        "[{}] Block {} uploaded successfully",
                        message.idx,
                        message.block_number
                    );
                    history.collect_ok(message.block_number);
                }
                Err(err) => {
                    log::error!(
                        "[{}] Failed to upload block {} to the Destination Ledger",
                        message.idx,
                        message.block_number
                    );
                    let error_msg = err.to_string();
                    log::trace!("{error_msg}");
                    history.collect_upload_failure(message.block_number, error_msg);
                }
            }
        }

        log::info!("Writer task ended.");

        history
    });

    for (idx, block_number) in blocks_to_repeat.into_iter().enumerate() {
        let idx = idx + 1;

        log::trace!(
            "[{}] Reading block {} from the Source Ledger",
            idx,
            block_number
        );

        let block = src.get_confirmed_block(block_number).await;

        match block {
            Ok(block) => {
                sender
                    .send(BlockMessage {
                        idx,
                        block,
                        block_number,
                    })
                    .map_err(AppError::SendAsyncNative)?;
            }
            Err(err) => {
                log::warn!(
                    "[{}] Unable to read block {} from the Source Ledger",
                    idx,
                    block_number
                );
                log::warn!("{}", err.to_string())
            }
        }
    }

    drop(sender);

    log::info!("Reading complete, awaiting tasks to finish...");

    let history = writer.await.map_err(AppError::TokioTaskJoin)?;

    log::info!("Successful writes total: {}", history.oks.len());

    match history.missing_metas.len() {
        0 => log::info!("All transactions metas were converted successfully"),
        n => log::warn!(
            "{n} transaction(s) meta(s) were unwrapped with default value: {:?}",
            history.missing_metas
        ),
    };

    match history.upload_failures.len() {
        0 => log::info!("All blocks were copied successfully"),
        n => log::warn!(
            "{n} block(s) were not copied: {:?}",
            history.upload_failures
        ),
    };

    Ok(())
}
