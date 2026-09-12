use {
    crate::blockstore::Blockstore,
    crossbeam_channel::{bounded, unbounded},
    log::*,
    solana_measure::measure::Measure,
    solana_sdk::clock::Slot,
    std::{
        cmp::{max, min},
        collections::HashSet,
        result::Result,
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        },
        time::{Duration, Instant},
    },
};

#[derive(Clone)]
pub struct ConfirmedBlockUploadConfig {
    pub force_reupload: bool,
    pub max_num_slots_to_check: usize,
    pub num_blocks_to_upload_in_parallel: usize,
    pub block_read_ahead_depth: usize, // should always be >= `num_blocks_to_upload_in_parallel`
}

impl Default for ConfirmedBlockUploadConfig {
    fn default() -> Self {
        let num_blocks_to_upload_in_parallel = num_cpus::get() / 2;
        ConfirmedBlockUploadConfig {
            force_reupload: false,
            max_num_slots_to_check: num_blocks_to_upload_in_parallel * 4,
            num_blocks_to_upload_in_parallel,
            block_read_ahead_depth: num_blocks_to_upload_in_parallel * 2,
        }
    }
}

struct BlockstoreLoadStats {
    pub num_blocks_read: usize,
    pub elapsed: Duration,
}

pub async fn upload_confirmed_blocks(
    blockstore: Arc<Blockstore>,
    bigtable: solana_storage_bigtable::LedgerStorage,
    starting_slot: Slot,
    ending_slot: Slot,
    config: ConfirmedBlockUploadConfig,
    exit: Arc<AtomicBool>,
) -> Result<Slot, Box<dyn std::error::Error>> {
    let mut measure = Measure::start("entire upload");

    info!("Loading ledger slots starting at {}...", starting_slot);
    let blockstore_slots: Vec<_> = blockstore
        .rooted_slot_iterator(starting_slot)
        .map_err(|err| {
            format!(
                "Failed to load entries starting from slot {}: {:?}",
                starting_slot, err
            )
        })?
        .map_while(|slot| (slot <= ending_slot).then(|| slot))
        .collect();

    if blockstore_slots.is_empty() {
        return Err(format!(
            "Ledger has no slots from {} to {:?}",
            starting_slot, ending_slot
        )
        .into());
    }

    let first_blockstore_slot = blockstore_slots.first().unwrap();
    let last_blockstore_slot = blockstore_slots.last().unwrap();
    info!(
        "Found {} slots in the range ({}, {})",
        blockstore_slots.len(),
        first_blockstore_slot,
        last_blockstore_slot,
    );

    // Gather the blocks that are already present in bigtable, by slot
    let bigtable_slots = if !config.force_reupload {
        let mut bigtable_slots = vec![];
        info!(
            "Loading list of bigtable blocks between slots {} and {}...",
            first_blockstore_slot, last_blockstore_slot
        );

        let mut start_slot = *first_blockstore_slot;
        while start_slot <= *last_blockstore_slot {
            let mut next_bigtable_slots = loop {
                let num_bigtable_blocks = min(1000, config.max_num_slots_to_check * 2);
                match bigtable
                    .get_confirmed_blocks(start_slot, num_bigtable_blocks)
                    .await
                {
                    Ok(slots) => break slots,
                    Err(err) => {
                        error!("get_confirmed_blocks for {} failed: {:?}", start_slot, err);
                        // Consider exponential backoff...
                        tokio::time::sleep(Duration::from_secs(2)).await;
                    }
                }
            };
            if next_bigtable_slots.is_empty() {
                break;
            }
            bigtable_slots.append(&mut next_bigtable_slots);
            start_slot = bigtable_slots.last().unwrap() + 1;
        }
        bigtable_slots
            .into_iter()
            .filter(|slot| slot <= last_blockstore_slot)
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };

    // The blocks that still need to be uploaded is the difference between what's already in the
    // bigtable and what's in blockstore...
    let blocks_to_upload = {
        let blockstore_slots = blockstore_slots.iter().cloned().collect::<HashSet<_>>();
        let bigtable_slots = bigtable_slots.into_iter().collect::<HashSet<_>>();

        let mut blocks_to_upload = blockstore_slots
            .difference(&bigtable_slots)
            .cloned()
            .collect::<Vec<_>>();
        blocks_to_upload.sort_unstable();
        blocks_to_upload.truncate(config.max_num_slots_to_check);
        blocks_to_upload
    };

    if blocks_to_upload.is_empty() {
        info!("No blocks need to be uploaded to bigtable");
        return Ok(*last_blockstore_slot);
    }
    let last_slot = *blocks_to_upload.last().unwrap();
    info!(
        "{} blocks to be uploaded to the bucket in the range ({}, {})",
        blocks_to_upload.len(),
        blocks_to_upload.first().unwrap(),
        last_slot
    );

    // Distribute the blockstore reading across a few background threads to speed up the bigtable uploading
    let (loader_threads, receiver): (Vec<_>, _) = {
        let exit = exit.clone();

        let (sender, receiver) = bounded(config.block_read_ahead_depth);

        let (slot_sender, slot_receiver) = unbounded();
        let _ = blocks_to_upload
            .into_iter()
            .for_each(|b| slot_sender.send(b).unwrap());
        drop(slot_sender);

        (
            (0..config.num_blocks_to_upload_in_parallel)
                .map(|_| {
                    let blockstore = blockstore.clone();
                    let sender = sender.clone();
                    let slot_receiver = slot_receiver.clone();
                    let exit = exit.clone();

                    std::thread::spawn(move || {
                        let start = Instant::now();
                        let mut num_blocks_read = 0;

                        while let Ok(slot) = slot_receiver.recv() {
                            if exit.load(Ordering::Relaxed) {
                                break;
                            }

                            let _ = match blockstore.get_rooted_block(slot, true) {
                                Ok(confirmed_block) => {
                                    num_blocks_read += 1;
                                    sender.send((slot, Some(confirmed_block)))
                                }
                                Err(err) => {
                                    warn!(
                                        "Failed to get load confirmed block from slot {}: {:?}",
                                        slot, err
                                    );
                                    sender.send((slot, None))
                                }
                            };
                        }
                        BlockstoreLoadStats {
                            num_blocks_read,
                            elapsed: start.elapsed(),
                        }
                    })
                })
                .collect(),
            receiver,
        )
    };

    let mut failures = 0;
    use futures::stream::StreamExt;

    let mut stream =
        tokio_stream::iter(receiver.into_iter()).chunks(config.num_blocks_to_upload_in_parallel);

    while let Some(blocks) = stream.next().await {
        if exit.load(Ordering::Relaxed) {
            break;
        }

        let mut measure_upload = Measure::start("Upload");
        let mut num_blocks = blocks.len();
        info!("Preparing the next {} blocks for upload", num_blocks);

        let uploads = blocks.into_iter().filter_map(|(slot, block)| match block {
            None => {
                num_blocks -= 1;
                None
            }
            Some(confirmed_block) => {
                let bt = bigtable.clone();
                Some(tokio::spawn(async move {
                    bt.upload_confirmed_block(slot, confirmed_block).await
                }))
            }
        });

        for result in futures::future::join_all(uploads).await {
            if let Err(err) = result {
                error!("upload_confirmed_block() join failed: {:?}", err);
                failures += 1;
            } else if let Err(err) = result.unwrap() {
                error!("upload_confirmed_block() upload failed: {:?}", err);
                failures += 1;
            }
        }

        measure_upload.stop();
        info!("{} for {} blocks", measure_upload, num_blocks);
    }

    measure.stop();
    info!("{}", measure);

    let blockstore_results = loader_threads.into_iter().map(|t| t.join());

    let mut blockstore_num_blocks_read = 0;
    let mut blockstore_load_wallclock = Duration::default();
    let mut blockstore_errors = 0;

    for r in blockstore_results {
        match r {
            Ok(stats) => {
                blockstore_num_blocks_read += stats.num_blocks_read;
                blockstore_load_wallclock = max(stats.elapsed, blockstore_load_wallclock);
            }
            Err(e) => {
                error!("error joining blockstore thread: {:?}", e);
                blockstore_errors += 1;
            }
        }
    }

    info!(
        "blockstore upload took {:?} for {} blocks ({:.2} blocks/s) errors: {}",
        blockstore_load_wallclock,
        blockstore_num_blocks_read,
        blockstore_num_blocks_read as f64 / blockstore_load_wallclock.as_secs_f64(),
        blockstore_errors
    );

    if failures > 0 {
        Err(format!("Incomplete upload, {} operations failed", failures).into())
    } else {
        Ok(last_slot)
    }
}

const NUM_BLOCKS_TO_UPLOAD_IN_PARALLEL: usize = 8;

pub async fn upload_evm_confirmed_blocks(
    blockstore: Arc<Blockstore>,
    bigtable: solana_storage_bigtable::LedgerStorage,
    starting_block: evm_state::BlockNum,
    ending_block: Option<evm_state::BlockNum>,
    push_not_confirmed: bool,
    force_reupload: bool,
    exit: Arc<AtomicBool>,
) -> Result<evm_state::BlockNum, Box<dyn std::error::Error>> {
    let mut measure = Measure::start("entire upload");

    info!(
        "Loading evm ledger blocks starting at {}...",
        starting_block
    );
    let mut block_headers: Vec<_> = blockstore
        .evm_blocks_iterator(starting_block)
        .map_err(|err| {
            format!(
                "Failed to load entries starting from slot {}: {:?}",
                starting_block, err
            )
        })?
        .filter_map(|((block_num, _slot), _block)| {
            if let Some(ending_block) = &ending_block {
                if block_num > *ending_block {
                    return None;
                }
            }
            Some(block_num)
        })
        .collect();

    // evm_blocks_iterator can return multiple blocks with same block_num, remove duplicates.
    block_headers.dedup();

    if block_headers.is_empty() {
        return Err(format!(
            "Ledger has no blocks from {} to {:?}",
            starting_block, ending_block
        )
        .into());
    }

    info!(
        "Found {} slots in the range ({}, {})",
        block_headers.len(),
        block_headers.first().unwrap(),
        block_headers.last().unwrap()
    );

    // Gather the blocks that are already present in bigtable, by slot
    let bigtable_slots = if !force_reupload {
        let mut bigtable_blocks = vec![];
        let first_blockstore_block = *block_headers.first().unwrap();
        let last_blockstore_block = *block_headers.last().unwrap();
        info!(
            "Loading list of bigtable evm blocks between blocks {} and {}...",
            first_blockstore_block, last_blockstore_block
        );

        let mut start_block = *block_headers.first().unwrap();
        while start_block <= last_blockstore_block {
            let mut next_bigtable_blocks = loop {
                match bigtable.get_evm_confirmed_blocks(start_block, 1000).await {
                    Ok(slots) => break slots,
                    Err(err) => {
                        error!(
                            "get_evm_confirmed_blocks for {} failed: {:?}",
                            start_block, err
                        );
                        // Consider exponential backoff...
                        tokio::time::sleep(Duration::from_secs(2)).await;
                    }
                }
            };
            if next_bigtable_blocks.is_empty() {
                break;
            }
            bigtable_blocks.append(&mut next_bigtable_blocks);
            start_block = bigtable_blocks.last().unwrap() + 1;
        }
        bigtable_blocks
            .into_iter()
            .filter(|slot| *slot <= last_blockstore_block)
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };

    // The blocks that still need to be uploaded is the difference between what's already in the
    // bigtable and what's in blockstore...
    let blocks_to_upload = {
        let block_headers = block_headers.iter().cloned().collect::<HashSet<_>>();
        let bigtable_slots = bigtable_slots.into_iter().collect::<HashSet<_>>();

        let mut blocks_to_upload = block_headers
            .difference(&bigtable_slots)
            .cloned()
            .collect::<Vec<_>>();
        blocks_to_upload.sort_unstable();
        blocks_to_upload
    };

    if blocks_to_upload.is_empty() {
        info!("No blocks need to be uploaded to bigtable");
        return Ok(0);
    }
    info!(
        "{} blocks to be uploaded to the bucket in the range ({}, {})",
        blocks_to_upload.len(),
        blocks_to_upload.first().unwrap(),
        blocks_to_upload.last().unwrap()
    );

    // Load the blocks out of blockstore in a separate thread to allow for concurrent block uploading
    let (_loader_thread, receiver) = {
        let exit = exit.clone();

        let (sender, receiver) = std::sync::mpsc::sync_channel(NUM_BLOCKS_TO_UPLOAD_IN_PARALLEL);
        (
            std::thread::spawn(move || {
                let mut measure = Measure::start("block loader thread");
                for (i, block_num) in blocks_to_upload.iter().enumerate() {
                    if exit.load(Ordering::Relaxed) {
                        break;
                    }

                    let _ = match blockstore.get_evm_block(*block_num) {
                        Ok(confirmed_block) => sender.send((*block_num, Some(confirmed_block))),
                        Err(err) => {
                            warn!(
                                "Failed to get load evm confirmed block from slot {}: {:?}",
                                block_num, err
                            );
                            sender.send((*block_num, None))
                        }
                    };

                    if i > 0 && i % NUM_BLOCKS_TO_UPLOAD_IN_PARALLEL == 0 {
                        info!(
                            "{}% of blocks processed ({}/{})",
                            i * 100 / blocks_to_upload.len(),
                            i,
                            blocks_to_upload.len()
                        );
                    }
                }
                measure.stop();
                info!("{} to load {} blocks", measure, blocks_to_upload.len());
            }),
            receiver,
        )
    };

    let mut failures = 0;
    let mut not_confirmed_blocks = 0;
    use futures::stream::StreamExt;

    let mut stream =
        tokio_stream::iter(receiver.into_iter()).chunks(NUM_BLOCKS_TO_UPLOAD_IN_PARALLEL);

    while let Some(blocks) = stream.next().await {
        if exit.load(Ordering::Relaxed) {
            break;
        }

        let mut measure_upload = Measure::start("Upload");
        let mut num_blocks = blocks.len();
        info!("Preparing the next {} blocks for upload", num_blocks);

        let uploads = blocks
            .into_iter()
            .filter_map(|(block_num, confirmed_block)| match confirmed_block {
                None => {
                    num_blocks -= 1;
                    None
                }
                Some((confirmed_block, true)) => {
                    Some(bigtable.upload_evm_block(block_num, confirmed_block))
                }
                Some((confirmed_block, false)) => {
                    debug!(
                        "Foind evm block = {:?}, that is still not confirmed, push_not_confirmed={}.",
                        block_num, push_not_confirmed
                    );
                    if push_not_confirmed {
                        Some(bigtable.upload_evm_block(block_num, confirmed_block))
                    } else {
                        not_confirmed_blocks += 1;
                        None
                    }
                }
            });

        for result in futures::future::join_all(uploads).await {
            if result.is_err() {
                error!("upload_confirmed_block() failed: {:?}", result.err());
                failures += 1;
            }
        }

        measure_upload.stop();
        info!("{} for {} blocks", measure_upload, num_blocks);
    }

    measure.stop();
    info!("{}", measure);
    if failures > 0 {
        Err(format!("Incomplete upload, {} operations failed", failures).into())
    } else {
        Ok(not_confirmed_blocks)
    }
}
