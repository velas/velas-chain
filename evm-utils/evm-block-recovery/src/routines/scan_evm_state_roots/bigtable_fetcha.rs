use {
    crate::error::AppError,
    backon::{ExponentialBuilder, Retryable},
    evm_state::{Block, BlockNum},
    solana_storage_bigtable::LedgerStorage,
    std::sync::{Arc, Mutex},
    tokio::sync::mpsc,
};

pub async fn fetch_one(
    bigtable: &LedgerStorage,
    height: BlockNum,
) -> Result<Option<Block>, solana_storage_bigtable::Error> {
    let block_res = bigtable.get_evm_confirmed_full_block(height).await;

    match block_res {
        Err(solana_storage_bigtable::Error::BlockNotFound(_slot)) => {
            // assert_eq!(slot, height);
            Ok(None)
        }
        Err(e) => Err(e),
        Ok(block) => Ok(Some(block)),
    }
}

const MIN_DELAY_NANOS: u32 = 1_000_000; // 1 millisecond
const MAX_TIMES: usize = 22; // 1 millisecond

pub async fn fetch_one_retry_backoff(
    bigtable: &LedgerStorage,
    height: BlockNum,
) -> Result<Option<Block>, solana_storage_bigtable::Error> {
    let count = Arc::new(Mutex::new(0));
    let fetch_cl = || {
        {
            let mut lock = count.lock().expect("locked poisoned");
            *lock += 1;
        }
        async {
            log::trace!(
                "attempting try fo fetch block_num ({:?}) {}",
                count.clone(),
                height
            );
            fetch_one(bigtable, height).await
        }
    };

    fetch_cl
        .retry(
            &ExponentialBuilder::default()
                .with_min_delay(std::time::Duration::new(0, MIN_DELAY_NANOS))
                .with_max_times(MAX_TIMES),
        )
        .await
}

struct ChunkedRange {
    range: std::ops::Range<BlockNum>,
    chunk_size: BlockNum,
}

impl Iterator for ChunkedRange {
    type Item = std::ops::Range<BlockNum>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.range.is_empty() {
            return None;
        }

        let start = self.range.start;
        let next = std::cmp::min(self.range.start + self.chunk_size, self.range.end);

        self.range.start = next;
        Some(start..next)
    }
}

#[derive(Debug)]
pub struct BigtableEVMBlockFetcher {
    workers: usize,
    pub receiver: Option<tokio::sync::mpsc::Receiver<(BlockNum, Option<Block>)>>,
}

impl BigtableEVMBlockFetcher {
    pub fn new(workers: usize) -> Self {
        Self {
            workers,
            receiver: None,
        }
    }
}

const CHANNEL_CAPACITY: usize = 10000;

async fn worker_task(
    bigtable: solana_storage_bigtable::LedgerStorage,
    subrange: std::ops::Range<BlockNum>,
    tx: mpsc::Sender<(BlockNum, Option<Block>)>,
) {
    log::info!("spawned chunk {:?}", subrange);
    for height in subrange.clone() {
        let fetch_result = fetch_one_retry_backoff(&bigtable, height).await;

        let block = match fetch_result {
            Err(e) => {
                panic!(
                    "failing on retries to get evm_confirmed full block for {}: {:?}",
                    height, e
                );
            }
            Ok(block) => block,
        };
        let send_result = tx.send((height, block)).await;
        if let Err(err) = send_result {
            log::error!("send failed {:?}, exiting range {:?}", err, subrange);
            break;
        }
    }
    log::info!("finished chunk {:?}", subrange);
}

impl BigtableEVMBlockFetcher {
    pub async fn schedule_range(
        &mut self,
        bigtable: &solana_storage_bigtable::LedgerStorage,
        handle: &tokio::runtime::Handle,
        range: std::ops::Range<BlockNum>,
    ) -> Result<(), AppError> {
        if range.is_empty() {
            return Ok(());
        }
        let chunk_size = (range.end - range.start) / (self.workers as BlockNum);

        let (tx, rx) = mpsc::channel(CHANNEL_CAPACITY);
        self.receiver = Some(rx);
        let chunked = ChunkedRange { range, chunk_size };
        for subrange in chunked {
            let tx_double = tx.clone();
            let _worker_jh = handle.spawn(worker_task(bigtable.clone(), subrange, tx_double));
        }
        Ok(())
    }

    pub async fn get_block(&mut self) -> Option<(BlockNum, Option<Block>)> {
        if let Some(ref mut receiver) = self.receiver {
            receiver.recv().await
        } else {
            None
        }
    }
}
