use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
use evm_state::{empty_trie_hash, Block, BlockNum, H256};
use solana_storage_bigtable::LedgerStorage;
use tokio::{sync::mpsc, task::JoinHandle};

use backon::{ExponentialBuilder, Retryable};
use std::default::Default;

#[derive(Clone)]
pub struct CachedHeightIndexSpunOff {
    cache: Arc<Mutex<HashMap<BlockNum, Option<H256>>>>,
    sender: tokio::sync::mpsc::Sender<BlockNum>,
}

pub struct CachedHeightIndexBackgroundMan {
    storage: LedgerStorage,
    cache: Arc<Mutex<HashMap<BlockNum, Option<H256>>>>,
    receiver: tokio::sync::mpsc::Receiver<BlockNum>,
}

const WAIT_NANOS: u32 = 3_000_000; // 3 milliseconds

pub async fn fetch_one(
    bigtable: &LedgerStorage,
    height: BlockNum,
) -> Result<Option<Block>, solana_storage_bigtable::Error> {
    let block_res = bigtable.get_evm_confirmed_full_block(height).await;

    match block_res {
        Err(solana_storage_bigtable::Error::BlockNotFound(slot)) => {
            assert_eq!(slot, height);
            Ok(None)
        }
        Err(e) => Err(e),
        Ok(block) => Ok(Some(block)),
    }
}

const MIN_DELAY_NANOS: u32 = 1_000_000; // 1 millisecond
const MAX_TIMES: usize = 22; // 1 millisecond

impl CachedHeightIndexBackgroundMan {
    async fn spin_off(mut self, runtime: &tokio::runtime::Handle) -> JoinHandle<()> {
        runtime.spawn(async move {
            loop {
                let block_num = self.receiver.recv().await;
                if block_num.is_none() {
                    return;
                }
                let block_num = block_num.unwrap();
                let result = if block_num == 0 {
                    Some(empty_trie_hash())
                } else {
                    let count = Arc::new(Mutex::new(0));
                    let fetch_cl = || {
                        {
                            let mut lock = count.lock().expect("locked poisoned");
                            *lock +=1;
                            
                        }
                        async {
                            log::debug!(
                                "attempting try fo fetch block_num ({:?}) {}",
                                count.clone(),
                                block_num
                            );
                            fetch_one(&self.storage, block_num).await
                        }
                    };

                    let block = fetch_cl
                        .retry(
                            &ExponentialBuilder::default()
                                .with_min_delay(std::time::Duration::new(0, MIN_DELAY_NANOS))
                                .with_max_times(MAX_TIMES),
                        )
                        .await;

                    let block = match block {
                        Err(e) => {
                            self.receiver.close();
                            panic!(
                                "failing on retries to get evm_confirmed full block for {}: {:?}",
                                block_num, e
                            );
                        }
                        Ok(block) => block,
                    };

                    block.map(|block| block.header.state_root)
                };

                {
                    let mut cache = self.cache.lock().expect("lock poisoned");
                    cache.insert(block_num, result);
                }
            }
        })
    }
}

impl CachedHeightIndexSpunOff {
    pub async fn new(
        runtime: &tokio::runtime::Handle,
    ) -> Result<(Self, JoinHandle<()>), solana_storage_bigtable::Error> {
        let bigtable = solana_storage_bigtable::LedgerStorage::new(
            false,
            Some(std::time::Duration::new(5, 0)),
            None,
        )
        .await?;

        let cache = Arc::new(Mutex::new(HashMap::new()));
        let (tx, rx) = mpsc::channel(500);

        let bg_man = CachedHeightIndexBackgroundMan {
            storage: bigtable,
            cache: cache.clone(),
            receiver: rx,
        };
        let jh = bg_man.spin_off(runtime).await;
        Ok((Self { cache, sender: tx }, jh))
    }
}

#[async_trait]
impl super::EvmHeightIndex for CachedHeightIndexSpunOff {
    async fn get_evm_confirmed_state_root(&self, block_num: BlockNum) -> Option<H256> {
        loop {
            {
                {
                    let cache = self.cache.lock().expect("lock poisoned");
                    if let Some(result) = cache.get(&block_num) {
                        return *result;
                    }
                }
                log::trace!("no result on get ready {}, sleeping...", block_num);
                tokio::time::sleep(std::time::Duration::new(0, WAIT_NANOS)).await;
            }
        }
    }
    async fn schedule_height(
        &self,
        height: BlockNum,
    ) -> Result<(), tokio::sync::mpsc::error::SendError<BlockNum>> {
        self.sender.send(height).await?;
        Ok(())
    }
}
