use std::time::Duration;

use methods::app_grpc::backend_client::BackendClient;

use super::{range::{Advance, MasterRange}, LittleBig};
use evm_state::{BlockNum, Storage, H256};
use log;
use triedb::gc::DbCounter;
mod methods;

type RocksHandleA<'a> = triedb::rocksdb::RocksHandle<'a, &'a triedb::rocksdb::DB>;

pub struct Client<S> {
    state_rpc_address: String,
    storage: Storage,
    client: BackendClient<tonic::transport::Channel>,
    range: MasterRange,
    block_storage: S,
}

impl From<methods::app_grpc::GetBlockRangeReply> for std::ops::Range<BlockNum> {
    fn from(value: methods::app_grpc::GetBlockRangeReply) -> Self {
        value.start..value.end
    }
}

const MAX_CHUNK: u64 = 10;
impl<S> Client<S> {
    pub async fn connect(
        state_rpc_address: String,
        range: MasterRange,
        storage: Storage,
        block_storage: S,
    ) -> Result<Self, tonic::transport::Error> {
        log::info!("starting the client routine {}", state_rpc_address);
        let client = BackendClient::connect(state_rpc_address.clone()).await?;
        Ok(Self {
            client,
            range,
            state_rpc_address,
            storage,
            block_storage,
        })
    }

    fn compute_advance(&self, server_offer: std::ops::Range<BlockNum>) -> Advance {
        self.range.compute_advance(MAX_CHUNK, server_offer)
    }

    pub fn db_handles(
        storage: &Storage,
    ) -> (
        RocksHandleA<'_>,
        triedb::gc::TrieCollection<RocksHandleA<'_>>,
    ) {
        (
            storage.rocksdb_trie_handle(),
            triedb::gc::TrieCollection::new(storage.rocksdb_trie_handle()),
        )
    }

    
}

impl<S> Client<S> where S:LittleBig {
    async fn fetch_state_roots(
        &self,
        heights: (BlockNum, BlockNum),
    ) -> anyhow::Result<(H256, H256)> {
        let from = self.block_storage.get_evm_confirmed_state_root(heights.0).await?;
        let to = self.block_storage.get_evm_confirmed_state_root(heights.1).await?;
        Ok((from, to))
    }


    async fn iterate_range(&mut self, mut advance: Advance) -> anyhow::Result<()> {
        let (db_handle, collection) = Self::db_handles(&self.storage);
        let mut start = advance.start;
        log::warn!("attempting to advance {:?}", advance);

        while let Some(next) = advance.next_biderectional() {
            log::warn!("next height {}", next);
            let heights = (start, next);
            let hashes = self.fetch_state_roots(heights).await?;
            let diff_response = Self::download_and_apply_diff(
                &mut self.client,
                &db_handle,
                &collection,
                heights,
                hashes,
            )
            .await;
            match diff_response {
                Err(e) => {
                    return Err(anyhow::anyhow!(
                        "heights advance error: {:?}, {:?}, {:?}",
                        heights,
                        hashes,
                        e
                    ));
                }
                Ok(guard) => {
                    let to = hashes.1;
                    log::debug!("persisted root {}", guard.leak_root());
                    db_handle.gc_pin_root(to);
                    log::debug!("persisted root count after leak {}", db_handle.gc_count(to));
                    self.range.update(next).expect("persist range update");
                }
            }
            start = next;
        }
        Ok(())
    }

    async fn main_loop_iteration(&mut self) -> Result<Advance, (anyhow::Error, Duration)> {
        let block_range = self.get_block_range().await;
        if let Err(e) = block_range {
            return Err((
                anyhow::anyhow!(
                    "get block range from server {:?}: {:?}",
                    self.state_rpc_address,
                    e
                ),
                Duration::new(1, 0),
            ));
        }
        let block_range: std::ops::Range<BlockNum> = block_range.unwrap().into();

        let advance = self.compute_advance(block_range.clone());
        if advance.is_empty() {
            return Err((
                anyhow::anyhow!(
                    "no useful advance can be made on {:?};  our : {:?} ; offer: {:?}",
                    self.state_rpc_address,
                    self.range.get(),
                    block_range,
                ),
                Duration::new(3, 0),
            ));
        }
        let result = self.iterate_range(advance.clone()).await;
        if let Err(e) = result {
            Err((
                anyhow::anyhow!("during iteration over advance.added_range {:?}", e),
                Duration::new(5, 0),
            ))
        } else {
            Ok(advance)
        }
    }

    pub async fn server_routine(&mut self) {
        loop {
            match self.main_loop_iteration().await {
                Err((err, dur)) => {
                    log::error!("main loop {:?}", err);
                    tokio::time::sleep(dur).await;
                }
                Ok(advance) => {
                    log::warn!("success on advance {:?}", advance);
                }
            }
        }
    }
}
