use std::time::Duration;

use methods::app_grpc::backend_client::BackendClient;
use rlp::Rlp;
use sha3::Digest;
use sha3::Keccak256;
use triedb::gc::RootGuard;

use self::splice_count_stack::SpliceCountStack;

use super::{
    range::{Advance, MasterRange},
    LittleBig,
};
use evm_state::{storage::account_extractor, BlockNum, Storage, H256};
use log;
use triedb::{
    gc::{DbCounter, ReachableHashes},
    merkle::MerkleNode,
};
mod methods;
mod splice_count_stack;

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
type NodeFullInfo = ((H256, bool), Vec<u8>);
impl<S> Client<S>
where
    S: LittleBig,
{
    async fn fetch_state_roots(
        &self,
        heights: (BlockNum, BlockNum),
    ) -> anyhow::Result<(H256, H256)> {
        let from = self
            .block_storage
            .get_evm_confirmed_state_root(heights.0)
            .await?;
        let to = self
            .block_storage
            .get_evm_confirmed_state_root(heights.1)
            .await?;
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

    pub async fn extend_range_routine(&mut self) {
        assert!(!self.range.get().is_empty());
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

    pub async fn fetch_hashes_data_very_much(
        client: &mut BackendClient<tonic::transport::Channel>,
        input: Vec<(H256, bool)>,
    ) -> anyhow::Result<Vec<((H256, bool), Vec<u8>)>> {
        let input_clone: Vec<_> = input.iter().map(|el| el.0).collect();
        let nodes = Self::get_raw_bytes(client, input_clone).await?;
        if nodes.nodes.len() != input.len() {
            return Err(anyhow::anyhow!(
                "fetch_hashes_data_very_much: len mismatch on input/output {} {}",
                input.len(),
                nodes.nodes.len()
            ));
        }

        for (index, element) in input.iter().enumerate() {
            verify_hash(&nodes.nodes[index], element.0)?;
        }

        let res: Vec<_> = input.into_iter().zip(nodes.nodes).collect();
        Ok(res)
    }

    pub async fn bootstrap_state(&mut self, height: BlockNum) -> anyhow::Result<()> {
        let root_hash = self
            .block_storage
            .get_evm_confirmed_state_root(height)
            .await?;
        let (db_handle, _) = Self::db_handles(&self.storage);

        let mut stack_children: SpliceCountStack<Vec<(H256, bool)>> =
            SpliceCountStack::new("children".to_string());

        let mut stack_fetched: SpliceCountStack<anyhow::Result<Vec<NodeFullInfo>>> =
            SpliceCountStack::new("fetched and verified data".to_string());

        let root_guard = RootGuard::new(&db_handle, root_hash, account_extractor);
        let first_with_data =
            Self::fetch_hashes_data_very_much(&mut self.client, vec![(root_hash, true)]).await;
        let first_with_data = first_with_data?;

        let children_layer = splice_children(&first_with_data)?;
        children_layer.into_iter().for_each(|childs_vec| {
            stack_children.push(childs_vec);
        });
        let mut total: usize = 0;
        for ((hash, _direct), value) in first_with_data {
            db_handle.gc_insert_node(hash, &value, account_extractor);
            total += 1;
        }
        loop {
            let fetched = stack_fetched.pop();
            match fetched {
                Some(fetched) => {
                    let fetched = fetched?;
                    let children_layer = splice_children(&fetched)?;
                    children_layer.into_iter().for_each(|childs_vec| {
                        stack_children.push(childs_vec);
                    });
                    for ((hash, _direct), value) in fetched {
                        db_handle.gc_insert_node(hash, &value, account_extractor);
                        total += 1;
                    }
                }
                None => {
                    let next_child_slice = stack_children.pop();
                    match next_child_slice {
                        Some(next_child_slice) => {
                            let first_with_data = Self::fetch_hashes_data_very_much(
                                &mut self.client,
                                next_child_slice,
                            )
                            .await;
                            stack_fetched.push(first_with_data);
                        }
                        None => {
                            break;
                        }
                    }
                }
            }
        }

        let to = root_guard.leak_root();
        log::debug!("persisted root {} {}", to, total);
        db_handle.gc_pin_root(to);
        log::debug!("persisted root count after leak {}", db_handle.gc_count(to));
        self.range.update(height).expect("persist range update");

        Ok(())
    }
}

fn verify_hash(value: &[u8], hash: H256) -> anyhow::Result<()> {
    let actual_hash = H256::from_slice(Keccak256::digest(value).as_slice());
    if hash != actual_hash {
        return Err(anyhow::anyhow!(
            "hash mismatch {:?} {:?}",
            hash,
            actual_hash
        ))?;
    }
    Ok(())
}

pub fn no_childs(_: &[u8]) -> Vec<H256> {
    vec![]
}
const MAX_CHUNK_HASHES: usize = 100_000;
const SPLIT_FACTOR: usize = 20;

fn splice_children(layer: &Vec<((H256, bool), Vec<u8>)>) -> anyhow::Result<Vec<Vec<(H256, bool)>>> {
    let mut childs_all = vec![];
    for element in layer {
        let res = map_node_to_next_layer(element)?;
        childs_all.extend(res.into_iter());
    }
    let res: Vec<_> = if childs_all.len() > MAX_CHUNK_HASHES {
        let len = childs_all.len();
        childs_all
            .rchunks(len / SPLIT_FACTOR)
            .map(|el| el.to_vec())
            .filter(|el| !el.is_empty())
            .collect()
    } else if childs_all.is_empty() {
        vec![]
    } else {
        vec![childs_all]
    };
    Ok(res)
}

fn map_node_to_next_layer(parent: &((H256, bool), Vec<u8>)) -> anyhow::Result<Vec<(H256, bool)>> {
    let ((_hash, direct), node) = parent;
    let node = MerkleNode::decode(&Rlp::new(node))?;

    let (direct_childs, indirect_childs) = if *direct {
        ReachableHashes::collect(&node, account_extractor).childs()
    } else {
        // prevent more than one layer of indirection
        let childs = ReachableHashes::collect(&node, no_childs).childs();
        assert!(
            childs.1.is_empty(),
            "There should be no subtrie with 'no_childs' extractor"
        );
        // All direct childs for indirect childs should be handled as indirect.
        (vec![], childs.0)
    };

    let paths: Vec<_> = direct_childs
        .into_iter()
        .map(|k| (k, true))
        .chain(indirect_childs.into_iter().map(|k| (k, false)))
        .collect();
    Ok(paths)
}
