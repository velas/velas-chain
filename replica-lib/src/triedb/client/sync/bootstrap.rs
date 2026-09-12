use evm_state::{storage::account_extractor, BlockNum, H256};
use triedb::gc::DbCounter;
use triedb::gc::RootGuard;

use crate::triedb::client::proto::app_grpc::backend_client::BackendClient;
use crate::triedb::client::Client;
use crate::triedb::error::client;
use crate::triedb::error::client::bootstrap::fetch_nodes;
use crate::triedb::ReadRange;
use crate::triedb::WriteRange;
use crate::triedb::{collection, error::client::bootstrap, EvmHeightIndex};

use self::splice_count_stack::SpliceCountStack;

mod helpers;
mod splice_count_stack;

type NodeFullInfo = ((H256, bool), Vec<u8>);

impl<S> Client<S>
where
    S: EvmHeightIndex + Sync,
{
    pub async fn fetch_nodes_of_hashes(
        client: &mut BackendClient<tonic::transport::Channel>,
        rpc_address: &String,
        input: Vec<(H256, bool)>,
    ) -> Result<Vec<((H256, bool), Vec<u8>)>, fetch_nodes::Error> {
        let response = {
            let input = input.iter().map(|el| el.0).collect();
            Self::get_array_of_nodes_retried(client, rpc_address, input).await
        };

        let nodes = match response {
            Ok(Ok(result)) => result,
            Ok(Err(fast)) => {
                let err = fetch_nodes::get::Error::Fast(fast);
                let err = fetch_nodes::Error::Get(input.len(), err);
                Err(err)
            }?,
            Err(slow) => {
                let err = fetch_nodes::get::Error::Slow(slow);
                let err = fetch_nodes::Error::Get(input.len(), err);
                Err(err)
            }?,
        };

        if nodes.nodes.len() != input.len() {
            return Err(client::proto::Error::NodesLenMismatch(
                input.len(),
                nodes.nodes.len(),
            ))?;
        }

        for (index, element) in input.iter().enumerate() {
            helpers::verify_hash(&nodes.nodes[index], element.0)?;
        }

        let res: Vec<_> = input.into_iter().zip(nodes.nodes).collect();
        Ok(res)
    }

    pub async fn bootstrap_state(&mut self, height: BlockNum) -> Result<(), bootstrap::Error> {
        if self.range.get().await.expect("get range").contains(&height) {
            log::warn!("skipping height {} as already present", height);
            return Ok(());
        }

        let root_hash = self
            .block_storage
            .get_evm_confirmed_state_root_retried(height)
            .await?;
        log::info!(
            "starting bootstrap at height {}, hash {:?}",
            height,
            root_hash
        );

        match self.check_height(root_hash, height).await {
            Ok(..) => {}
            Err(err) => match err {
                mismatch @ client::check_height::Error::HashMismatch { .. } => {
                    panic!("different chains {:?}", mismatch);
                }
                other => {
                    return Err(other)?;
                }
            },
        };
        let collection = collection(&self.storage);

        let mut stack_children: SpliceCountStack<Vec<(H256, bool)>> =
            SpliceCountStack::new("children".to_string());

        let mut stack_fetched: SpliceCountStack<Result<Vec<NodeFullInfo>, fetch_nodes::Error>> =
            SpliceCountStack::new("fetched and verified data".to_string());

        let root_guard = RootGuard::new(&collection.database, root_hash, account_extractor);
        let first_with_data = Self::fetch_nodes_of_hashes(
            &mut self.client,
            &self.state_rpc_address,
            vec![(root_hash, true)],
        )
        .await;
        let first_with_data = first_with_data?;

        let children_layer = helpers::compute_and_maybe_split_children(&first_with_data)?;
        children_layer.into_iter().for_each(|childs_vec| {
            stack_children.push(childs_vec);
        });
        let mut total: usize = 0;
        for ((hash, _direct), value) in first_with_data {
            collection
                .database
                .gc_insert_node(hash, &value, account_extractor);
            total += 1;
        }
        loop {
            let fetched = stack_fetched.pop();
            match fetched {
                Some(fetched) => {
                    let fetched = fetched?;
                    let children_layer = helpers::compute_and_maybe_split_children(&fetched)?;
                    children_layer.into_iter().for_each(|childs_vec| {
                        stack_children.push(childs_vec);
                    });
                    for ((hash, _direct), value) in fetched {
                        collection
                            .database
                            .gc_insert_node(hash, &value, account_extractor);
                        total += 1;
                        if total % 200_000 == 0 {
                            log::info!("bootstrapping ... {}", total);
                        }
                    }
                }
                None => {
                    let next_child_slice = stack_children.pop();
                    match next_child_slice {
                        Some(next_child_slice) => {
                            let first_with_data = Self::fetch_nodes_of_hashes(
                                &mut self.client,
                                &self.state_rpc_address,
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
        collection.database.gc_pin_root(to);
        log::debug!(
            "persisted root count after leak {}",
            collection.database.gc_count(to)
        );
        self.range.update(height).expect("persist range update");
        self.range.flush().expect("persist range update");

        Ok(())
    }
}
