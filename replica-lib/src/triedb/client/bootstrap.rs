use evm_state::{H256, BlockNum, storage::account_extractor};
use triedb::gc::RootGuard;
use triedb::gc::DbCounter;

use crate::triedb::{error::{ClientError, BootstrapError, source_matches_type}, collection, EvmHeightIndex};

use self::splice_count_stack::SpliceCountStack;

use super::{Client, proto::app_grpc::backend_client::BackendClient};

mod splice_count_stack;
mod helpers;


type NodeFullInfo = ((H256, bool), Vec<u8>);



impl<S> Client<S> 
where
    S: EvmHeightIndex,
{

    pub async fn fetch_nodes_of_hashes(
        client: &mut BackendClient<tonic::transport::Channel>,
        input: Vec<(H256, bool)>,
    ) -> Result<Vec<((H256, bool), Vec<u8>)>, ClientError> {
        let input_clone: Vec<_> = input.iter().map(|el| el.0).collect();
        let nodes = Self::get_array_of_nodes(client, input_clone).await;
        if let Err(ref err) = nodes {
            let _match = source_matches_type::<tonic::transport::Error>(err);
        }

        let nodes = nodes?;
        if nodes.nodes.len() != input.len() {
            return Err(ClientError::GetArrayOfNodesReplyLenMismatch(
                input.len(),
                nodes.nodes.len(),
            ));
        }

        for (index, element) in input.iter().enumerate() {
            helpers::verify_hash(&nodes.nodes[index], element.0)?;
        }

        let res: Vec<_> = input.into_iter().zip(nodes.nodes).collect();
        Ok(res)
    }

    pub async fn bootstrap_state(&mut self, height: BlockNum) -> Result<(), BootstrapError> {
        if self.range.get().contains(&height) {
            log::warn!("skipping height {} as already present", height);
            return Ok(());
        }

        let root_hash = self
            .block_storage
            .get_evm_confirmed_state_root(height)
            .await?;
        log::info!(
            "starting bootstrap at height {}, hash {:?}",
            height,
            root_hash
        );
        let collection = collection(&self.storage);

        let mut stack_children: SpliceCountStack<Vec<(H256, bool)>> =
            SpliceCountStack::new("children".to_string());

        let mut stack_fetched: SpliceCountStack<Result<Vec<NodeFullInfo>, ClientError>> =
            SpliceCountStack::new("fetched and verified data".to_string());

        let root_guard = RootGuard::new(&collection.database, root_hash, account_extractor);
        let first_with_data =
            Self::fetch_nodes_of_hashes(&mut self.client, vec![(root_hash, true)]).await;
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
                    }
                }
                None => {
                    let next_child_slice = stack_children.pop();
                    match next_child_slice {
                        Some(next_child_slice) => {
                            let first_with_data =
                                Self::fetch_nodes_of_hashes(&mut self.client, next_child_slice)
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

        Ok(())
    }
}
