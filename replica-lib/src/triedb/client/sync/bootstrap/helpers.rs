use evm_state::{storage::account_extractor, H256};

use rlp::Rlp;
use sha3::{Digest, Keccak256};
use triedb::{gc::ReachableHashes, merkle::MerkleNode};

use crate::triedb::{error::client, MAX_CHUNK_HASHES};

pub fn no_childs(_: &[u8]) -> Vec<H256> {
    vec![]
}
pub(super) fn verify_hash(value: &[u8], hash: H256) -> Result<(), client::proto::Error> {
    let actual_hash = H256::from_slice(Keccak256::digest(value).as_slice());
    if hash != actual_hash {
        return Err(client::proto::Error::NodesHashMismatch(hash, actual_hash))?;
    }
    Ok(())
}

fn map_node_to_next_layer(
    parent: &((H256, bool), Vec<u8>),
) -> Result<Vec<(H256, bool)>, triedb::Error> {
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
pub(super) fn compute_and_maybe_split_children(
    layer: &Vec<((H256, bool), Vec<u8>)>,
) -> Result<Vec<Vec<(H256, bool)>>, triedb::Error> {
    let mut childs_all = vec![];
    for element in layer {
        let res = map_node_to_next_layer(element)?;
        childs_all.extend(res.into_iter());
    }
    let res: Vec<_> = if childs_all.len() > MAX_CHUNK_HASHES {
        childs_all
            .rchunks(MAX_CHUNK_HASHES)
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
