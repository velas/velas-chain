use std::sync::RwLock;
use std::{borrow::Borrow};
use triedb::merkle::{MerkleNode, MerkleValue};
use triedb::merkle::nibble::NibbleVec;
use primitive_types::H256;
use rlp::Rlp;

use rocksdb::OptimisticTransactionDB;

pub struct StateTraversal<DB> {
    pub db: DB,
    pub needle: H256,
    found: RwLock<Option<Vec<u8>>>
}

impl<DB: Borrow<OptimisticTransactionDB> + Sync + Send> StateTraversal<DB> {
    pub fn new(db: DB, needle: H256) -> Self {
        Finder {
            db,
            needle,
            found: RwLock::new(None)
        }
    }

    pub fn traverse(&self, hash: H256) -> Result<Option<Vec<u8>>, ()> {
        self.traverse_inner(Default::default(), hash);
        let reader = self.found.read().unwrap();
        Ok(reader.clone())
    }

    fn traverse_inner(&self, nibble: NibbleVec, hash: H256) -> Result<Option<Vec<u8>>, ()> {
        eprintln!("traversing {:?} ...", hash);
        if hash != triedb::empty_trie_hash() {
            let db = self.db.borrow();
            let bytes = db
                .get(hash)
                .map_err(|_| ())?
                .ok_or_else(|| panic!("panicing in byte parsing"))?;
            eprintln!("raw bytes: {:?}", bytes);

            let rlp = Rlp::new(bytes.as_slice());
            println!("rlp: {:?}", rlp);
            let node = MerkleNode::decode(&rlp).map_err(|e| panic!("merkle rlp decode"))?;
            println!("node: {:?}", node);

            println!("Comparing hashes {} and {}", hash, self.needle);

            self.process_node(nibble, &node)?;

            // self.trie_inspector.inspect_node(hash, &bytes)?;
        } else {
            println!("skip empty trie");
        }

        Ok(None)
    }

    fn process_node(&self, mut nibble: NibbleVec, node: &MerkleNode) -> Result<Option<Vec<u8>>, ()> {
        match node {
            MerkleNode::Leaf(nibbles, data) => {
                nibble.extend_from_slice(&*nibbles);
                let key = triedb::merkle::nibble::into_key(&nibble);
                // self.data_inspector.inspect_data_raw(key, data)
                Ok(None)
            }
            MerkleNode::Extension(nibbles, value) => {
                nibble.extend_from_slice(&*nibbles);
                self.process_value(nibble, value);
                Ok(None)
            }
            MerkleNode::Branch(values, mb_data) => {
                // lack of copy on result, forces setting array manually
                let mut values_result = [
                    None, None, None, None, None, None, None, None, None, None, None, None, None,
                    None, None, None,
                ];
                let result : Result<Option<Vec<u8>>, ()> = rayon::scope(|s| {
                    for (nibbl, (value, result)) in
                        values.iter().zip(&mut values_result).enumerate()
                    {
                        let mut cloned_nibble = nibble.clone();
                        s.spawn(move |_| {
                            cloned_nibble.push(nibbl.into());
                            *result = Some(self.process_value(cloned_nibble, value))
                        });
                    }
                    if let Some(data) = mb_data {
                        let key = triedb::merkle::nibble::into_key(&nibble);
                        // self.data_inspector.inspect_data_raw(key, data)
                        Ok(None)
                    } else {
                        Ok(None)
                    }
                });
                for result in values_result {
                    result.unwrap()?;
                }
                Ok(None)
            }
        }
    }

    fn process_value(&self, nibble: NibbleVec, value: &MerkleValue) -> Result<Option<Vec<u8>>, ()> {
        match value {
            MerkleValue::Empty => Ok(None),
            MerkleValue::Full(node) => self.process_node(nibble, node),
            MerkleValue::Hash(hash) => self.traverse_inner(nibble, *hash),
        }
    }
}
