use {
    super::inspectors::{encoding, TrieDataInsectorRaw, TrieInspector},
    anyhow::{anyhow, Result},
    log::*,
    primitive_types::H256,
    rlp::Rlp,
    std::{borrow::Borrow, sync::Arc},
    triedb::merkle::{nibble::NibbleVec, Branch, Extension, Leaf, MerkleNode, MerkleValue},
};

pub struct Walker<DB, TI, DI> {
    db: DB,
    pub trie_inspector: TI,
    pub data_inspector: DI,
}

impl<DB, I, K, V> Walker<DB, Arc<I>, encoding::SecTrie<Arc<I>, K, V>> {
    // Create walker with shared inspector that allow cloning.
    pub fn new_shared(db: DB, inspector: I) -> Self {
        let inspector = Arc::new(inspector);

        Self::new_raw(db, inspector.clone(), encoding::SecTrie::new(inspector))
    }
}

impl<DB, TI, DI, K, V> Walker<DB, TI, encoding::SecTrie<DI, K, V>> {
    pub fn new_sec_encoding(db: DB, trie_inspector: TI, data_inspector: DI) -> Self {
        Self::new_raw(db, trie_inspector, encoding::SecTrie::new(data_inspector))
    }
}
impl<DB, TI, DI> Walker<DB, TI, DI> {
    pub fn new_raw(db: DB, trie_inspector: TI, data_inspector: DI) -> Self {
        Self {
            db,
            trie_inspector,
            data_inspector,
        }
    }
}

impl<DB, TI, DI> Walker<DB, TI, DI>
where
    DB: Borrow<super::DB> + Sync + Send,
    TI: TrieInspector + Sync + Send,
    DI: TrieDataInsectorRaw + Sync + Send,
{
    pub fn traverse(&self, hash: H256) -> Result<()> {
        self.traverse_inner(Default::default(), hash)
    }
    pub fn traverse_inner(&self, nibble: NibbleVec, hash: H256) -> Result<()> {
        debug!("traversing {:?} ...", hash);
        if hash != triedb::empty_trie_hash() {
            let db = self.db.borrow();
            let bytes = db
                .get(hash)?
                .ok_or_else(|| anyhow!("hash {:?} not found in database", hash))?;
            trace!("raw bytes: {:?}", bytes);

            let rlp = Rlp::new(bytes.as_slice());
            trace!("rlp: {:?}", rlp);
            let node = MerkleNode::decode(&rlp)?;
            debug!("node: {:?}", node);

            self.process_node(nibble, &node)?;

            // process node after inspection, to copy root later than it's data, to make sure that all roots are correct links
            self.trie_inspector.inspect_node(hash, &bytes)?;
        } else {
            debug!("skip empty trie");
        }

        Ok(())
    }

    fn process_node(&self, mut nibble: NibbleVec, node: &MerkleNode) -> Result<()> {
        match node {
            MerkleNode::Leaf(Leaf { nibbles, data }) => {
                nibble.extend_from_slice(nibbles);
                let key = triedb::merkle::nibble::into_key(&nibble);
                self.data_inspector.inspect_data_raw(key, data)
            }
            MerkleNode::Extension(Extension { nibbles, value }) => {
                nibble.extend_from_slice(nibbles);
                self.process_value(nibble, value)
            }
            MerkleNode::Branch(Branch {
                childs: values,
                data: maybe_data,
            }) => {
                // lack of copy on result, forces setting array manually
                let mut values_result = [
                    None, None, None, None, None, None, None, None, None, None, None, None, None,
                    None, None, None,
                ];
                let result = rayon::scope(|s| {
                    for (nibbl, (value, result)) in
                        values.iter().zip(&mut values_result).enumerate()
                    {
                        let mut cloned_nibble = nibble.clone();
                        s.spawn(move |_| {
                            cloned_nibble.push(nibbl.into());
                            *result = Some(self.process_value(cloned_nibble, value))
                        });
                    }
                    if let Some(data) = maybe_data {
                        let key = triedb::merkle::nibble::into_key(&nibble);
                        self.data_inspector.inspect_data_raw(key, data)
                    } else {
                        Ok(())
                    }
                });
                for result in values_result {
                    result.unwrap()?
                }
                result
            }
        }
    }

    fn process_value(&self, nibble: NibbleVec, value: &MerkleValue) -> Result<()> {
        match value {
            MerkleValue::Empty => Ok(()),
            MerkleValue::Full(node) => self.process_node(nibble, node),
            MerkleValue::Hash(hash) => self.traverse_inner(nibble, *hash),
        }
    }
}
