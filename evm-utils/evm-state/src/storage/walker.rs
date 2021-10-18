use std::{borrow::Borrow, marker::PhantomData};

use primitive_types::H256;
use rlp::{Decodable, Rlp};
use triedb::merkle::{MerkleNode, MerkleValue};

use anyhow::{anyhow, Result};
use log::*;

use super::inspectors::Inspector;

pub struct Walker<DB, T, I> {
    db: DB,
    pub inspector: I,
    _data: PhantomData<T>,
}

impl<DB, T, I> Walker<DB, T, I> {
    pub fn new(db: DB, inspector: I) -> Self {
        Self {
            db,
            inspector,
            _data: PhantomData,
        }
    }
}

impl<DB, T, I> Walker<DB, T, I>
where
    DB: Borrow<rocksdb::DB>,
    T: Decodable,
    I: Inspector<T>,
{
    pub fn traverse(&mut self, hash: H256) -> Result<()> {
        debug!("traversing {:?} ...", hash);
        if hash != triedb::empty_trie_hash() {
            let db = self.db.borrow();
            let bytes = db
                .get(hash)?
                .ok_or_else(|| anyhow!("hash {:?} not found in database"))?;
            trace!("raw bytes: {:?}", bytes);

            self.inspector.inspect_raw(hash, &bytes)?;

            let rlp = Rlp::new(bytes.as_slice());
            trace!("rlp: {:?}", rlp);
            let node = MerkleNode::decode(&rlp)?;
            debug!("node: {:?}", node);

            self.process_node(node)?;
        } else {
            debug!("skip empty trie");
        }

        Ok(())
    }

    fn process_node(&mut self, node: MerkleNode) -> Result<()> {
        match node {
            MerkleNode::Leaf(_nibbles, data) => {
                let rlp = Rlp::new(data);
                trace!("rlp: {:?}", rlp);
                let t = T::decode(&rlp)?;
                // TODO: debug T
                self.inspector.inspect_typed(&t)?;
                Ok(())
            }
            MerkleNode::Extension(_nibbles, value) => self.process_value(value),
            MerkleNode::Branch(values, mb_data) => {
                if let Some(data) = mb_data {
                    let rlp = Rlp::new(data);
                    trace!("rlp: {:?}", rlp);
                    let t = T::decode(&rlp)?;
                    // TODO: debug T
                    self.inspector.inspect_typed(&t)?;
                }
                for value in values {
                    self.process_value(value)?;
                }
                Ok(())
            }
        }
    }

    fn process_value(&mut self, value: MerkleValue) -> Result<()> {
        match value {
            MerkleValue::Empty => Ok(()),
            MerkleValue::Full(node) => self.process_node(*node),
            MerkleValue::Hash(hash) => self.traverse(hash),
        }
    }
}
