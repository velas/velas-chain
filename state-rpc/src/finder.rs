use primitive_types::H256;
use std::borrow::Borrow;
use std::sync::RwLock;

use rocksdb::OptimisticTransactionDB;

pub struct Finder<DB> {
    pub db: DB,
    found: RwLock<Option<Vec<u8>>>,
}

impl<DB: Borrow<OptimisticTransactionDB> + Sync + Send> Finder<DB> {
    pub fn new(db: DB) -> Self {
        Finder {
            db,
            found: RwLock::new(None),
        }
    }

    pub fn find(&self, hash: H256) -> Result<Option<Vec<u8>>, String> {
        let db = self.db.borrow();
        let bytes = db.get(hash)?;
        Ok(bytes)
    }
}
