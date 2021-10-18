use std::{borrow::Borrow, collections::HashSet};

use primitive_types::{H256, U256};

use anyhow::{anyhow, bail, ensure, Result};
use log::*;

use super::walker::Walker;
use super::{Codes, Storage, SubStorage};
use crate::types::{Account, Code};

pub trait Inspector<T> {
    fn inspect_raw<Data: AsRef<[u8]>>(&mut self, _: H256, _: &Data) -> Result<bool>;
    fn inspect_typed(&mut self, _: &T) -> Result<()>;

    // TODO: pass storage ref into `inspect_*` method
    // type Storage;
    // fn inspect_raw<Data: AsRef<[u8]>>(
    //     &mut self,
    //     _: &Self::Storage,
    //     (_, _): (H256, &Data),
    // ) -> Result<bool>;
    // fn inspect_typed(&mut self, _: &Self::Storage, _: &T) -> Result<()>;
}

pub mod memorizer {
    use super::*;

    #[derive(Default)]
    pub struct AccountsKeysCollector {
        pub trie_keys: HashSet<H256>,
        pub data_size: usize,
        pub storage_roots: HashSet<H256>,
        pub code_hashes: HashSet<H256>,
    }

    impl Inspector<Account> for AccountsKeysCollector {
        fn inspect_raw<Data: AsRef<[u8]>>(&mut self, key: H256, data: &Data) -> Result<bool> {
            let is_new_key = self.trie_keys.insert(key);
            if is_new_key {
                self.data_size += data.as_ref().len();
            }
            Ok(is_new_key)
        }
        fn inspect_typed(&mut self, account: &Account) -> Result<()> {
            self.storage_roots.insert(account.storage_root);
            self.code_hashes.insert(account.code_hash);
            Ok(())
        }
    }

    #[derive(Default)]
    pub struct StoragesKeysCollector {
        pub trie_keys: HashSet<H256>,
        pub data_size: usize,
    }

    impl Inspector<U256> for StoragesKeysCollector {
        fn inspect_raw<Data: AsRef<[u8]>>(&mut self, key: H256, data: &Data) -> Result<bool> {
            let is_new_key = self.trie_keys.insert(key);
            if is_new_key {
                self.data_size += data.as_ref().len();
            }
            Ok(is_new_key)
        }
        fn inspect_typed(&mut self, _: &U256) -> Result<()> {
            Ok(())
        }
    }

    impl AccountsKeysCollector {
        pub fn summarize(&self) {
            info!(
                "Accounts state summary: \
                       trie keys: {}, \
                       data size: {}, \
                       unique storage roots: {}, \
                       unique code hashes: {}",
                self.trie_keys.len(),
                self.data_size,
                self.storage_roots.len(),
                self.code_hashes.len(),
            );
        }
    }

    impl StoragesKeysCollector {
        pub fn summarize(&self) {
            info!(
                "Storages state summary: \
                       trie keys: {}, \
                       data size: {}",
                self.trie_keys.len(),
                self.data_size,
            );
        }
    }
}

pub mod streamer {
    use super::*;
    use rocksdb::WriteBatch;

    pub struct AccountsStreamer {
        pub source: Storage,
        pub destination: Storage,
    }

    impl Inspector<Account> for AccountsStreamer {
        fn inspect_raw<Data: AsRef<[u8]>>(&mut self, key: H256, data: &Data) -> Result<bool> {
            let destination = self.destination.db();

            if let Some(exist_data) = destination.get_pinned(key)? {
                ensure!(
                    data.as_ref() == &*exist_data,
                    "Database existing data for key {:?} differs",
                    key
                );
                Ok(false)
            } else {
                destination.put(key, data)?;
                Ok(true)
            }
        }

        fn inspect_typed(&mut self, account: &Account) -> Result<()> {
            let source = self.source.borrow();
            let destination = self.destination.borrow();

            // - Account Storage
            let mut walker = Walker::new(source, StoragesKeysStreamer::new(destination));
            walker.traverse(account.storage_root)?;
            walker.inspector.apply()?;

            // - Account Code
            let code_hash = account.code_hash;
            if let Some(code_data) = self.source.get::<Codes>(code_hash) {
                self.destination.set::<Codes>(code_hash, code_data);
            } else {
                assert_eq!(code_hash, Code::empty().hash());
            }

            Ok(())
        }
    }

    pub struct StoragesKeysStreamer<Destination> {
        batch: WriteBatch,
        destination: Destination,
    }

    impl<Destination> StoragesKeysStreamer<Destination> {
        fn new(destination: Destination) -> Self {
            let batch = WriteBatch::default();
            Self { batch, destination }
        }
    }

    impl<Destination> Inspector<U256> for StoragesKeysStreamer<Destination>
    where
        Destination: Borrow<rocksdb::DB>,
    {
        fn inspect_raw<Data: AsRef<[u8]>>(&mut self, key: H256, data: &Data) -> Result<bool> {
            let destination = self.destination.borrow();

            if let Some(exist_data) = destination.get_pinned(key)? {
                if data.as_ref() != &*exist_data {
                    panic!("Database existing data for key {:?} differs", key);
                }
                Ok(false)
            } else {
                self.batch.put(key, data);
                Ok(true)
            }
        }

        fn inspect_typed(&mut self, _: &U256) -> Result<()> {
            Ok(())
        }
    }

    impl<Destination> StoragesKeysStreamer<Destination>
    where
        Destination: Borrow<rocksdb::DB>,
    {
        fn apply(self) -> Result<()> {
            let destination = self.destination.borrow();
            destination.write(self.batch)?;
            Ok(())
        }
    }
}

pub mod verifier {
    use super::*;

    use sha3::{Digest, Keccak256};

    pub struct AccountsVerifier {
        storage: Storage,
        pub storage_roots: HashSet<H256>,
    }

    impl AccountsVerifier {
        pub fn new(storage: Storage) -> Self {
            let storage_roots = HashSet::new();
            Self {
                storage,
                storage_roots,
            }
        }
    }

    impl Inspector<Account> for AccountsVerifier {
        fn inspect_raw<Data: AsRef<[u8]>>(&mut self, key: H256, data: &Data) -> Result<bool> {
            let hash = H256::from_slice(Keccak256::digest(data.as_ref()).as_slice());
            ensure!(
                hash == key,
                "Key {:?} differs from content hash {:?}",
                key,
                hash
            );
            Ok(false) // treat all keys as new
        }

        fn inspect_typed(&mut self, account: &Account) -> Result<()> {
            // - Account Storage
            self.storage_roots.insert(account.storage_root);

            // - Account Code
            if account.code_hash != Code::empty().hash() {
                if let Some(code) = self.storage.get::<Codes>(account.code_hash) {
                    let expected = account.code_hash;
                    let actual = code.hash();
                    ensure!(
                        actual == expected,
                        "Account code hash key {:?} differs from actual code hash {:?}",
                        expected,
                        actual
                    );
                } else {
                    bail!("Code data for {:?} is missed in storage", account.code_hash);
                }
            }

            Ok(())
        }
    }

    #[derive(Default)]
    pub struct StoragesTriesVerifier {}

    impl Inspector<U256> for StoragesTriesVerifier {
        fn inspect_raw<Data: AsRef<[u8]>>(&mut self, key: H256, data: &Data) -> Result<bool> {
            let hash = H256::from_slice(Keccak256::digest(data.as_ref()).as_slice());
            ensure!(
                key == hash,
                "key {:?} differs from data hash {:?}",
                key,
                hash
            );
            Ok(false) // treat all keys as new
        }

        fn inspect_typed(&mut self, _: &U256) -> Result<()> {
            Ok(())
        }
    }
}

pub mod cleaner {
    use super::{memorizer, *};
    use std::convert::TryFrom;

    pub struct Cleaner<DB> {
        db: DB,
        accounts: memorizer::AccountsKeysCollector,
        storages: memorizer::StoragesKeysCollector,
    }

    impl<DB> Cleaner<DB> {
        pub fn new_with(
            db: DB,
            accounts: memorizer::AccountsKeysCollector,
            storages: memorizer::StoragesKeysCollector,
        ) -> Self {
            Self {
                db,
                accounts,
                storages,
            }
        }

        pub fn cleanup(self) -> Result<()>
        where
            DB: Borrow<rocksdb::DB>,
        {
            let db = self.db.borrow();

            // Cleanup unused trie keys in default column family
            {
                let mut batch = rocksdb::WriteBatch::default();

                for (key, _data) in db.iterator(rocksdb::IteratorMode::Start) {
                    let bytes = <&[u8; 32]>::try_from(key.as_ref())?;
                    let key = H256::from(bytes);
                    if self.accounts.trie_keys.contains(&key)
                        || self.accounts.storage_roots.contains(&key)
                        || self.storages.trie_keys.contains(&key)
                    {
                        continue; // skip this key
                    } else {
                        batch.delete(key);
                    }
                }

                let batch_size = batch.len();
                db.write(batch)?;
                info!("{} keys was removed", batch_size);
            }

            // Cleanup unused Account Code keys
            {
                let column_name = Codes::COLUMN_NAME;
                let codes_cf = db
                    .cf_handle(column_name)
                    .ok_or_else(|| anyhow!("Codes Column Family '{}' not found", column_name))?;
                let mut batch = rocksdb::WriteBatch::default();

                for (key, _data) in db.iterator_cf(codes_cf, rocksdb::IteratorMode::Start) {
                    let code_hash = rlp::decode(&key)?; // NOTE: keep in sync with ::storage mod
                    if self.accounts.code_hashes.contains(&code_hash) {
                        continue; // skip this key
                    } else {
                        batch.delete_cf(codes_cf, key);
                    }
                }

                let batch_size = batch.len();
                db.write(batch)?;
                info!("{} code keys was removed", batch_size);
            }

            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quickcheck::{Arbitrary, Gen};
    use quickcheck_macros::quickcheck;
    use std::convert::TryFrom;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct Hash(H256);

    impl Arbitrary for Hash {
        fn arbitrary<G: Gen>(g: &mut G) -> Self {
            let mut bytes = [0; 32];
            for byte in &mut bytes {
                *byte = u8::arbitrary(g);
            }
            Hash(H256::from(bytes))
        }
    }

    #[quickcheck]
    fn qc_hash_is_reversible_from_bytes(Hash(expected): Hash) {
        assert_eq!(expected, H256::from_slice(expected.as_bytes()));
        assert_eq!(expected, H256::from_slice(expected.as_ref()));
        assert_eq!(expected.as_bytes(), expected.as_ref());
        assert_eq!(
            H256::from(<&[u8; 32]>::try_from(expected.as_bytes()).unwrap()),
            expected
        );
    }
}
