use std::{
    borrow::Borrow,
    collections::HashSet,
    marker::PhantomData,
    path::{Path, PathBuf},
};

use anyhow::{anyhow, ensure, Result};
use clap::{value_t_or_exit, App, AppSettings, Arg, ArgMatches, SubCommand};
use log::*;
use solana_clap_utils::ArgConstant;

use evm_state::storage::{self, rocksdb, Storage, SubStorage};
use evm_state::{
    types::{Account, Code},
    H256, U256,
};
use rlp::{Decodable, Rlp};
use triedb::{
    empty_trie_hash,
    merkle::{MerkleNode, MerkleValue},
};

pub trait EvmStateSubCommand {
    fn evm_state_subcommand(self) -> Self;
}

const ROOT_ARG: ArgConstant<'static> = ArgConstant {
    name: "root",
    long: "root",
    help: "EVM state root hash",
};

impl EvmStateSubCommand for App<'_, '_> {
    fn evm_state_subcommand(self) -> Self {
        self.subcommand(
            SubCommand::with_name("evm_state")
                .about("EVM state utilities")
                .setting(AppSettings::ArgRequiredElseHelp)
                .subcommand(
                    SubCommand::with_name("purge")
                        .about("Cleanup EVM state data unreachable from state root")
                        .arg(
                            Arg::with_name(ROOT_ARG.name)
                                .long(ROOT_ARG.long)
                                .required(true)
                                .takes_value(true)
                                .help(ROOT_ARG.help),
                        )
                        .arg(
                            Arg::with_name("dry_run")
                                .long("dry-run")
                                .help("Do nothing, just collect hashes and print them"),
                        ),
                )
                .subcommand(
                    SubCommand::with_name("copy")
                        .about("Copy EVM accounts state into destination RocksDB")
                        .setting(AppSettings::ArgRequiredElseHelp)
                        .arg(
                            Arg::with_name(ROOT_ARG.name)
                                .long(ROOT_ARG.long)
                                .required(true)
                                .takes_value(true)
                                .help(ROOT_ARG.help),
                        )
                        .arg(
                            Arg::with_name("destination")
                                .long("destination")
                                .required(true)
                                .takes_value(true)
                                .help("Path to destination RocksDB"),
                        ),
                ),
        )
    }
}

pub fn process_evm_state_command(ledger_path: &Path, matches: &ArgMatches<'_>) -> Result<()> {
    let evm_state_path = ledger_path.join("evm-state");
    let storage = Storage::open_persistent(evm_state_path)?;

    match matches.subcommand() {
        ("purge", Some(matches)) => {
            let root = value_t_or_exit!(matches, ROOT_ARG.name, H256);
            let is_dry_run = matches.is_present("dry_run");

            assert!(storage.check_root_exist(root));
            let db = storage.db();

            if is_dry_run {
                info!("Dry run, do nothing after collecting keys ...");
            }

            let mut accounts_state_walker =
                Walker::new(db, inspectors::memorizer::AccountsKeysCollector::default());
            accounts_state_walker.traverse(root)?;
            accounts_state_walker.inspector.summarize();

            let mut storages_walker =
                Walker::new(db, inspectors::memorizer::StoragesKeysCollector::default());
            for storage_root in &accounts_state_walker.inspector.storage_roots {
                storages_walker.traverse(*storage_root)?;
            }
            storages_walker.inspector.summarize();

            if !is_dry_run {
                let cleaner = cleaner::Cleaner::new_with(
                    db,
                    accounts_state_walker.inspector,
                    storages_walker.inspector,
                );
                cleaner.cleanup()?;
            }
        }
        ("copy", Some(matches)) => {
            let root = value_t_or_exit!(matches, ROOT_ARG.name, H256);
            let destination = value_t_or_exit!(matches, "destination", PathBuf);

            assert!(storage.check_root_exist(root));
            let destination = Storage::open_persistent(destination)?;

            let source = storage.clone();
            let streamer = inspectors::streamer::AccountsStreamer {
                source,
                destination,
            };
            let mut walker = Walker::new(storage, streamer);
            walker.traverse(root)?;
        }
        unhandled => panic!("Unhandled {:?}", unhandled),
    }
    Ok(())
}

trait Inspector<T> {
    fn inspect_raw<Data: AsRef<[u8]>>(&mut self, _: H256, _: &Data) -> Result<bool>;
    fn inspect_typed(&mut self, _: &T) -> Result<()>;
}

struct Walker<DB, T, I> {
    db: DB,
    inspector: I,
    _data: PhantomData<T>,
}

impl<DB, T, I> Walker<DB, T, I> {
    fn new(db: DB, inspector: I) -> Self {
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
    fn traverse(&mut self, hash: H256) -> Result<()> {
        debug!("traversing {:?} ...", hash);
        if hash != empty_trie_hash() {
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

mod inspectors {
    use super::*;

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
                if let Some(code_data) = self.source.get::<storage::Codes>(code_hash) {
                    self.destination.set::<storage::Codes>(code_hash, code_data);
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
}

mod cleaner {
    use super::{inspectors::memorizer, *};
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
                let column_name = storage::Codes::COLUMN_NAME;
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
        fn arbitrary(g: &mut Gen) -> Self {
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
