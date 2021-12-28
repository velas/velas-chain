use std::{
    array::TryFromSliceError,
    borrow::Borrow,
    convert::TryInto,
    fs,
    io::Error as IoError,
    path::{Path, PathBuf},
    sync::Arc,
};

use bincode::config::{BigEndian, DefaultOptions, Options as _, WithOtherEndian};
use derive_more::{AsRef, Deref};
use lazy_static::lazy_static;
use log::*;
use rlp::{Decodable, Encodable};
use rocksdb::{
    backup::{BackupEngine, BackupEngineOptions, RestoreOptions},
    ColumnFamily, ColumnFamilyDescriptor, Env, IteratorMode, OptimisticTransactionDB, Options,
};
use serde::{de::DeserializeOwned, Serialize};
use tempfile::TempDir;

use crate::{
    transactions::{Transaction, TransactionReceipt},
    types::*,
};
use triedb::{
    empty_trie_hash,
    gc::{DatabaseTrieMut, DbCounter, TrieCollection},
    rocksdb::{RocksDatabaseHandle, RocksHandle},
    FixedSecureTrieMut,
};

pub mod inspectors;
pub mod walker;

pub type Result<T, E = Error> = std::result::Result<T, E>;
pub use rocksdb; // avoid mess with dependencies for another crates

type DB = OptimisticTransactionDB;
type BincodeOpts = WithOtherEndian<DefaultOptions, BigEndian>;
lazy_static! {
    static ref CODER: BincodeOpts = DefaultOptions::new().with_big_endian();
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Database(#[from] rocksdb::Error),
    #[error("Type {1} :: {0}")]
    Bincode(bincode::Error, &'static str),
    #[error("Unable to construct key from bytes")]
    Key(#[from] TryFromSliceError),
    #[error("Internal IO error: {0:?}")]
    Internal(#[from] IoError),

    #[error("Root not found: {0:?}")]
    RootNotFound(H256),
}

const BACKUP_SUBDIR: &str = "backup";
const CUSTOM_LOCATION: &str = "tmp_inner_space";

/// Marker-like wrapper for cleaning temporary directory.
/// Temporary directory is only used in tests.
#[derive(Clone, Debug)]
enum Location {
    Temporary(Arc<TempDir>),
    Persisent(PathBuf),
}
impl Eq for Location {}
impl PartialEq for Location {
    fn eq(&self, other: &Location) -> bool {
        match (self, other) {
            (Location::Persisent(p1), Location::Persisent(p2)) => p1 == p2,
            (Location::Temporary(p1), Location::Temporary(p2)) => p1.path() == p2.path(),
            _ => false,
        }
    }
}

impl AsRef<Path> for Location {
    fn as_ref(&self) -> &Path {
        match self {
            Self::Temporary(temp_dir) => temp_dir.as_ref().path(),
            Self::Persisent(path) => path.as_ref(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Storage {
    pub(crate) db: Arc<DbWithClose>,
    // Location should be second field, because of drop order in Rust.
    location: Location,
    gc_enabled: bool,
}

impl Storage {
    pub fn open_persistent<P: AsRef<Path>>(path: P, gc_enabled: bool) -> Result<Self> {
        Self::open(Location::Persisent(path.as_ref().to_owned()), gc_enabled)
    }

    pub fn create_temporary() -> Result<Self> {
        Self::open(Location::Temporary(Arc::new(TempDir::new()?)), false)
    }
    pub fn create_temporary_gc() -> Result<Self> {
        Self::open(Location::Temporary(Arc::new(TempDir::new()?)), true)
    }

    pub fn gc_enabled(&self) -> bool {
        self.gc_enabled
    }

    // without gc_enabled
    fn open(location: Location, gc_enabled: bool) -> Result<Self> {
        let db_opts = default_db_opts()?;

        // TODO: if gc_enabled remove deprecated columns, and add gc column
        let descriptors = if gc_enabled {
            vec![
                ColumnFamilyDescriptor::new(Codes::COLUMN_NAME, db_opts.clone()),
                ColumnFamilyDescriptor::new(SlotsRoots::COLUMN_NAME, db_opts.clone()),
                ColumnFamilyDescriptor::new(
                    ReferenceCounter::COLUMN_NAME,
                    reference_counter_opts(),
                ),
                // Make sure to reflect changes in `merge_from_db`
            ]
        } else {
            [
                Codes::COLUMN_NAME,
                Transactions::COLUMN_NAME,
                Receipts::COLUMN_NAME,
                TransactionHashesPerBlock::COLUMN_NAME,
                // Make sure to reflect changes in `merge_from_db`
            ]
            .iter()
            .map(|column| ColumnFamilyDescriptor::new(*column, db_opts.clone()))
            .collect()
        };

        let db = DB::open_cf_descriptors(&db_opts, &location, descriptors)?;

        Ok(Self {
            db: Arc::new(DbWithClose(db)),
            location,
            gc_enabled,
        })
    }

    pub fn backup(&self, backup_dir: Option<PathBuf>) -> Result<PathBuf> {
        let backup_dir = backup_dir.unwrap_or_else(|| self.location.as_ref().join(BACKUP_SUBDIR));
        info!("EVM Backup storage data into {}", backup_dir.display());

        let mut engine = BackupEngine::open(&BackupEngineOptions::default(), &backup_dir)?;
        if engine.get_backup_info().len() > HARD_BACKUPS_COUNT {
            // TODO: measure
            engine.purge_old_backups(HARD_BACKUPS_COUNT)?;
        }
        engine.create_new_backup_flush(&self.db.0, true)?;
        Ok(backup_dir)
    }

    pub fn restore_from(path: impl AsRef<Path>, target: impl AsRef<Path>) -> Result<()> {
        let path = path.as_ref();
        let target = target.as_ref();

        // TODO: ensure target dir is empty or doesn't exists at all
        fs::create_dir_all(target).expect("Unable to create target dir");

        assert!(
            path.is_dir() && path.exists(),
            "Storage can be loaded only from existing directory"
        );
        assert!(
            target.is_dir(),
            "Loaded storage data must lays in target dir"
        );

        info!(
            "Loading storage data from {} into {} (restore from backup)",
            path.display(),
            target.display()
        );
        let mut engine = BackupEngine::open(&BackupEngineOptions::default(), path)?;
        engine.restore_from_latest_backup(&target, &target, &RestoreOptions::default())?;

        Ok(())
    }

    /// Temporary solution to check if anything was purged from bd.
    pub fn check_root_exist(&self, root: H256) -> bool {
        if root == empty_trie_hash() {
            true // empty root should exist always
        } else {
            // only return true if root is retrivable
            matches!(self.db.get(root.as_ref()), Ok(Some(_)))
        }
    }

    pub fn typed_for<K: AsRef<[u8]>, V: Encodable + Decodable>(
        &self,
        root: H256,
    ) -> FixedSecureTrieMut<DatabaseTrieMut<RocksHandle<&DB>>, K, V> {
        let handle = self.rocksdb_trie_handle();

        FixedSecureTrieMut::new(DatabaseTrieMut::trie_for(handle, root))
    }

    pub fn rocksdb_trie_handle(&self) -> RocksHandle<&DB> {
        if let Some(cf) = self.counters_cf() {
            RocksHandle::new(RocksDatabaseHandle::new(self.db(), cf))
        } else {
            RocksHandle::new(RocksDatabaseHandle::without_counter(self.db()))
        }
    }

    // Returns evm state subdirectory that can be used temporary used by extern users.
    pub fn get_inner_location(&self) -> Result<PathBuf> {
        let location = self.location.as_ref().join(CUSTOM_LOCATION);
        std::fs::create_dir_all(&location)?;
        Ok(location)
    }

    pub fn db(&self) -> &DB {
        (*self.db).borrow()
    }

    pub fn counters_cf(&self) -> Option<&ColumnFamily> {
        if !self.gc_enabled {
            return None;
        }
        Some(self.cf::<ReferenceCounter>())
    }

    pub fn flush_changes(&self, state_root: H256, state_updates: crate::ChangedState) -> H256 {
        let r = self.rocksdb_trie_handle();

        let db_trie = TrieCollection::new(r);

        let mut storage_patches = triedb::Change::default();
        let mut accounts =
            FixedSecureTrieMut::<_, H160, Account>::new(db_trie.trie_for(state_root));

        for (address, (state, storages)) in state_updates {
            if let Maybe::Just(AccountState {
                nonce,
                balance,
                code,
            }) = state
            {
                let mut account = accounts.get(&address).unwrap_or_default();

                account.nonce = nonce;
                account.balance = balance;

                if !code.is_empty() {
                    let code_hash = code.hash();
                    self.set::<Codes>(code_hash, code);
                    account.code_hash = code_hash;
                }

                let mut storage = FixedSecureTrieMut::<_, H256, U256>::new(
                    db_trie.trie_for(account.storage_root),
                );

                for (index, value) in storages {
                    if value != H256::default() {
                        let value = U256::from_big_endian(&value[..]);
                        storage.insert(&index, &value);
                    } else {
                        storage.delete(&index);
                    }
                }

                let storage_patch = storage.to_trie().into_patch();
                let storage_root = storage_patch.root;
                storage_patches.merge(&storage_patch.change);
                account.storage_root = storage_root;

                accounts.insert(&address, &account);
            } else {
                accounts.delete(&address);
            }
        }

        let mut accounts_patch = accounts.to_trie().into_patch();
        accounts_patch.change.merge_child(&storage_patches);
        db_trie
            .apply_increase(accounts_patch, account_extractor)
            .leak_root()
    }

    pub fn merge_from_db(&self, other_db: &Self) -> Result<()> {
        assert!(!self.gc_enabled, "Cannot merge to db with rc counters");
        assert!(
            !other_db.gc_enabled,
            "Cannot merge from db with rc counters"
        );
        info!("Iterating over storage");
        for (k, v) in other_db.db.full_iterator(rocksdb::IteratorMode::Start) {
            self.db.put(&k, &v)?
        }
        info!("Iterating over codes");
        // copy all codes
        let cf = self.cf::<Codes>();
        for (k, v) in other_db
            .db
            .full_iterator_cf(cf, rocksdb::IteratorMode::Start)
        {
            self.db.put_cf(cf, &k, &v)?
        }
        // TODO: make it possible to merge reference counters?
        Ok(())
    }

    pub fn gc_count(&self, link: H256) -> Result<u64> {
        if !self.gc_enabled {
            return Ok(0);
        }
        let mut tx = self.db().transaction();
        let trie = self.rocksdb_trie_handle();
        Ok(trie
            .db
            .get_counter_in_tx(&mut tx, link)
            .map(|v| v.try_into().unwrap_or_default())?)
    }

    // Because solana handle each bank independently.
    // We also inherit this behaviour.
    /// Mark slot as removed, also find root_hash that correspond to this bank, and decrement its counter.
    /// Return root_hash if it counter == 0 after removing
    pub fn purge_slot(&self, slot: u64) -> Result<Option<H256>> {
        // TODO: clever retry on purge slot failure (if transaction conflict).
        // TODO: also make some retry on RootCleanup manager.
        if !self.gc_enabled {
            return Ok(None);
        }
        let slots_cf = self.cf::<SlotsRoots>();
        let mut tx = self.db().transaction();
        let trie = self.rocksdb_trie_handle();
        let val = tx.get_cf(slots_cf, &slot.to_be_bytes())?;
        let remove_root = if let Some(root) = val {
            let root = H256::from_slice(root.as_ref());

            let counter = trie.db.get_counter_in_tx(&mut tx, root)?;
            info!("Purge slot:{} root:{}, counter:{}", slot, root, counter);
            trie.db.decrease(&mut tx, root)?;
            // Return root if it counter was == 1
            if counter <= 1 {
                Some(root)
            } else {
                None
            }
        } else {
            info!("Purge slot:{} without root data.", slot);
            None
        };

        tx.delete_cf(slots_cf, &slot.to_be_bytes())?;
        tx.commit()?;
        Ok(remove_root)
    }

    /// Our garbage collection counts only references of child objects.
    /// Because root_hash has no parents it should be handled separately.
    ///
    /// This method introduce a link between slot and root.
    /// Increment root_link reference counter, and mark slot.
    ///
    /// This operation is used in two cases:
    /// 1. When new bank is created.
    /// 2. When bank change it's root (reset_slot_root flag is provided).
    // Save info. slot -> root_hash
    // Increment root_hash references counter.
    pub fn register_slot(&self, slot: u64, root: H256, reset_slot_root: bool) -> Result<()> {
        if !self.gc_enabled {
            return Ok(());
        }
        let slots_cf = self.cf::<SlotsRoots>();
        let trie = self.rocksdb_trie_handle();

        info!("Register slot:{} root:{}", slot, root);

        const NUM_RETRY: usize = 500; // ~10ms-100ms
        let purge_root = if let Some(data) = self.db().get_cf(slots_cf, &slot.to_be_bytes())? {
            let purge_root = H256::from_slice(data.as_ref());
            // root should be changed only on purpose, and changed to different value
            if !reset_slot_root || root == purge_root {
                error!(
                    "Slot was already registered, but reset_slot_root wasn't set, slot: {}, previous: {}, new:{}",
                    slot, purge_root, root
                );
                return Ok(());
            }
            Some(purge_root)
        } else {
            None
        };

        let retry = || -> Result<_> {
            let mut tx = self.db().transaction();
            tx.put_cf(slots_cf, &slot.to_be_bytes(), root.as_ref())?;
            trie.db.increase(&mut tx, root)?;
            tx.commit()?;
            Ok(())
        };
        let mut complete = None;
        for retry_count in 0..NUM_RETRY {
            complete = Some(retry().map(|v| (v, retry_count)));
            match complete.as_ref().unwrap() {
                Ok(_) => break,
                Err(e) => log::trace!(
                    "Error during transaction execution retry_count:{} reason:{}",
                    retry_count + 1,
                    e
                ),
            }
        }
        complete.expect("Retry should save completion artifact.")?;

        if let Some(purge_root) = purge_root {
            let trie = self.rocksdb_trie_handle();
            if trie.gc_unpin_root(purge_root) {
                // TODO: Propagate cleanup to outer level.
                RootCleanup::new(&self, vec![purge_root]).cleanup()?;
            }
        }
        Ok(())
    }

    pub fn cleanup_slots(&self, keep_slot: u64, root: H256) -> Result<()> {
        if !self.check_root_exist(root) {
            return Err(Error::RootNotFound(root));
        }

        let slots_cf = self.cf::<SlotsRoots>();
        let mut collect_slots = vec![];
        let mut cleanup_roots = vec![];
        for (k, _v) in self.db().iterator_cf(slots_cf, IteratorMode::Start) {
            let mut slot_arr = [0; 8];
            slot_arr.copy_from_slice(&k[0..8]);
            let slot = u64::from_be_bytes(slot_arr);
            collect_slots.push(slot);
        }

        for slot in collect_slots {
            if slot == keep_slot {
                continue;
            }
            self.purge_slot(slot)?.map(|root| cleanup_roots.push(root));
        }

        let mut cleaner = RootCleanup::new(&self, cleanup_roots);
        cleaner.cleanup()
    }

    pub fn gc_try_cleanup_account_hashes(&self, removes: &[H256]) -> Result<Vec<H256>> {
        if !self.gc_enabled {
            return Ok(vec![]);
        }
        Ok(self
            .rocksdb_trie_handle()
            .gc_cleanup_layer(removes, account_extractor))
    }
    pub fn list_roots(&self) {
        if !self.gc_enabled {
            println!("Gc is not enabled");
            return;
        }
        let slots_cf = self.cf::<SlotsRoots>();
        for (k, v) in self.db().iterator_cf(slots_cf, IteratorMode::Start) {
            let mut slot_arr = [0; 8];
            slot_arr.copy_from_slice(&k[0..8]);
            let slot = u64::from_be_bytes(slot_arr);

            println!("Found root for slot: {} => {:?}", slot, hex::encode(&v))
        }
    }
}

fn account_extractor(data: &[u8]) -> Vec<H256> {
    if let Ok(account) = rlp::decode::<Account>(data) {
        vec![account.storage_root]
    } else {
        vec![] // this trie is mixed collection, and can contain storage values among with accounts
    }
}

pub struct RootCleanup<'a> {
    storage: &'a Storage,
    elems: Vec<H256>,
}

impl<'a> RootCleanup<'a> {
    pub fn new(storage: &'a Storage, roots: Vec<H256>) -> Self {
        Self {
            elems: roots,
            storage,
        }
    }

    pub fn cleanup(&mut self) -> Result<()> {
        const MAX_ELEMS: usize = 200;
        while !self.elems.is_empty() {
            let total_elems = self.elems.len();
            let num_elems = usize::min(self.elems.len(), MAX_ELEMS);

            let elems: Vec<_> = self.elems.drain(0..num_elems).collect();
            let new_elems = self.storage.gc_try_cleanup_account_hashes(&elems)?;

            debug!(
                "Cleaning up {} elems, total elems in queue {}, adding elems {}",
                num_elems,
                total_elems,
                new_elems.len()
            );
            self.elems.extend_from_slice(&new_elems);
        }
        Ok(())
    }
}

impl Borrow<DB> for Storage {
    fn borrow(&self) -> &DB {
        self.db()
    }
}

#[derive(Debug, AsRef, Deref)]
// Hack to close rocksdb background threads. And flush database.
pub struct DbWithClose(DB);

impl Drop for DbWithClose {
    fn drop(&mut self) {
        if let Err(e) = self.flush() {
            error!("Error during rocksdb flush: {:?}", e);
        }
        self.cancel_all_background_work(true);
    }
}

pub trait SubStorage {
    const COLUMN_NAME: &'static str;
    type Key: Encodable + Decodable;
    type Value: Serialize + DeserializeOwned;
}

pub enum SlotsRoots {}
impl SubStorage for SlotsRoots {
    const COLUMN_NAME: &'static str = "slots_roots";
    type Key = u64;
    type Value = H256;
}

pub enum ReferenceCounter {}
impl SubStorage for ReferenceCounter {
    const COLUMN_NAME: &'static str = "reference_counter";
    type Key = H256;
    type Value = i64;
}
pub enum Codes {}
impl SubStorage for Codes {
    const COLUMN_NAME: &'static str = "codes";
    type Key = H256;
    type Value = Code;
}

pub enum Transactions {}
impl SubStorage for Transactions {
    const COLUMN_NAME: &'static str = "transactions";
    type Key = H256;
    type Value = Transaction;
}

pub enum Receipts {}
impl SubStorage for Receipts {
    const COLUMN_NAME: &'static str = "receipts";
    type Key = H256;
    type Value = TransactionReceipt;
}

pub enum TransactionHashesPerBlock {}
impl SubStorage for TransactionHashesPerBlock {
    const COLUMN_NAME: &'static str = "transactions_per_block";
    type Key = BlockNum;
    type Value = Vec<H256>;
}

impl Storage {
    pub fn get<S: SubStorage>(&self, key: S::Key) -> Option<S::Value> {
        let cf = self.cf::<S>();
        let key_bytes = rlp::encode(&key);

        self.db
            .get_pinned_cf(cf, key_bytes)
            .expect("Error on reading mapped column")
            .map(|slice| {
                CODER
                    .deserialize(slice.as_ref())
                    .expect("Unable to decode value")
            })
    }

    pub fn set<S: SubStorage>(&self, key: S::Key, value: S::Value) {
        let cf = self.cf::<S>();
        let key_bytes = rlp::encode(&key);
        let value_bytes = CODER.serialize(&value).expect("Unable to serialize value");
        self.db
            .put_cf(cf, key_bytes, value_bytes)
            .expect("Error when put value into database");
    }

    pub fn cf<S: SubStorage>(&self) -> &ColumnFamily {
        self.db
            .cf_handle(S::COLUMN_NAME)
            .unwrap_or_else(|| panic!("Column Family descriptor {} not found", S::COLUMN_NAME))
    }
}

// hard limit of backups count
const HARD_BACKUPS_COUNT: usize = 1; // TODO: tweak it

// #[macro_export]
// macro_rules! persistent_types {
//     ($($Marker:ident in $Column:expr => $Key:ty : $Value:ty,)+) => {
//         const COLUMN_NAMES: &[&'static str] = &[$($Column),+];

//         $(
//             #[derive(Debug)]
//             pub(crate) enum $Marker {}
//             impl PersistentAssoc for $Marker {
//                 const COLUMN_NAME: &'static str = $Column;
//                 type Key = $Key;
//                 type Value = $Value;
//             }
//         )+
//     };
//     ($($Marker:ident in $Column:expr => $Key:ty : $Value:ty),+) => {
//         persistent_types! { $($Marker in $Column => $Key : $Value,)+ }
//     }
// }

pub fn default_db_opts() -> Result<Options> {
    let mut opts = Options::default();
    opts.create_if_missing(true);
    opts.create_missing_column_families(true);
    let mut env = Env::default()?;
    env.join_all_threads();
    opts.set_env(&env);
    Ok(opts)
}

pub mod cleaner {
    use crate::storage::ReferenceCounter;

    use super::inspectors::memorizer;
    use std::borrow::Borrow;

    use primitive_types::H256;

    use anyhow::{anyhow, Result};
    use log::*;

    use super::{Codes, SubStorage};

    pub struct Cleaner<DB, T> {
        db: DB,
        trie_nodes: T,
        accounts: memorizer::AccountStorageRootsCollector,
    }

    impl<DB, T> Cleaner<DB, T>
    where
        T: AsRef<memorizer::TrieCollector>,
    {
        pub fn new_with(
            db: DB,
            trie_nodes: T,
            accounts: memorizer::AccountStorageRootsCollector,
        ) -> Self {
            Self {
                db,
                trie_nodes,
                accounts,
            }
        }

        pub fn cleanup(self) -> Result<()>
        where
            DB: Borrow<crate::storage::DB>,
        {
            let db = self.db.borrow();

            let trie_nodes = self.trie_nodes.as_ref();
            // Cleanup unused trie keys in default column family
            {
                let mut batch = rocksdb::WriteBatchWithTransaction::<true>::default();

                for (key, _data) in db.iterator(rocksdb::IteratorMode::Start) {
                    let key =
                        <H256 as super::inspectors::encoding::TryFromSlice>::try_from_slice(&key)?;
                    if trie_nodes.trie_keys.contains(&key) {
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
                let mut batch = rocksdb::WriteBatchWithTransaction::<true>::default();

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

            {
                let column_name = ReferenceCounter::COLUMN_NAME;
                if let Some(counters_cf) = db.cf_handle(column_name) {
                    let mut batch = rocksdb::WriteBatchWithTransaction::<true>::default();

                    for (key, _data) in db.iterator_cf(counters_cf, rocksdb::IteratorMode::Start) {
                        let key =
                            <H256 as super::inspectors::encoding::TryFromSlice>::try_from_slice(
                                &key,
                            )?;
                        if trie_nodes.trie_keys.contains(&key) {
                            continue; // skip this key
                        } else {
                            batch.delete_cf(counters_cf, key);
                        }
                    }

                    let batch_size = batch.len();
                    db.write(batch)?;
                    info!("{} counters was removed", batch_size);
                }
            }

            Ok(())
        }
    }
}

pub fn copy_and_purge(
    src: Storage,
    destinations: &[Storage],
    root: H256,
) -> Result<(), anyhow::Error> {
    anyhow::ensure!(src.check_root_exist(root), "Root does not exist");

    let source = src.clone();
    let streamer = inspectors::streamer::AccountsStreamer {
        source,
        destinations,
    };
    let walker = walker::Walker::new_shared(src, streamer);
    walker.traverse(root)?;
    // during walking AccountsStreamer increase link to all nodes.
    // Root should be decreased, because it has no parent for now, and outer caller will increase it's count.
    for destination in destinations {
        let trie = destination.rocksdb_trie_handle();
        trie.db.decrease_atomic(root)?;
    }
    Ok(())
}

pub fn reference_counter_opts() -> Options {
    let mut opts = Options::default();
    opts.set_merge_operator_associative("inc_counter", triedb::rocksdb::merge_counter);
    opts
}
