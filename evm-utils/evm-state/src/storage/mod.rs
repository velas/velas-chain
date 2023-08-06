use {
    crate::{
        transactions::{Transaction, TransactionReceipt},
        types::*,
    },
    bincode::config::{BigEndian, DefaultOptions, Options as _, WithOtherEndian},
    derive_more::{AsRef, Deref},
    itertools::Itertools,
    lazy_static::lazy_static,
    log::*,
    rlp::{Decodable, Encodable},
    rocksdb::{
        backup::{BackupEngine, BackupEngineOptions, RestoreOptions},
        AsColumnFamilyRef, ColumnFamily, ColumnFamilyDescriptor, DBAccess,
        DBIteratorWithThreadMode, DBPinnableSlice, DBWithThreadMode, Env, IteratorMode,
        OptimisticTransactionDB, Options, ReadOptions,
    },
    serde::{de::DeserializeOwned, Serialize},
    std::{
        array::TryFromSliceError,
        borrow::Borrow,
        collections::{BTreeSet, HashMap},
        convert::TryInto,
        fs,
        io::Error as IoError,
        path::{Path, PathBuf},
        sync::Arc,
    },
    tempfile::TempDir,
    triedb::{
        empty_trie_hash,
        gc::{DatabaseTrieMut, DbCounter, TrieCollection},
        rocksdb::{RocksDatabaseHandle, RocksDatabaseHandleGC, RocksHandle, SyncRocksHandle},
        FixedSecureTrieMut,
    },
};

pub mod inspectors;
pub mod two_modes_enum;
pub mod walker;

pub type Result<T, E = Error> = std::result::Result<T, E>;
pub use rocksdb; // avoid mess with dependencies for another crates

type DB = OptimisticTransactionDB;
type BincodeOpts = WithOtherEndian<DefaultOptions, BigEndian>;
type ChangedState = HashMap<H256, (Maybe<AccountState>, HashMap<H256, H256>)>;
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
const NUM_ENTRIES_IN_STORAGES_CHUNK: usize = 10000;

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

pub struct Storage<D = OptimisticTransactionDB>
where
    D: VelasDBCommon,
{
    pub(crate) db: Arc<DbWithClose<D>>,
    // Location should be second field, because of drop order in Rust.
    location: Location,
    gc_enabled: bool,
}

impl<D: VelasDBCommon> Clone for Storage<D> {
    fn clone(&self) -> Self {
        Self {
            db: Arc::clone(&self.db),
            location: self.location.clone(),
            gc_enabled: self.gc_enabled,
        }
    }
}

impl<D: VelasDBCommon> std::fmt::Debug for Storage<D> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Storage<D>")
            .field("db", &self.db)
            .field("location", &self.location)
            .finish()
    }
}

struct Descriptors {
    all: Vec<ColumnFamilyDescriptor>,
    cleanup_cfs: Vec<&'static str>,
}

impl Descriptors {
    pub fn reference_counter_opts() -> Options {
        let mut opts = Options::default();
        opts.set_merge_operator_associative("inc_counter", triedb::rocksdb::merge_counter);
        opts
    }
    fn descriptors(db_opts: Options, gc_enabled: bool) -> Vec<ColumnFamilyDescriptor> {
        if gc_enabled {
            vec![
                ColumnFamilyDescriptor::new(Codes::COLUMN_NAME, db_opts.clone()),
                ColumnFamilyDescriptor::new(SlotsRoots::COLUMN_NAME, db_opts),
                ColumnFamilyDescriptor::new(
                    ReferenceCounter::COLUMN_NAME,
                    Self::reference_counter_opts(),
                ),
                // Make sure to reflect new columns in `merge_from_db`
            ]
        } else {
            [
                Codes::COLUMN_NAME,
                // Make sure to reflect new columns in `merge_from_db`
            ]
            .iter()
            .map(|column| ColumnFamilyDescriptor::new(*column, db_opts.clone()))
            .collect()
        }
    }
    // List of cfs, that was deprecated.
    fn startup_deprecated_cfs() -> &'static [&'static str] {
        &[
            Receipts::COLUMN_NAME,
            TransactionHashesPerBlock::COLUMN_NAME,
            Transactions::COLUMN_NAME,
        ]
    }
    fn compute(exist_cfs: BTreeSet<String>, db_opts: &Options, gc_enabled: bool) -> Self {
        let mut descriptors = Self::descriptors(db_opts.clone(), gc_enabled);

        // find deprecated cfs and remove them at first startup
        let mut cleanup_cfs = Vec::new();
        for d in Self::startup_deprecated_cfs() {
            if exist_cfs.contains(*d) {
                cleanup_cfs.push(*d);
                descriptors.push(ColumnFamilyDescriptor::new(*d, db_opts.clone()))
            }
        }
        Self {
            all: descriptors,
            cleanup_cfs,
        }
    }
    fn secondary_descriptors(gc_enabled: bool) -> Vec<&'static str> {
        if gc_enabled {
            vec![
                Codes::COLUMN_NAME,
                SlotsRoots::COLUMN_NAME,
                ReferenceCounter::COLUMN_NAME,
                // Make sure to reflect new columns in `merge_from_db`
            ]
        } else {
            vec![
                Codes::COLUMN_NAME,
                // Make sure to reflect new columns in `merge_from_db`
            ]
        }
    }
}

impl<D> Storage<D>
where
    D: VelasDBCommon,
{
    pub fn gc_enabled(&self) -> bool {
        self.gc_enabled
    }

    pub fn db(&self) -> &D {
        (*self.db).borrow()
    }

    pub fn list_roots(&self) -> Result<()> {
        if !self.gc_enabled {
            println!("Gc is not enabled");
            return Ok(());
        }
        let slots_cf = self.cf::<SlotsRoots>();
        for item in self.db().iterator_cf(slots_cf, IteratorMode::Start) {
            let (k, v) = item?;
            let mut slot_arr = [0; 8];
            slot_arr.copy_from_slice(&k[0..8]);
            let slot = u64::from_be_bytes(slot_arr);

            println!("Found root for slot: {} => {:?}", slot, hex::encode(&v))
        }
        Ok(())
    }

    /// Temporary solution to check if anything was purged from bd.
    pub fn check_root_exist(&self, root: H256) -> bool {
        if root == empty_trie_hash() {
            true // empty root should exist always
        } else {
            // only return true if root is retrivable
            matches!(
                self.db.get_opt(root.as_ref(), &ReadOptions::default()),
                Ok(Some(_))
            )
        }
    }

    // Returns evm state subdirectory that can be used temporary used by extern users.
    pub fn get_inner_location(&self) -> Result<PathBuf> {
        let location = self.location.as_ref().join(CUSTOM_LOCATION);
        std::fs::create_dir_all(&location)?;
        Ok(location)
    }

    pub fn counters_cf(&self) -> Option<&ColumnFamily> {
        if !self.gc_enabled {
            return None;
        }
        Some(self.cf::<ReferenceCounter>())
    }
}

type RocksWithThreadMode = DBWithThreadMode<rocksdb::SingleThreaded>;

pub type StorageSecondary = Storage<RocksWithThreadMode>;

impl StorageSecondary {
    pub fn open_secondary_persistent<P: AsRef<Path>>(path: P, gc_enabled: bool) -> Result<Self> {
        Self::open(Location::Persisent(path.as_ref().to_owned()), gc_enabled)
    }

    pub fn try_catch_up(&self) -> Result<()> {
        self.db.0.try_catch_up_with_primary()?;
        Ok(())
    }

    pub fn rocksdb_trie_handle(&self) -> SyncRocksHandle<RocksWithThreadMode> {
        SyncRocksHandle::new(RocksDatabaseHandle::new(self.db()))
    }

    fn open(location: Location, gc_enabled: bool) -> Result<Self> {
        log::warn!("gc_enabled {}", gc_enabled);
        let db_opts = default_db_opts()?;

        let descriptors = Descriptors::secondary_descriptors(gc_enabled);
        let db = {
            warn!("Trying as secondary at : {:?}", &location);
            let path = match location.clone() {
                Location::Temporary(..) => {
                    unimplemented!("not implementing a not yet practical case")
                }
                Location::Persisent(path) => path,
            };
            let secondary_path = path.join(SECONDARY_MODE_PATH_SUFFIX);
            warn!(
                "This active secondary db use may 
                temporarily cause the performance of 
                another db use (like by validator) to degrade"
            );
            RocksWithThreadMode::open_cf_as_secondary(
                &db_opts,
                path.as_ref(),
                secondary_path.as_path(),
                descriptors,
            )?
        };

        Ok(Self {
            db: Arc::new(DbWithClose(db)),
            location,
            gc_enabled,
        })
    }
}

impl Storage<OptimisticTransactionDB> {
    pub fn open_persistent<P: AsRef<Path>>(path: P, gc_enabled: bool) -> Result<Self> {
        Self::open(Location::Persisent(path.as_ref().to_owned()), gc_enabled)
    }

    pub fn create_temporary() -> Result<Self> {
        Self::open(Location::Temporary(Arc::new(TempDir::new()?)), false)
    }

    pub fn create_temporary_gc() -> Result<Self> {
        Self::open(Location::Temporary(Arc::new(TempDir::new()?)), true)
    }

    fn open(location: Location, gc_enabled: bool) -> Result<Self> {
        log::warn!("gc_enabled {}", gc_enabled);
        log::info!("location is {:?}", location);
        let db_opts = default_db_opts()?;

        let exist_cfs: BTreeSet<_> = DB::list_cf(&db_opts, &location)
            .unwrap_or_default()
            .into_iter()
            .collect();

        let descriptors = Descriptors::compute(exist_cfs, &db_opts, gc_enabled);
        let db = {
            warn!("Trying as primary at : {:?}", &location);
            let mut db = DB::open_cf_descriptors(&db_opts, &location, descriptors.all)?;

            for removed_cf in descriptors.cleanup_cfs {
                info!("Perform cleanup of deprecated cf: {}", removed_cf);
                db.drop_cf(removed_cf)?
            }
            db
        };

        Ok(Self {
            db: Arc::new(DbWithClose(db)),
            location,
            gc_enabled,
        })
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
        let opts = BackupEngineOptions::new(path)?;
        let env = Env::new()?;
        let mut engine = BackupEngine::open(&opts, &env)?;
        engine.restore_from_latest_backup(target, target, &RestoreOptions::default())?;

        Ok(())
    }

    pub fn rocksdb_trie_handle(&self) -> RocksHandle<&DB> {
        if let Some(cf) = self.counters_cf() {
            RocksHandle::new(RocksDatabaseHandleGC::new(self.db(), cf))
        } else {
            RocksHandle::new(RocksDatabaseHandleGC::without_counter(self.db()))
        }
    }

    pub fn typed_for<K: AsRef<[u8]>, V: Encodable + Decodable>(
        &self,
        root: H256,
    ) -> FixedSecureTrieMut<DatabaseTrieMut<RocksHandle<&DB>>, K, V> {
        let handle = self.rocksdb_trie_handle();

        FixedSecureTrieMut::new(DatabaseTrieMut::trie_for(handle, root))
    }

    // FIXME: flush_changes_hashed code duplication
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

    // FIXME: flush_changes code duplication
    pub fn flush_changes_hashed(&self, state_root: H256, state_updates: ChangedState) -> H256 {
        let r = self.rocksdb_trie_handle();

        let db_trie = TrieCollection::new(r);

        use triedb::TrieMut;
        let mut accounts = db_trie.trie_for(state_root);

        for (address, (state, storages)) in state_updates {
            if let Maybe::Just(AccountState {
                nonce,
                balance,
                code,
            }) = state
            {
                let mut account: Account = accounts
                    .get(address.as_bytes())
                    .and_then(|accounts| rlp::decode(&accounts).ok())
                    .unwrap_or_default();

                account.nonce = nonce;
                account.balance = balance;

                if !code.is_empty() {
                    let code_hash = code.hash();
                    self.set::<Codes>(code_hash, code);
                    account.code_hash = code_hash;
                }

                let storage_values = storages.into_iter().chunks(NUM_ENTRIES_IN_STORAGES_CHUNK);
                for index_changes in storage_values.into_iter() {
                    let mut storage = db_trie.trie_for(account.storage_root);
                    for (index, value) in index_changes {
                        if value != H256::default() {
                            let value = U256::from_big_endian(&value[..]);
                            storage.insert(index.as_bytes(), &rlp::encode(&value));
                        } else {
                            storage.delete(index.as_bytes());
                        }
                    }

                    let storage_patch = storage.into_patch();
                    account.storage_root = db_trie
                        .apply_increase(storage_patch, |_| vec![])
                        .leak_root()
                }
                accounts.insert(address.as_bytes(), &rlp::encode(&account));
            } else {
                accounts.delete(address.as_bytes());
            }
        }

        let accounts_patch = accounts.into_patch();
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
        for item in other_db.db.full_iterator(rocksdb::IteratorMode::Start) {
            let (k, v) = item?;
            self.db.put(&k, &v)?
        }
        info!("Iterating over codes");
        // copy all codes
        let cf = self.cf::<Codes>();
        for item in other_db
            .db
            .full_iterator_cf(cf, rocksdb::IteratorMode::Start)
        {
            let (k, v) = item?;
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
        let val = tx.get_cf(slots_cf, slot.to_be_bytes())?;
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

        tx.delete_cf(slots_cf, slot.to_be_bytes())?;
        tx.commit()?;
        Ok(remove_root)
    }

    pub fn cleanup_slots(&self, keep_slot: u64, root: H256) -> Result<()> {
        if !self.check_root_exist(root) {
            return Err(Error::RootNotFound(root));
        }

        let slots_cf = self.cf::<SlotsRoots>();
        let mut collect_slots = vec![];
        let mut cleanup_roots = vec![];
        for item in self.db().iterator_cf(slots_cf, IteratorMode::Start) {
            let (k, _v) = item?;
            let mut slot_arr = [0; 8];
            slot_arr.copy_from_slice(&k[0..8]);
            let slot = u64::from_be_bytes(slot_arr);
            collect_slots.push(slot);
        }

        for slot in collect_slots {
            if slot == keep_slot {
                continue;
            }
            if let Some(root) = self.purge_slot(slot)? {
                cleanup_roots.push(root)
            }
        }

        let mut cleaner = RootCleanup::new(self, cleanup_roots);
        cleaner.cleanup()
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
        let purge_root = if let Some(data) = self.db().get_cf(slots_cf, slot.to_be_bytes())? {
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
            tx.put_cf(slots_cf, slot.to_be_bytes(), root.as_ref())?;
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
                RootCleanup::new(self, vec![purge_root]).cleanup()?;
            }
        }
        Ok(())
    }

    pub fn gc_try_cleanup_account_hashes(&self, removes: &[H256]) -> (Vec<H256>, Vec<H256>) {
        if !self.gc_enabled {
            return (vec![], vec![]);
        }
        self.rocksdb_trie_handle()
            .gc_cleanup_layer(removes, account_extractor)
    }

    pub fn backup(&self, backup_dir: Option<PathBuf>) -> Result<PathBuf> {
        let backup_dir = backup_dir.unwrap_or_else(|| self.location.as_ref().join(BACKUP_SUBDIR));
        info!("EVM Backup storage data into {}", backup_dir.display());

        let opts = BackupEngineOptions::new(&backup_dir)?;
        let env = Env::new()?;

        let mut engine = BackupEngine::open(&opts, &env)?;
        if engine.get_backup_info().len() > HARD_BACKUPS_COUNT {
            // TODO: measure
            engine.purge_old_backups(HARD_BACKUPS_COUNT)?;
        }
        engine.create_new_backup_flush(self.db.as_ref(), true)?;
        Ok(backup_dir)
    }

    pub fn set_initial(
        &mut self,
        accounts: impl IntoIterator<Item = (H256, evm::backend::MemoryAccount)>,
        state_root: H256,
    ) -> H256 {
        let mut state_updates: ChangedState = HashMap::new();

        for (
            address,
            evm::backend::MemoryAccount {
                nonce,
                balance,
                storage,
                code,
            },
        ) in accounts
        {
            let account_state = AccountState {
                nonce,
                balance,
                code: code.into(),
            };

            state_updates
                .entry(address)
                .or_insert((Maybe::Nothing, HashMap::new()))
                .0 = Maybe::Just(account_state);

            state_updates
                .entry(address)
                .or_insert_with(|| (Maybe::Just(AccountState::default()), HashMap::new()))
                .1
                .extend(storage);
        }

        self.flush_changes_hashed(state_root, state_updates)
    }
}

static SECONDARY_MODE_PATH_SUFFIX: &str = "velas-secondary";

pub fn account_extractor(data: &[u8]) -> Vec<H256> {
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
        const MAX_ELEMENTS: usize = 200;
        let mut indirect = vec![];

        while !self.elems.is_empty() {
            let total_elems = self.elems.len();

            let num_elems = usize::min(total_elems, MAX_ELEMENTS);

            let iteration: Vec<_> = self.elems.drain(0..num_elems).collect();
            debug!(
                "About to clean up {} elements, total elements left in queue {} ...",
                num_elems,
                total_elems - num_elems,
            );
            let childs = self.storage.gc_try_cleanup_account_hashes(&iteration);
            debug!(
                "Cleaned up, about ot add {} elements to queue!",
                childs.0.len() + childs.1.len()
            );
            self.elems.extend_from_slice(&childs.0);
            indirect.extend_from_slice(&childs.1);
        }
        while !indirect.is_empty() {
            let total_elems = indirect.len();

            let num_elems = usize::min(total_elems, MAX_ELEMENTS);

            let iteration: Vec<_> = indirect.drain(0..num_elems).collect();
            debug!(
                "About to clean up {} elements, total elements left in queue {} ...",
                num_elems,
                total_elems - num_elems,
            );
            let childs = self.storage.gc_try_cleanup_account_hashes(&iteration);
            debug!(
                "Cleaned up, about ot add {} elements to queue!",
                childs.0.len()
            );
            indirect.extend_from_slice(&childs.0);
            debug_assert!(childs.1.is_empty());
        }
        Ok(())
    }
}

impl Borrow<DB> for Storage<OptimisticTransactionDB> {
    fn borrow(&self) -> &DB {
        self.db()
    }
}

pub trait VelasDBCommon: DBAccess + std::fmt::Debug + Sized {
    fn flush(&self) -> Result<(), rocksdb::Error>;
    fn cancel_all_background_work(&self, wait: bool);

    fn iterator_cf<'a: 'b, 'b>(
        &'a self,
        cf_handle: &impl AsColumnFamilyRef,
        mode: IteratorMode,
    ) -> DBIteratorWithThreadMode<'b, Self>;

    fn get_pinned_cf<K: AsRef<[u8]>>(
        &self,
        cf: &impl AsColumnFamilyRef,
        key: K,
    ) -> Result<Option<DBPinnableSlice>, rocksdb::Error>;

    fn put_cf<K, V>(
        &self,
        cf: &impl AsColumnFamilyRef,
        key: K,
        value: V,
    ) -> Result<(), rocksdb::Error>
    where
        K: AsRef<[u8]>,
        V: AsRef<[u8]>;

    fn cf_handle(&self, name: &str) -> Option<&ColumnFamily>;
}

impl VelasDBCommon for rocksdb::DBWithThreadMode<rocksdb::SingleThreaded> {
    fn flush(&self) -> Result<(), rocksdb::Error> {
        self.flush()
    }

    fn cancel_all_background_work(&self, wait: bool) {
        self.cancel_all_background_work(wait)
    }

    fn iterator_cf<'a: 'b, 'b>(
        &'a self,
        cf_handle: &impl AsColumnFamilyRef,
        mode: IteratorMode,
    ) -> DBIteratorWithThreadMode<'b, Self> {
        self.iterator_cf(cf_handle, mode)
    }
    fn get_pinned_cf<K: AsRef<[u8]>>(
        &self,
        cf: &impl AsColumnFamilyRef,
        key: K,
    ) -> Result<Option<DBPinnableSlice>, rocksdb::Error> {
        self.get_pinned_cf(cf, key)
    }

    fn put_cf<K, V>(
        &self,
        cf: &impl AsColumnFamilyRef,
        key: K,
        value: V,
    ) -> Result<(), rocksdb::Error>
    where
        K: AsRef<[u8]>,
        V: AsRef<[u8]>,
    {
        self.put_cf(cf, key, value)
    }

    fn cf_handle(&self, name: &str) -> Option<&ColumnFamily> {
        self.cf_handle(name)
    }
}

impl VelasDBCommon for OptimisticTransactionDB {
    fn flush(&self) -> Result<(), rocksdb::Error> {
        self.flush()
    }

    fn cancel_all_background_work(&self, wait: bool) {
        self.cancel_all_background_work(wait)
    }

    fn iterator_cf<'a: 'b, 'b>(
        &'a self,
        cf_handle: &impl AsColumnFamilyRef,
        mode: IteratorMode,
    ) -> DBIteratorWithThreadMode<'b, Self> {
        self.iterator_cf(cf_handle, mode)
    }

    fn get_pinned_cf<K: AsRef<[u8]>>(
        &self,
        cf: &impl AsColumnFamilyRef,
        key: K,
    ) -> Result<Option<DBPinnableSlice>, rocksdb::Error> {
        self.get_pinned_cf(cf, key)
    }

    fn put_cf<K, V>(
        &self,
        cf: &impl AsColumnFamilyRef,
        key: K,
        value: V,
    ) -> Result<(), rocksdb::Error>
    where
        K: AsRef<[u8]>,
        V: AsRef<[u8]>,
    {
        self.put_cf(cf, key, value)
    }

    fn cf_handle(&self, name: &str) -> Option<&ColumnFamily> {
        self.cf_handle(name)
    }
}

#[derive(AsRef, Deref)]
// Hack to close rocksdb background threads. And flush database.
pub struct DbWithClose<D: VelasDBCommon>(D);

impl<D> Drop for DbWithClose<D>
where
    D: VelasDBCommon,
{
    fn drop(&mut self) {
        if let Err(e) = self.flush() {
            error!("Error during rocksdb flush: {:?}", e);
        }
        self.cancel_all_background_work(true);
    }
}

impl<D: VelasDBCommon> std::fmt::Debug for DbWithClose<D> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DbWithClose<D>")
            .field("0", &self.0)
            .finish()
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

impl<D> Storage<D>
where
    D: VelasDBCommon,
{
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
    let mut env = Env::new()?;
    env.join_all_threads();
    opts.set_env(&env);
    Ok(opts)
}

pub mod cleaner {
    use {
        super::{inspectors::memorizer, Codes, SubStorage},
        crate::storage::ReferenceCounter,
        anyhow::{anyhow, Result},
        log::*,
        primitive_types::H256,
        std::borrow::Borrow,
    };

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

                for item in db.iterator(rocksdb::IteratorMode::Start) {
                    let (key, _data) = item?;
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

                for item in db.iterator_cf(codes_cf, rocksdb::IteratorMode::Start) {
                    let (key, _data) = item?;
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

                    for item in db.iterator_cf(counters_cf, rocksdb::IteratorMode::Start) {
                        let (key, _data) = item?;
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
