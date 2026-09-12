use {
    crate::{
        storage::{Codes, Storage as KVS},
        transactions::TransactionReceipt,
        types::*,
    },
    evm::ExitReason,
    log::*,
    primitive_types::H256,
    serde::{Deserialize, Serialize},
    std::{
        collections::HashMap,
        fmt::Debug,
        fs,
        path::{Path, PathBuf},
        sync::Arc,
    },
    triedb::empty_trie_hash,
};

pub const DEFAULT_GAS_LIMIT: u64 = 300_000_000;

pub const BURN_GAS_PRICE: u64 = 2_000_000_000; // 2 lamports per gas.
/// Dont load to many account to memory, to avoid OOM.
pub const MAX_IN_MEMORY_EVM_ACCOUNTS: usize = 10000;
/// Approximate size, real size could be twice as much
pub const MAX_IN_HEAP_EVM_ACCOUNTS_BYTES: usize = 100_000_000;

pub type ChangedState = HashMap<H160, (Maybe<AccountState>, HashMap<H256, H256>)>;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Committed {
    pub block: BlockHeader,
    /// Transactions should be ordered somehow, because we
    pub committed_transactions: Vec<(H256, TransactionReceipt)>,
}

impl Committed {
    // Returns next Icomming state.
    fn next_incomming(&self, timestamp: u64) -> Incomming {
        debug!("Creating new state = {}.", self.block.block_number + 1);
        Incomming::new(
            self.block.block_number + 1,
            self.block.state_root,
            self.block.hash(),
            timestamp,
            self.block.version,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Incomming {
    pub block_number: BlockNum,
    pub timestamp: u64,
    pub used_gas: u64,
    pub(crate) state_root: H256,
    pub last_block_hash: H256,
    /// Maybe::Nothing indicates removed account
    pub(crate) state_updates: ChangedState,

    /// Transactions that was processed but wasn't committed.
    /// Transactions should be ordered by execution order on all validators.
    pub(crate) executed_transactions: Vec<(H256, TransactionReceipt)>,
    #[serde(deserialize_with = "crate::deserialize_utils::default_on_eof")]
    pub(crate) block_version: BlockVersion,
}

impl Incomming {
    pub fn genesis_from_state(state_root: H256) -> Self {
        Self {
            state_root,
            ..Default::default()
        }
    }

    fn new(
        block_number: BlockNum,
        state_root: H256,
        last_block_hash: H256,
        timestamp: u64,
        block_version: BlockVersion,
    ) -> Self {
        Incomming {
            block_number,
            timestamp,
            state_root,
            last_block_hash,
            block_version,
            ..Default::default()
        }
    }

    fn new_update_time(&self, timestamp: u64) -> Self {
        trace!("Updating time for state, timestamp={}", timestamp);
        debug_assert!(!self.is_active_changes());
        let mut new = self.clone();
        new.timestamp = timestamp;
        new
    }

    fn is_active_changes(&self) -> bool {
        !(self.state_updates.is_empty()
            && self.executed_transactions.is_empty()
            && self.used_gas == 0)
    }

    fn into_committed(self, slot: u64, native_blockhash: H256) -> Committed {
        let committed_transactions: Vec<_> = self.executed_transactions;
        let block = BlockHeader::new(
            self.last_block_hash,
            DEFAULT_GAS_LIMIT,
            self.state_root,
            self.block_number,
            self.used_gas,
            self.timestamp,
            slot,
            native_blockhash,
            committed_transactions.iter(),
            self.block_version,
        );
        Committed {
            block,
            committed_transactions,
        }
    }

    // Take current state, replace original with empty
    fn take(&mut self) -> Incomming {
        let empty = Incomming::new(
            self.block_number,
            self.state_root,
            self.last_block_hash,
            self.timestamp,
            self.block_version,
        );
        std::mem::replace(self, empty)
    }
}

#[derive(Clone, Debug)]
pub struct EvmBackend<State> {
    pub state: State,
    pub kvs: KVS,
}

impl<State> EvmBackend<State> {
    pub fn new(state: State, kvs: KVS) -> Self {
        Self { state, kvs }
    }
}

impl EvmBackend<Incomming> {
    /// Apply state updates.
    /// Be sure to commit_block manually after calling this method,
    /// because it clear pending state, and is_active_changes cannot detect any state changes.
    fn flush_changes(&mut self) {
        //todo: do in one tx
        let state = &mut self.state;
        let new_root = self
            .kvs
            .flush_changes(state.state_root, std::mem::take(&mut state.state_updates));

        state.state_root = new_root;
    }

    fn increase_nonce(&mut self, address: H160) {
        let mut account_state = self.get_account_state(address).unwrap_or_default();
        account_state.nonce += U256::from(1);
        self.set_account_state(address, account_state)
    }

    pub fn commit_block(mut self, slot: u64, native_blockhash: H256) -> EvmBackend<Committed> {
        debug!("commit: State before = {:?}", self.state);
        self.flush_changes();
        let state = self.state.into_committed(slot, native_blockhash);
        debug!("commit: State after = {:?}", state);
        EvmBackend {
            state,
            kvs: self.kvs,
        }
    }

    pub fn set_account_state(&mut self, address: H160, account_state: AccountState) {
        use std::collections::hash_map::Entry::*;

        match self.state.state_updates.entry(address) {
            Occupied(mut e) => {
                e.get_mut().0 = Maybe::Just(account_state);
            }
            Vacant(e) => {
                e.insert((Maybe::Just(account_state), HashMap::new()));
            }
        };
    }

    pub fn remove_account(&mut self, address: H160) {
        self.state
            .state_updates
            .entry(address)
            .and_modify(|(state, _)| *state = Maybe::Nothing)
            .or_insert_with(|| (Maybe::Nothing, HashMap::new()));
    }

    pub fn ext_storage(
        &mut self,
        address: H160,
        indexed_values: impl IntoIterator<Item = (H256, H256)>,
    ) {
        let (_, storage) = self
            .state
            .state_updates
            .entry(address)
            .or_insert_with(|| (Maybe::Just(AccountState::default()), HashMap::new()));

        storage.extend(indexed_values);
    }

    //
    // Transactions
    //
    pub fn find_transaction_receipt(&self, transaction: H256) -> Option<&TransactionReceipt> {
        self.state
            .executed_transactions
            .iter()
            .find(|(h, _)| *h == transaction)
            .map(|(_, tx)| tx)
    }

    pub fn push_transaction_receipt(&mut self, transaction: H256, receipt: TransactionReceipt) {
        debug_assert!(self.find_transaction_receipt(transaction).is_none());
        self.state
            .executed_transactions
            .push((transaction, receipt));
    }

    pub fn get_executed_transactions(&self) -> Vec<H256> {
        self.state
            .executed_transactions
            .iter()
            .map(|(h, _)| *h)
            .collect()
    }

    pub fn apply_failed_update(&mut self, failed: &Self, clear_logs: bool) {
        let txs_len = self.state.executed_transactions.len();
        debug_assert_eq!(
            self.state.executed_transactions[..txs_len],
            failed.state.executed_transactions[..txs_len]
        );

        // Save all remaining txs as reverted, increase nonce to transaction sender.
        if failed.state.executed_transactions.len() > txs_len {
            for (h, tx) in failed.state.executed_transactions[txs_len..].iter() {
                let mut tx = tx.clone();

                // dont change failed or error status
                if matches!(tx.status, ExitReason::Succeed(_)) {
                    debug!("Setting exit status to reverted, for tx={:?}", h);

                    tx.to_failed(clear_logs);
                }

                if let Some(caller) = tx.caller() {
                    debug!("Increasing nonce for caller={:?}", caller);
                    self.increase_nonce(caller);
                    self.state.executed_transactions.push((*h, tx));
                } else {
                    error!(
                        "Cannot get caller for tx={:?}, don't save this transaction",
                        h
                    )
                }
            }
        }
    }

    pub fn set_initial(
        &mut self,
        accounts: impl IntoIterator<Item = (H160, evm::backend::MemoryAccount)>,
    ) {
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

            self.set_account_state(address, account_state);
            self.ext_storage(address, storage);
        }
        self.flush_changes()
    }

    pub fn new_incomming_for_root(mut self, root: H256) -> Option<Self> {
        if !self.kvs().check_root_exist(root) || self.state.is_active_changes() {
            return None;
        }
        self.state.state_root = root;
        Some(self)
    }

    pub fn get_account_state_at(
        &self,
        root: H256,
        address: H160,
    ) -> Result<Option<AccountState>, anyhow::Error> {
        if !self.kvs.check_root_exist(root) {
            anyhow::bail!("Failed to find root in storage, root: {}", root);
        }
        Ok(self.get_account_state_from_kvs(root, address))
    }
    pub fn get_storage_at(
        &self,
        root: H256,
        address: H160,
        index: H256,
    ) -> Result<Option<H256>, anyhow::Error> {
        if !self.kvs.check_root_exist(root) {
            anyhow::bail!("Failed to find root in storage, root: {}", root);
        }
        Ok(self.get_storage_from_kvs(root, address, index))
    }

    fn take(&mut self) -> Self {
        Self {
            kvs: self.kvs.clone(),
            state: self.state.take(),
        }
    }

    pub fn kvs(&self) -> &KVS {
        &self.kvs
    }

    fn state_updates(&self, address: &H160) -> Option<&(Maybe<AccountState>, HashMap<H256, H256>)> {
        self.state.state_updates.get(address)
    }
}

pub trait AccountProvider {
    fn last_root(&self) -> H256;
    fn get_account_state(&self, address: H160) -> Option<AccountState>;
    fn get_storage(&self, address: H160, index: H256) -> Option<H256>;
    fn block_number(&self) -> u64;
    fn timestamp(&self) -> u64;
    fn block_version(&self) -> BlockVersion;
}

impl AccountProvider for EvmBackend<Incomming> {
    fn get_account_state(&self, address: H160) -> Option<AccountState> {
        self.state_updates(&address)
            .map(|(state, _)| state.clone().into())
            .unwrap_or_else(|| self.get_account_state_from_kvs(self.last_root(), address))
    }

    fn get_storage(&self, address: H160, index: H256) -> Option<H256> {
        self.state_updates(&address)
            .and_then(|(_, indices)| indices.get(&index))
            .copied()
            .or_else(|| self.get_storage_from_kvs(self.last_root(), address, index))
    }

    fn last_root(&self) -> H256 {
        self.state.state_root
    }

    fn block_number(&self) -> u64 {
        self.state.block_number
    }

    fn timestamp(&self) -> u64 {
        self.state.timestamp
    }

    fn block_version(&self) -> BlockVersion {
        self.state.block_version
    }
}

impl AccountProvider for EvmBackend<Committed> {
    fn get_account_state(&self, address: H160) -> Option<AccountState> {
        self.get_account_state_from_kvs(self.last_root(), address)
    }

    fn get_storage(&self, address: H160, index: H256) -> Option<H256> {
        self.get_storage_from_kvs(self.last_root(), address, index)
    }

    fn last_root(&self) -> H256 {
        self.state.block.state_root
    }

    fn block_number(&self) -> u64 {
        self.state.block.block_number
    }

    fn timestamp(&self) -> u64 {
        self.state.block.timestamp
    }

    fn block_version(&self) -> BlockVersion {
        self.state.block.version
    }
}

impl AccountProvider for EvmState {
    fn get_account_state(&self, address: H160) -> Option<AccountState> {
        match self {
            Self::Incomming(i) => i.get_account_state_from_kvs(self.last_root(), address),
            Self::Committed(c) => c.get_account_state_from_kvs(self.last_root(), address),
        }
    }

    fn get_storage(&self, address: H160, index: H256) -> Option<H256> {
        match self {
            Self::Incomming(i) => i.get_storage_from_kvs(self.last_root(), address, index),
            Self::Committed(c) => c.get_storage_from_kvs(self.last_root(), address, index),
        }
    }

    fn last_root(&self) -> H256 {
        match self {
            Self::Incomming(i) => i.last_root(),
            Self::Committed(c) => c.last_root(),
        }
    }

    fn block_number(&self) -> u64 {
        match self {
            Self::Incomming(i) => i.block_number(),
            Self::Committed(c) => c.block_number(),
        }
    }

    fn timestamp(&self) -> u64 {
        match self {
            Self::Incomming(i) => i.timestamp(),
            Self::Committed(c) => c.timestamp(),
        }
    }

    fn block_version(&self) -> BlockVersion {
        match self {
            Self::Incomming(i) => i.block_version(),
            Self::Committed(c) => c.block_version(),
        }
    }
}

impl<State> EvmBackend<State> {
    pub fn get_account_state_from_kvs(&self, root: H256, address: H160) -> Option<AccountState> {
        self.kvs.typed_for(root).get(&address).map(
            |Account {
                 nonce,
                 balance,
                 code_hash,
                 ..
             }| {
                let code = self
                    .kvs
                    .get::<Codes>(code_hash)
                    // TODO: default only when code_hash == Code::default().hash()
                    .unwrap_or_default();

                AccountState {
                    nonce,
                    balance,
                    code,
                }
            },
        )
    }
    pub fn get_storage_from_kvs(&self, root: H256, address: H160, index: H256) -> Option<H256> {
        self.kvs.counters_cf();
        self.kvs
            .typed_for(root)
            .get(&address)
            .and_then(|Account { storage_root, .. }| {
                self.kvs
                    .typed_for(storage_root)
                    .get(&index)
                    .map(|value: U256| {
                        let mut encoded = H256::default();
                        value.to_big_endian(encoded.as_bytes_mut());
                        encoded
                    })
            })
    }
}

impl EvmBackend<Committed> {
    pub fn kvs(&self) -> &KVS {
        &self.kvs
    }
    pub fn last_root(&self) -> H256 {
        self.state.block.state_root
    }

    pub fn next_incomming(&self, block_start_time: u64) -> EvmBackend<Incomming> {
        EvmBackend {
            state: self.state.next_incomming(block_start_time),
            kvs: self.kvs.clone(),
        }
    }
    pub fn find_committed_transaction(&self, hash: H256) -> Option<&TransactionReceipt> {
        self.state
            .committed_transactions
            .iter()
            .find(|(h, _)| h == &hash)
            .map(|(_, v)| v)
    }
}

#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug)]
pub enum EvmState {
    Committed(EvmBackend<Committed>),
    Incomming(EvmBackend<Incomming>),
}

#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum EvmPersistState {
    Committed(Committed),
    Incomming(Incomming), // Usually bank will never try to freeze banks with persist state.
}
impl EvmPersistState {
    pub fn last_root(&self) -> H256 {
        match self {
            EvmPersistState::Committed(c) => c.block.state_root,
            EvmPersistState::Incomming(i) => i.state_root,
        }
    }
}

impl Default for EvmPersistState {
    fn default() -> Self {
        Self::Incomming(Incomming::default())
    }
}

impl EvmState {
    /// Clears content of `path` directory and creates new empty `EvmState`
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self, anyhow::Error> {
        let evm_state = path.as_ref();
        if evm_state.is_dir() && evm_state.exists() {
            warn!("deleting existing state {}", evm_state.display());
            fs::remove_dir_all(evm_state)?;
            fs::create_dir(evm_state)?;
        }

        Self::load_from(evm_state, Incomming::default(), true)
    }

    /// Clears content of `evm_state` directory and creates new `EvmState` from genesis
    pub fn new_from_genesis(
        evm_state: impl AsRef<Path>,
        evm_genesis: impl AsRef<Path>,
        root_hash: H256,
        timestamp: u64,
        spv_compatibility: bool,
    ) -> Result<Self, anyhow::Error> {
        let evm_state = evm_state.as_ref();
        if evm_state.is_dir() && evm_state.exists() {
            warn!("deleting existing state {}", evm_state.display());
            fs::remove_dir_all(evm_state)?;
            fs::create_dir(evm_state)?;
        }

        KVS::restore_from(evm_genesis, evm_state)?;
        let version = if spv_compatibility {
            BlockVersion::VersionConsistentHashes
        } else {
            BlockVersion::InitVersion
        };

        Self::load_from(
            evm_state,
            Incomming::new(1, root_hash, H256::zero(), timestamp, version),
            true, // enable gc in newest version of genesis
        )
    }

    /// Ignores all unapplied updates.
    /// spv_compatibility - is oneway feature flag, if activated change current version from InitVersion to VersionConsistentHashes (dont change if version is feature).
    pub fn new_from_parent(&self, block_start_time: u64, spv_compatibility: bool) -> Self {
        let mut b = match self {
            EvmState::Committed(committed) => committed.next_incomming(block_start_time),
            EvmState::Incomming(incomming) => EvmBackend {
                state: incomming.state.new_update_time(block_start_time),
                kvs: incomming.kvs.clone(),
            },
        };

        if spv_compatibility {
            b.state.block_version.activate_spv_compatibility()
        }

        EvmState::Incomming(b)
    }
    // Request Unique reference to make sure caller own evm-state instance.
    pub fn register_slot(&mut self, slot: u64) -> Result<(), anyhow::Error> {
        Ok(self.kvs().register_slot(slot, self.last_root(), false)?)
    }
    // Mark changed state in slot.
    pub fn reregister_slot(&mut self, slot: u64) -> Result<(), anyhow::Error> {
        Ok(self.kvs().register_slot(slot, self.last_root(), true)?)
    }

    pub fn load_from<P: AsRef<Path>>(
        path: P,
        evm_persist_fields: impl Into<EvmPersistState>,
        gc_enabled: bool,
    ) -> Result<Self, anyhow::Error> {
        info!("Open EVM storage {}", path.as_ref().display());

        let kvs = KVS::open_persistent(path, gc_enabled)?;

        Ok(match evm_persist_fields.into() {
            EvmPersistState::Incomming(i) => EvmBackend::new(i, kvs).into(),
            EvmPersistState::Committed(c) => EvmBackend::new(c, kvs).into(),
        })
    }

    /// Make backup of current kvs storage.
    pub fn make_backup(&self) -> Result<PathBuf, anyhow::Error> {
        Ok(self.kvs().backup(None)?)
    }

    /// Convert current state into persist one.
    /// With persist state and database, one can load evm state back to memory.
    /// Consume self, so outer code should call `clone()`.
    /// Cloning KVS is cheap, and most work is in cloning state itself.
    pub fn save_state(self) -> EvmPersistState {
        match self {
            Self::Incomming(i) => i.state.into(),
            Self::Committed(c) => c.state.into(),
        }
    }

    pub fn kvs_references(&self) -> usize {
        Arc::strong_count(&self.kvs().db)
    }

    pub fn kvs(&self) -> &KVS {
        match self {
            Self::Committed(c) => c.kvs(),
            Self::Incomming(i) => i.kvs(),
        }
    }

    pub fn try_commit(
        &mut self,
        slot: u64,
        last_blockhash: [u8; 32],
    ) -> Result<Option<(H256, ChangedState)>, anyhow::Error> {
        match self {
            EvmState::Committed(committed) => Err(anyhow::Error::msg(format!(
                "Commit called on already committed block = {:?}.",
                committed.state
            ))),
            EvmState::Incomming(incomming) => {
                if incomming.state.is_active_changes() {
                    debug!(
                        "Found non-empty evm state, committing block = {}.",
                        incomming.state.block_number
                    );
                    let native_blockhash = H256::from_slice(&last_blockhash);
                    let changes = incomming.state.state_updates.clone();
                    let committed = incomming.take().commit_block(slot, native_blockhash);
                    let last_hash = committed.state.block.hash();
                    let mut new_backend = committed.into();
                    std::mem::swap(self, &mut new_backend);
                    Ok(Some((last_hash, changes)))
                } else {
                    Ok(None)
                }
            }
        }
    }

    /// Return block header if this state was committed before.
    pub fn get_block(&self) -> Option<Block> {
        match self {
            EvmState::Incomming(_) => None,
            EvmState::Committed(committed) => {
                let block = Block {
                    header: committed.state.block.clone(),
                    transactions: committed.state.committed_transactions.clone(),
                };
                Some(block)
            }
        }
    }

    // Count of processed transction since last commit, or previous if state is committed.
    pub fn processed_tx_len(&self) -> usize {
        match self {
            Self::Incomming(i) => i.state.executed_transactions.len(),
            Self::Committed(c) => c.state.committed_transactions.len(),
        }
    }
}

impl Default for Incomming {
    fn default() -> Self {
        Incomming {
            block_number: 0,
            state_root: empty_trie_hash(),
            last_block_hash: H256::zero(),
            state_updates: HashMap::new(),
            executed_transactions: Vec::new(),
            used_gas: 0,
            timestamp: 0,
            block_version: Default::default(),
        }
    }
}
impl Default for EvmBackend<Incomming> {
    fn default() -> Self {
        let kvs = KVS::create_temporary_gc().expect("Unable to create temporary storage");
        let state = Incomming::default();
        EvmBackend { state, kvs }
    }
}

/// NOTE: Only for testing purposes.
impl Default for EvmState {
    fn default() -> Self {
        EvmState::Incomming(EvmBackend::default())
    }
}

impl From<Incomming> for EvmPersistState {
    fn from(inc: Incomming) -> EvmPersistState {
        EvmPersistState::Incomming(inc)
    }
}

impl From<Committed> for EvmPersistState {
    fn from(comm: Committed) -> EvmPersistState {
        EvmPersistState::Committed(comm)
    }
}

impl From<EvmBackend<Incomming>> for EvmState {
    fn from(inc: EvmBackend<Incomming>) -> EvmState {
        EvmState::Incomming(inc)
    }
}

impl From<EvmBackend<Committed>> for EvmState {
    fn from(comm: EvmBackend<Committed>) -> EvmState {
        EvmState::Committed(comm)
    }
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        primitive_types::{H160, H256, U256},
        rand::{rngs::mock::StepRng, Rng},
        std::{
            collections::{BTreeMap, BTreeSet},
            str::FromStr,
        },
    };

    const RANDOM_INCR: u64 = 1; // TODO: replace by rand::SeedableRng implementor
    const MAX_SIZE: usize = 32; // Max size of test collections.

    const SEED: u64 = 1;

    impl<State> EvmBackend<State>
    where
        EvmBackend<State>: AccountProvider,
    {
        fn get_account(&self, address: H160) -> Option<Account> {
            self.kvs.typed_for(self.last_root()).get(&address)
        }
    }

    fn generate_account_by_seed(seed: u64) -> AccountState {
        let mut rng = StepRng::new(seed * RANDOM_INCR + seed, RANDOM_INCR);
        let nonce: [u8; 32] = rng.gen();
        let balance: [u8; 32] = rng.gen();

        let nonce = U256::from_little_endian(&nonce);
        let balance = U256::from_little_endian(&balance);
        let code_len: usize = rng.gen_range(0..=MAX_SIZE);
        let code = (0..code_len)
            .into_iter()
            .map(|_| rng.gen())
            .collect::<Vec<u8>>()
            .into();

        AccountState {
            nonce,
            balance,
            code,
        }
    }

    fn generate_accounts_state(seed: u64, accounts: &[H160]) -> BTreeMap<H160, AccountState> {
        let mut rng = StepRng::new(seed, RANDOM_INCR);
        let mut map = BTreeMap::new();
        for account in accounts {
            let seed = rng.gen();
            let state = generate_account_by_seed(seed);
            map.insert(*account, state);
        }
        map
    }

    fn generate_storage(seed: u64, accounts: &[H160]) -> BTreeMap<(H160, H256), H256> {
        let mut rng = StepRng::new(seed, RANDOM_INCR);

        let mut map = BTreeMap::new();

        for acc in accounts {
            let storage_len = rng.gen_range(0..=MAX_SIZE);
            for _ in 0..storage_len {
                let addr: [u8; 32] = rng.gen();
                let data: [u8; 32] = rng.gen();

                let addr = H256::from_slice(&addr);
                let data = H256::from_slice(&data);
                map.insert((*acc, addr), data);
            }
        }
        map
    }

    fn generate_accounts_addresses(seed: u64, count: usize) -> Vec<H160> {
        let mut rng = StepRng::new(seed, RANDOM_INCR);
        (0..count)
            .into_iter()
            .map(|_| H256::from_slice(&rng.gen::<[u8; 32]>()).into())
            .collect()
    }

    fn to_state_diff<K: Ord, Mv>(
        inserts: BTreeMap<K, Mv>,
        removes: BTreeSet<K>,
    ) -> BTreeMap<K, Option<Mv>> {
        let len = inserts.len() + removes.len();
        let mut map = BTreeMap::new();
        for insert in inserts {
            assert!(
                map.insert(insert.0, Some(insert.1)).is_none(),
                "double insert"
            );
        }

        for insert in removes {
            assert!(
                map.insert(insert, None).is_none(),
                "delete after insert is not allowed"
            );
        }
        assert_eq!(map.len(), len, "length differ from inserts + removes len");
        map
    }

    fn save_state(
        state: &mut EvmBackend<Incomming>,
        accounts: &BTreeMap<H160, Option<AccountState>>,
        storages: &BTreeMap<(H160, H256), Option<H256>>,
    ) {
        for (address, account_state) in accounts {
            if let Some(account_state) = account_state.as_ref().cloned() {
                state.set_account_state(*address, account_state);
            } else {
                state.remove_account(*address);
            }
        }

        let storages_per_account: HashMap<H160, HashMap<H256, H256>> =
            storages
                .iter()
                .fold(HashMap::new(), |mut s, ((address, index), expected)| {
                    s.entry(*address)
                        .or_default()
                        .insert(*index, expected.unwrap_or_default());
                    s
                });

        for (address, storages) in storages_per_account {
            state.ext_storage(address, storages);
        }
    }

    fn assert_state<State>(
        state: &EvmBackend<State>,
        accounts: &BTreeMap<H160, Option<AccountState>>,
        storage: &BTreeMap<(H160, H256), Option<H256>>,
    ) where
        EvmBackend<State>: AccountProvider,
    {
        for (address, expected) in accounts {
            let account_state = state.get_account_state(*address);

            assert_eq!(&account_state, expected);
        }

        let mut per_account_storage: HashMap<H160, HashMap<H256, H256>> = HashMap::new();

        for ((address, index), expected) in storage {
            per_account_storage
                .entry(*address)
                .or_default()
                .insert(*index, expected.unwrap_or_default());
        }

        for ((address, index), expected) in storage {
            assert_eq!(
                state.get_storage(*address, *index).as_ref(),
                expected.as_ref()
            )
        }
    }

    #[test]
    fn add_two_accounts_check_helpers() {
        let accounts = generate_accounts_addresses(SEED, 2);

        let storage = generate_storage(SEED, &accounts);
        let accounts_state = generate_accounts_state(SEED, &accounts);
        let storage_diff = to_state_diff(storage, BTreeSet::new());
        let accounts_state_diff = to_state_diff(accounts_state, BTreeSet::new());

        let mut evm_state = EvmBackend::default();

        assert_eq!(
            evm_state
                .get_account_state(H160::random())
                .unwrap_or_default()
                .balance,
            U256::zero(),
        );
        save_state(&mut evm_state, &accounts_state_diff, &storage_diff);

        assert_state(&evm_state, &accounts_state_diff, &storage_diff);
    }

    #[test]
    fn fork_add_remove_accounts() {
        let accounts = generate_accounts_addresses(SEED, 10);

        let storage = generate_storage(SEED, &accounts);
        let accounts_state = generate_accounts_state(SEED, &accounts);
        let storage_diff = to_state_diff(storage, BTreeSet::new());
        let accounts_state_diff = to_state_diff(accounts_state, BTreeSet::new());

        let mut evm_state = EvmBackend::default();

        save_state(&mut evm_state, &accounts_state_diff, &storage_diff);
        let committed = evm_state.commit_block(0, Default::default());

        assert_state(&committed, &accounts_state_diff, &storage_diff);

        assert_state(&committed, &accounts_state_diff, &storage_diff);

        let mut new_evm_state = committed.next_incomming(0);
        assert_state(&new_evm_state, &accounts_state_diff, &storage_diff);

        let new_accounts = generate_accounts_addresses(SEED + 1, 2);
        let new_accounts_state = generate_accounts_state(SEED + 1, &new_accounts);
        let removed_accounts: BTreeSet<_> = accounts[0..2].iter().copied().collect();
        let new_accounts_state_diff = to_state_diff(new_accounts_state, removed_accounts);

        save_state(
            &mut new_evm_state,
            &new_accounts_state_diff,
            &BTreeMap::new(),
        );

        assert_state(&new_evm_state, &new_accounts_state_diff, &BTreeMap::new());
    }

    #[test]
    fn reads_the_same_after_consequent_dumps() {
        use std::ops::Bound::Included;
        let _ = simple_logger::SimpleLogger::new()
            .with_utc_timestamps()
            .env()
            .init();

        const N_VERSIONS: usize = 10;
        const ACCOUNTS_PER_VERSION: usize = 10;

        let accounts = generate_accounts_addresses(SEED, ACCOUNTS_PER_VERSION * N_VERSIONS);
        let accounts_state = generate_accounts_state(SEED, &accounts);
        let accounts_storage = generate_storage(SEED, &accounts);

        let mut evm_state = EvmBackend::default();

        for accounts_per_version in accounts.chunks(N_VERSIONS) {
            for account in accounts_per_version {
                log::debug!("working with account: {:?}", account);

                let account_state = accounts_state[account].clone();

                evm_state.set_account_state(*account, account_state);

                let storage: HashMap<H256, H256> = accounts_storage
                    .range((
                        Included((*account, H256::zero())),
                        Included((*account, H256::repeat_byte(u8::MAX))),
                    ))
                    .map(|((address, index), data)| {
                        assert_eq!(account, address);
                        (*index, *data)
                    })
                    .collect();

                evm_state.ext_storage(*account, storage);
            }

            let committed = evm_state.commit_block(0, Default::default());
            evm_state = committed.next_incomming(0);
        }

        let accounts_state_diff = to_state_diff(accounts_state, BTreeSet::new());
        let accounts_storage_diff = to_state_diff(accounts_storage, BTreeSet::new());

        assert_state(&evm_state, &accounts_state_diff, &accounts_storage_diff);
    }

    #[test]
    fn lookups_thru_forks() {
        let _ = simple_logger::SimpleLogger::new()
            .with_utc_timestamps()
            .init();

        let mut state = EvmBackend::default();

        let accounts = generate_accounts_addresses(SEED, 1);
        let account_states = generate_accounts_state(SEED, &accounts);

        let account = accounts.first().copied().unwrap();
        let account_state = account_states[&account].clone();

        state.set_account_state(account, account_state.clone());

        for _ in 0..42 {
            let committed = state.take().commit_block(0, Default::default());
            state = committed.next_incomming(0);
        }

        let recv_state = state.get_account_state(account).unwrap();
        assert_eq!(recv_state, account_state);
    }

    #[test]
    fn it_handles_accounts_state_get_set_expectations() {
        let _ = simple_logger::SimpleLogger::new()
            .with_utc_timestamps()
            .init();

        let mut state = EvmBackend::default();

        let addr = H160::random();
        assert_eq!(state.get_account_state(addr), None);

        let new_state = AccountState {
            nonce: U256::from(1),
            ..Default::default()
        };

        state.set_account_state(addr, new_state.clone());
        assert_eq!(state.get_account_state(addr), Some(new_state.clone()));

        let committed = state.take().commit_block(0, Default::default());
        state = committed.next_incomming(0);

        assert_eq!(state.get_account_state(addr), Some(new_state.clone()));

        let another_addr = H160::random();

        assert_ne!(addr, another_addr);
        assert_eq!(state.get_account_state(another_addr), None);

        state.set_account_state(
            addr,
            AccountState {
                nonce: U256::from(2),
                ..new_state
            },
        );

        state.set_account_state(
            another_addr,
            AccountState {
                nonce: U256::from(1),
                ..Default::default()
            },
        );

        assert_eq!(
            state.get_account_state(addr).map(|acc| acc.nonce),
            Some(U256::from(2))
        );
        assert_eq!(
            state.get_account_state(another_addr).map(|acc| acc.nonce),
            Some(U256::from(1))
        );

        let state = state.commit_block(0, Default::default());

        assert_eq!(
            state.get_account_state(addr).map(|acc| acc.nonce),
            Some(U256::from(2))
        );
        assert_eq!(
            state.get_account_state(another_addr).map(|acc| acc.nonce),
            Some(U256::from(1))
        );
    }

    #[test]
    // https://github.com/openethereum/parity-ethereum/blob/v2.7.2-stable/ethcore/account-state/src/account.rs#L667
    fn it_checks_storage_at() {
        let address = H160::zero();

        let account_state = AccountState {
            nonce: 0.into(),
            balance: 69.into(),
            code: Code::empty(),
        };

        let storage_mod = Some((H256::zero(), H256::from_low_u64_be(0x1234)));

        let mut state = EvmBackend::default();
        state.set_account_state(address, account_state);
        state.ext_storage(address, storage_mod);

        let committed = state.take().commit_block(0, Default::default());
        let account = committed.get_account(address).unwrap();

        assert_eq!(
            committed.get_storage(address, H256::zero()),
            Some(H256::from_low_u64_be(0x1234))
        );
        assert_eq!(
            committed.get_storage(address, H256::from_low_u64_be(0x01)),
            None
        );
        assert_eq!(
            account.storage_root,
            H256::from_str("c57e1afb758b07f8d2c8f13a3b6e44fa5ff94ab266facc5a4fd3f062426e50b2")
                .unwrap()
        );
    }

    #[test]
    // https://github.com/openethereum/parity-ethereum/blob/v2.7.2-stable/ethcore/account-state/src/account.rs#L705
    fn it_checks_commit_storage() {
        let address = H160::zero();

        let account_state = AccountState {
            nonce: 0.into(),
            balance: 69.into(),
            code: Code::empty(),
        };

        let storage_mod = Some((H256::from_low_u64_be(0), H256::from_low_u64_be(0x1234)));

        let mut state = EvmBackend::default();
        state.set_account_state(address, account_state);
        state.ext_storage(address, storage_mod);

        let committed = state.take().commit_block(0, Default::default());
        let account = committed.get_account(address).unwrap();

        assert_eq!(
            account.storage_root,
            H256::from_str("c57e1afb758b07f8d2c8f13a3b6e44fa5ff94ab266facc5a4fd3f062426e50b2")
                .unwrap()
        );
    }

    #[test]
    // https://github.com/openethereum/parity-ethereum/blob/v2.7.2-stable/ethcore/account-state/src/account.rs#L716
    fn it_checks_commit_remove_commit_storage() {
        let address = H160::zero();

        let account_state = AccountState {
            nonce: 0.into(),
            balance: 69.into(),
            code: Code::empty(),
        };

        let mut state = EvmBackend::default();
        state.set_account_state(address, account_state);

        state.ext_storage(
            address,
            Some((H256::from_low_u64_be(0), H256::from_low_u64_be(0x1234))),
        );
        let committed = state.take().commit_block(0, Default::default());
        state = committed.next_incomming(0);
        state.ext_storage(
            address,
            Some((H256::from_low_u64_be(1), H256::from_low_u64_be(0x1234))),
        );
        let committed = state.take().commit_block(0, Default::default());
        state = committed.next_incomming(0);

        state.ext_storage(
            address,
            Some((H256::from_low_u64_be(1), H256::from_low_u64_be(0))),
        );
        let committed = state.take().commit_block(0, Default::default());

        let account = committed.get_account(address).unwrap();

        assert_eq!(
            account.storage_root,
            H256::from_str("c57e1afb758b07f8d2c8f13a3b6e44fa5ff94ab266facc5a4fd3f062426e50b2")
                .unwrap()
        );
    }
}
