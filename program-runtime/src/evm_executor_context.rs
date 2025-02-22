use {
    dashmap::{
        mapref::one::{MappedRef, MappedRefMut, Ref, RefMut},
        DashMap,
    },
    evm_state::{AccountProvider, EvmBackend, Executor, BURN_GAS_PRICE, TEST_CHAIN_ID, U256},
    log::{debug, warn},
    serde::{
        de::{SeqAccess, Visitor},
        ser::SerializeTuple as _,
        Deserialize, Deserializer, Serialize, Serializer,
    },
    solana_sdk::clock::Slot,
    std::{
        cell::RefCell, collections::HashMap, fmt, marker::PhantomData, ops::Deref, rc::Rc,
        sync::RwLock,
    },
};
// use solana_program_runtime::evm_executor_context::{BlockHashEvm, MAX_EVM_BLOCKHASHES};
// use solana_runtime::{bank::log_enabled, message_processor::ProcessedMessageInfo};

pub const MAX_EVM_BLOCKHASHES: usize = 256;
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct BlockHashEvm {
    #[serde(with = "BlockHashEvm")]
    hashes: [evm_state::H256; MAX_EVM_BLOCKHASHES],
}

impl BlockHashEvm {
    pub fn new() -> BlockHashEvm {
        BlockHashEvm {
            hashes: [evm_state::H256::zero(); MAX_EVM_BLOCKHASHES],
        }
    }
    pub fn get_hashes(&self) -> &[evm_state::H256; MAX_EVM_BLOCKHASHES] {
        &self.hashes
    }

    pub fn insert_hash(&mut self, hash: evm_state::H256) {
        let new_hashes = self.hashes;
        self.hashes[0..MAX_EVM_BLOCKHASHES - 1]
            .copy_from_slice(&new_hashes[1..MAX_EVM_BLOCKHASHES]);
        self.hashes[MAX_EVM_BLOCKHASHES - 1] = hash
    }

    fn deserialize<'de, D>(
        deserializer: D,
    ) -> Result<[evm_state::H256; MAX_EVM_BLOCKHASHES], D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ArrayVisitor<T> {
            element: PhantomData<T>,
        }
        impl<'de, T> Visitor<'de> for ArrayVisitor<T>
        where
            T: Default + Copy + Deserialize<'de>,
        {
            type Value = [T; MAX_EVM_BLOCKHASHES];

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str(concat!("an array of length ", 256))
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<[T; MAX_EVM_BLOCKHASHES], A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut arr = [T::default(); MAX_EVM_BLOCKHASHES];
                for (i, item) in arr.iter_mut().enumerate().take(MAX_EVM_BLOCKHASHES) {
                    *item = seq
                        .next_element()?
                        .ok_or_else(|| serde::de::Error::invalid_length(i, &self))?;
                }
                Ok(arr)
            }
        }

        let visitor = ArrayVisitor {
            element: PhantomData,
        };
        deserializer.deserialize_tuple(MAX_EVM_BLOCKHASHES, visitor)
    }

    fn serialize<S>(
        data: &[evm_state::H256; MAX_EVM_BLOCKHASHES],
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_tuple(data.len())?;
        for elem in &data[..] {
            seq.serialize_element(elem)?;
        }
        seq.end()
    }
}

impl Default for BlockHashEvm {
    fn default() -> Self {
        Self::new()
    }
}

pub type ChainID = u64;
pub type ChangedList = Option<(evm_state::H256, evm_state::ChangedState)>;

#[derive(Debug, Default)]
pub struct EvmChain {
    pub evm_state: evm_state::EvmState,
    pub evm_changed_list: ChangedList,
}

impl EvmChain {
    pub fn from_main_chain(main: &MainChain) -> Self {
        let evm_state = evm_state::EvmBackend {
            kvs: main.evm_state.read().unwrap().kvs().clone(),
            state: evm_state::Incomming::genesis_from_state(evm_state::empty_trie_hash()),
        };

        Self {
            evm_state: evm_state.into(),
            evm_changed_list: None,
        }
    }
}

//TODO(L): do we need clone?
impl Clone for EvmChain {
    fn clone(&self) -> Self {
        Self {
            evm_state: self.evm_state.clone(),
            evm_changed_list: self.evm_changed_list.clone(),
        }
    }
}

#[derive(Debug)]
pub struct MainChain {
    pub chain_id: ChainID,
    pub evm_state: RwLock<evm_state::EvmState>,
    pub evm_changed_list: RwLock<ChangedList>,
    pub evm_blockhashes: RwLock<BlockHashEvm>,
}

impl Clone for MainChain {
    fn clone(&self) -> Self {
        Self {
            chain_id: self.chain_id.clone(),
            evm_state: RwLock::new(self.evm_state.read().unwrap().clone()),
            evm_changed_list: RwLock::new(self.evm_changed_list.read().unwrap().clone()),
            evm_blockhashes: RwLock::new(self.evm_blockhashes.read().unwrap().clone()),
        }
    }
}

impl Default for MainChain {
    fn default() -> Self {
        Self {
            chain_id: TEST_CHAIN_ID,
            evm_state: RwLock::new(evm_state::EvmState::default()),
            evm_changed_list: RwLock::new(None),
            evm_blockhashes: RwLock::new(BlockHashEvm::default()),
        }
    }
}

impl MainChain {
    /// EVM Chain ID
    pub fn id(&self) -> ChainID {
        self.chain_id
    }

    pub fn set_id(&mut self, id: ChainID) {
        self.chain_id = id;
    }
    /// EVM Blockhashes Raw Lock
    pub fn blockhashes_raw<'a>(&'a self) -> &'a RwLock<BlockHashEvm> {
        &self.evm_blockhashes
    }

    /// EVM Blockhashes Read-Only Lock Guard
    pub fn blockhashes<'a>(&'a self) -> std::sync::RwLockReadGuard<'a, BlockHashEvm> {
        self.evm_blockhashes
            .read()
            .expect("EVM Blockhashes RwLock was poisoned")
    }

    // TODO(L): do not expose WriteGuard, do setter
    /// EVM Blockhashes Write Lock Guard
    pub fn blockhashes_write<'a>(&'a self) -> std::sync::RwLockWriteGuard<'a, BlockHashEvm> {
        self.evm_blockhashes
            .write()
            .expect("EVM Blockhashes RwLock was poisoned")
    }

    /// EVM State Read-Only Lock Guard
    pub fn state<'a>(&'a self) -> std::sync::RwLockReadGuard<'a, evm_state::EvmState> {
        self.evm_state
            .read()
            .expect("EVM State RwLock was poisoned")
    }

    /// EVM State Write Lock Guard
    pub fn state_write<'a>(&'a self) -> std::sync::RwLockWriteGuard<'a, evm_state::EvmState> {
        self.evm_state
            .write()
            .expect("EVM State RwLock was poisoned")
    }

    /// EVM Blockhashes Read-Only Lock Guard
    pub fn changed_list<'a>(&'a self) -> std::sync::RwLockReadGuard<'a, ChangedList> {
        self.evm_changed_list
            .read()
            .expect("EVM Blockhashes RwLock was poisoned")
    }

    // TODO(L): do not expose WriteGuard, do setter
    /// EVM Blockhashes Write Lock Guard
    pub fn changed_list_write<'a>(&'a self) -> std::sync::RwLockWriteGuard<'a, ChangedList> {
        self.evm_changed_list
            .write()
            .expect("EVM Blockhashes RwLock was poisoned")
    }
}

#[derive(Debug, Default, Clone)]
pub struct EvmBank {
    pub(crate) main_chain: MainChain,
    pub(crate) side_chains: DashMap<ChainID, EvmChain>,
}

impl EvmBank {
    pub fn new(
        evm_chain_id: ChainID,
        evm_blockhashes: BlockHashEvm,
        evm_state: evm_state::EvmState,
        side_chains: HashMap<ChainID, evm_state::EvmState>,
    ) -> Self {
        Self {
            main_chain: MainChain {
                chain_id: evm_chain_id,
                evm_blockhashes: RwLock::new(evm_blockhashes),
                evm_state: RwLock::new(evm_state),
                evm_changed_list: RwLock::new(None),
            },
            side_chains: side_chains
                .into_iter()
                .map(|(k, v)| {
                    (
                        k,
                        EvmChain {
                            evm_state: v,
                            evm_changed_list: None,
                        },
                    )
                })
                .collect(),
        }
    }
    pub fn new_with_state(evm_state: evm_state::EvmState) -> Self {
        Self {
            main_chain: MainChain {
                evm_state: RwLock::new(evm_state),
                ..Default::default()
            },
            side_chains: DashMap::new(),
        }
    }

    pub fn kvs(&self) -> evm_state::Storage {
        self.main_chain.state().kvs().clone()
    }

    pub fn main_chain(&self) -> &MainChain {
        &self.main_chain
    }

    pub fn side_chains(&self) -> &DashMap<ChainID, EvmChain> {
        &self.side_chains
    }

    pub fn subchain_roots(&self) -> Vec<evm_state::H256> {
        let mut subchains_roots: Vec<_> = self
            .side_chains
            .iter()
            .map(|c| c.evm_state.last_root())
            .collect();
        subchains_roots.sort();
        subchains_roots
    }

    // Return state of subchain, if not exist, creates new default
    pub fn chain_state(&self, chain_id: ChainID) -> Ref<u64, EvmChain> {
        if chain_id == self.main_chain.id() {
            panic!("Main chain state should be accessed via main_chain() method");
        }
        if let Some(c) = self.side_chains.get(&chain_id) {
            return c;
        }
        self.side_chains
            .insert(chain_id, EvmChain::from_main_chain(&self.main_chain));

        self.side_chains
            .get(&chain_id)
            .expect("Chain should be inserted")
    }
    // Return state of subchain, if not exist, creates new default
    pub fn chain_state_write(&self, chain_id: ChainID) -> RefMut<u64, EvmChain> {
        if chain_id == self.main_chain.id() {
            panic!("Main chain state should be accessed via main_chain() method");
        }
        if let Some(c) = self.side_chains.get_mut(&chain_id) {
            return c;
        }
        self.side_chains
            .insert(chain_id, EvmChain::from_main_chain(&self.main_chain));

        self.side_chains
            .get_mut(&chain_id)
            .expect("Chain should be inserted")
    }

    pub fn main_chain_mut(&mut self) -> &mut MainChain {
        &mut self.main_chain
    }
}

impl PartialEq for EvmChain {
    fn eq(&self, other: &Self) -> bool {
        let last_root_self = self.evm_state.last_root();
        let last_root_other = other.evm_state.last_root();

        last_root_self == last_root_other
    }
}
impl PartialEq for MainChain {
    fn eq(&self, other: &Self) -> bool {
        self.chain_id == other.chain_id && self.state().last_root() == other.state().last_root()
    }
}
impl PartialEq for EvmBank {
    fn eq(&self, other: &Self) -> bool {
        if self.main_chain != other.main_chain || self.side_chains.len() != other.side_chains.len()
        {
            return false;
        }
        for side in self.side_chains.iter() {
            let chain_id = side.key();
            let root = side.value().evm_state.last_root();
            if !other
                .side_chains
                .get(chain_id)
                .map(|other_chain| root == other_chain.evm_state.last_root())
                .unwrap_or_default()
            {
                return false;
            }
        }
        true
    }
}

// struct ExecutorContext {
//    ...
// };
// impl ExecutorContext {
//     pub fn get_executor(&mut self, chain_id: ChainID) -> Option<Executor>;
//     pub fn destruct(self) -> Vec<(ChainId, EvmBackend)>;
// }

// deserilalizer: fn (Account) -> ChainId;
// executor_factory: fn (ChainId) -> Option<Executor>;
// executor_getter: fn (Account) -> Option<Executor> = deserializer * executor_factory

type EvmPatch = evm_state::EvmBackend<evm_state::Incomming>;

pub enum EvmExecutorContextType {
    Execution,
    Simulation,
}

pub enum PatchStrategy {
    ApplyFailed,
    SetNew,
}
impl PatchStrategy {
    pub fn success(&self, new_error_handling: bool) -> bool {
        new_error_handling && matches!(self, PatchStrategy::SetNew)
    }
}

pub type Chain = Option<ChainID>;
//
// 1. Init state: in solana::Bank::evm -> EvmExecutorContext::new()
// 2. State for tx_batch = evm_patch::new(init_state)
// 3. intermediate state for one tx = evm_executor::new(evm_patch)
pub struct EvmExecutorContext {
    // TODO(L): share with bank
    evm: EvmBank,

    // None chain_id = main chain
    evm_patches: HashMap<Chain, EvmPatch>,

    active_executor: Option<(Chain, Rc<RefCell<Executor>>)>,

    // extract into struct
    feature_set: evm_state::executor::FeatureSet,
    unix_timestamp: i64,
    bank_slot: Slot,

    // bank data used for logging
    is_bank_frozen: bool,
    is_evm_burn_fee_activated: bool,

    // used for cleanup
    // TODO(L): hardcode this flag to `true`
    pub evm_new_error_handling: bool,
    clear_logs: bool,

    // defines default state getter
    context_type: EvmExecutorContextType,
}

pub type RefCellLocked = ();

pub type SubchainHashes = Box<[evm_state::H256; MAX_EVM_BLOCKHASHES]>;

pub enum ChainParam {
    GetMainChain,
    CreateSubchain {
        chain_id: ChainID,
    },
    GetSubchain {
        chain_id: ChainID,
        subchain_hashes: SubchainHashes,
        gas_price: U256,
    },
}
impl ChainParam {
    pub fn is_main(&self) -> bool {
        matches!(self, ChainParam::GetMainChain)
    }

    // Return None if main chain
    pub fn chain_id(&self) -> Chain {
        match self {
            ChainParam::GetMainChain => None,
            ChainParam::CreateSubchain { chain_id } => Some(*chain_id),
            ChainParam::GetSubchain { chain_id, .. } => Some(*chain_id),
        }
    }

    pub fn min_gas_price(&self, is_evm_burn_fee_activated: bool) -> U256 {
        if !is_evm_burn_fee_activated {
            return 0.into(); // pre beta velas behaviour
        }
        match self {
            ChainParam::GetSubchain { gas_price, .. } => *gas_price,
            _ => BURN_GAS_PRICE.into(),
        }
    }
}

impl EvmExecutorContext {
    pub fn new(
        evm: EvmBank,
        feature_set: evm_state::executor::FeatureSet,
        // NOTE: available from InvokeContext
        unix_timestamp: i64,
        bank_slot: Slot,
        is_bank_frozen: bool,
        is_evm_burn_fee_activated: bool,
        evm_new_error_handling: bool,
        clear_logs: bool,
        context_type: EvmExecutorContextType,
    ) -> Self {
        Self {
            evm,
            evm_patches: HashMap::new(),
            feature_set,
            unix_timestamp,
            bank_slot,
            is_bank_frozen,
            is_evm_burn_fee_activated,
            evm_new_error_handling,
            clear_logs,
            context_type,
            active_executor: None,
        }
    }
    pub fn get_main_chain_id(&self) -> ChainID {
        self.evm.main_chain().id()
    }
    pub fn get_slot(&self) -> u64 {
        self.bank_slot
    }

    pub fn get_executor(&mut self, params: ChainParam) -> Option<Rc<RefCell<Executor>>> {
        let chain_id = params.chain_id();

        if self.active_executor.is_some() {
            if self.active_executor.as_ref().unwrap().0 != chain_id {
                warn!(
                    "Executor already created for chain_id={:?}, ignoring.",
                    self.active_executor.as_ref().unwrap().0
                );

                // return Err(MultipleExecutors)
                return None;
            }
            return self.active_executor.clone().map(|v| v.1);
        }

        // append to old patch if exist, or create new, from existing evm state
        // TODO(L): Can be inlined?
        let patch = self.evm_patches.remove(&chain_id);

        if patch.is_some() && matches!(params, ChainParam::CreateSubchain { .. }) {
            // return Err executor already exist
            return None;
        }
        let patch = patch.or_else(|| self.get_evm_state(&params));

        let last_hashes = self.get_last_hashes(&params); // NOTE: 8kb

        if let Some(state) = patch {
            let evm_executor = evm_state::Executor::with_config(
                state.clone(),
                evm_state::ChainContext::new(last_hashes),
                evm_state::EvmConfig::new(
                    params
                        .chain_id()
                        .unwrap_or_else(|| self.evm.main_chain().id()),
                    params.min_gas_price(self.is_evm_burn_fee_activated),
                ),
                self.feature_set,
            );

            let evm_executor = Rc::new(RefCell::new(evm_executor));
            log::trace!("Executor created for chain_id={:?}", chain_id);
            self.evm_patches.insert(chain_id, state);
            self.active_executor = Some((chain_id, evm_executor.clone()));

            Some(evm_executor)
        } else {
            None
        }
    }

    // TODO: move params by value?
    fn get_last_hashes(&self, params: &ChainParam) -> [evm_state::H256; MAX_EVM_BLOCKHASHES] {
        match params {
            ChainParam::CreateSubchain { chain_id: _ } => {
                [evm_state::H256::zero(); MAX_EVM_BLOCKHASHES]
            }
            ChainParam::GetSubchain {
                chain_id: _,
                gas_price: _,
                subchain_hashes,
            } => (subchain_hashes.deref()).clone(),
            ChainParam::GetMainChain => self.evm.main_chain().blockhashes().get_hashes().clone(),
        }
    }

    fn get_evm_state_from_lock(
        &self,
        state: impl Deref<Target = evm_state::EvmState>,
    ) -> Option<evm_state::EvmBackend<evm_state::Incomming>> {
        let lock = match self.context_type {
            EvmExecutorContextType::Execution => self.take_evm_state_cloned(state),
            EvmExecutorContextType::Simulation => self.take_evm_state_for_simulation(state),
        };
        if lock.is_none() {
            warn!("Executing evm transaction on already locked bank.");
        }
        lock
    }

    fn get_evm_state(
        &self,
        params: &ChainParam,
    ) -> Option<evm_state::EvmBackend<evm_state::Incomming>> {
        match params {
            ChainParam::GetSubchain { chain_id, .. } => {
                let subchain_state = self
                    .evm
                    .side_chains
                    .get(chain_id)
                    .map(|c| c.map(|s| &s.evm_state))
                    .and_then(|s| self.get_evm_state_from_lock(s));
                if subchain_state.is_none() {
                    warn!("Can't create new executor, for non-initialized subchain.");
                }
                subchain_state
            }
            ChainParam::GetMainChain => self.get_evm_state_from_lock(self.evm.main_chain().state()),

            ChainParam::CreateSubchain { chain_id } => {
                let subchain_state = self
                    .evm
                    .side_chains
                    .get(chain_id)
                    .map(|c| c.map(|s| &s.evm_state))
                    .and_then(|s| self.get_evm_state_from_lock(s));

                if subchain_state.is_some() {
                    warn!("Can't get executor, for already initialized subchain.");
                    return None;
                }
                // recreate from main chain
                let main_chain_state = self.get_evm_state_from_lock(self.evm.main_chain().state());

                // Use main_chain kvs for new chain, but set empty trie hash root
                // TODO(L): new constructor EvmBackend::new_subchain(..)
                main_chain_state.map(|s| EvmBackend {
                    kvs: s.kvs,
                    state: evm_state::Incomming::genesis_from_state(evm_state::empty_trie_hash()),
                })
            }
        }
    }

    // for test purposes
    pub fn take_executor(&mut self) -> Option<(Option<ChainID>, Executor)> {
        self.active_executor
            .take()
            .and_then(|rc| Rc::try_unwrap(rc.1).ok().map(|i| (rc.0, i.into_inner())))
    }

    pub fn cleanup(&mut self, strategy: PatchStrategy) {
        let (chain_id, executor): (_, Executor) = {
            let Some((chain_id, executor)) = self.active_executor.take() else {
                if strategy.success(self.evm_new_error_handling) {
                    log::error!("Executor was not created, on cleanup, but execution success.");
                }
                return;
            };
            (
                chain_id,
                Rc::try_unwrap(executor)
                    .map(|e| e.into_inner())
                    .expect("Reference to Active Executor was not freed"),
            )
        };

        let new_patch = executor.deconstruct();
        let mut old_patch = self
            .evm_patches
            .remove(&chain_id)
            .expect("Evm patch should exist, on transaction execution.");

        let before = old_patch.last_root();
        let after = new_patch.last_root();

        log::trace!(
            "Updating EVM patches, hash_before = {:?}, after = {:?}",
            before,
            after
        );
        // On error save only transaction and increase nonce.
        match strategy {
            PatchStrategy::ApplyFailed => {
                old_patch.apply_failed_update(&new_patch, self.clear_logs);
            }
            PatchStrategy::SetNew => {
                old_patch = new_patch;
            }
        }
        self.evm_patches.insert(chain_id, old_patch);
    }

    pub fn deconstruct_to_patches(self) -> HashMap<Option<ChainID>, EvmPatch> {
        self.evm_patches.clone()
    }

    fn take_evm_state_cloned(
        &self,
        state: impl Deref<Target = evm_state::EvmState>,
    ) -> Option<evm_state::EvmBackend<evm_state::Incomming>> {
        match &*state {
            evm_state::EvmState::Incomming(i) => Some(i.clone()),
            evm_state::EvmState::Committed(_) => {
                warn!(
                    "Take evm after freeze, bank_slot={}, bank_is_freeze={}",
                    self.bank_slot, self.is_bank_frozen
                );
                // Return None, so this transaction will fail to execute,
                // this transaction will be marked as retriable after bank realise that PoH is reached it's max height.
                None
            }
        }
    }

    fn take_evm_state_for_simulation(
        &self,
        state: impl Deref<Target = evm_state::EvmState>,
    ) -> Option<evm_state::EvmBackend<evm_state::Incomming>> {
        match state.deref() {
            evm_state::EvmState::Incomming(i) => Some(i.clone()),
            evm_state::EvmState::Committed(c) => {
                debug!(
                    "Creating cloned evm state for simulation, bank_slot={}, bank_is_freeze={}",
                    self.bank_slot, self.is_bank_frozen
                );
                Some(c.next_incomming(self.unix_timestamp as u64))
            }
        }
    }
}

pub trait StateExt<'a> {
    type MapRef<'b, T: 'b + 'a>
    where
        'a: 'b;
    fn state(self) -> Self::MapRef<'a, evm_state::EvmState>;
}
impl<'a, K: Eq + std::hash::Hash + 'a> StateExt<'a> for Ref<'a, K, EvmChain> {
    type MapRef<'b, T: 'b + 'a> = MappedRef<'b, K, EvmChain, T>
    where
        'a: 'b;
    fn state(self) -> Self::MapRef<'a, evm_state::EvmState> {
        self.map(|c| &c.evm_state)
    }
}

impl<'a, K: Eq + std::hash::Hash + 'a> StateExt<'a> for RefMut<'a, K, EvmChain> {
    type MapRef<'b, T: 'b + 'a> = MappedRefMut<'b, K, EvmChain, T>
    where
        'a: 'b;
    fn state(self) -> Self::MapRef<'a, evm_state::EvmState> {
        self.map(|c| &mut c.evm_state)
    }
}

impl<'a> StateExt<'a> for &'a EvmChain {
    type MapRef<'b, T: 'b + 'a> = &'b T
    where
        'a: 'b;

    fn state(self) -> Self::MapRef<'a, evm_state::EvmState> {
        &self.evm_state
    }
}
#[cfg(test)]
mod tests {
    use {super::*, evm_state::H256};

    #[test]
    fn test_evm_blockhaheshes() {
        let mut blockhash_queue = BlockHashEvm::new();
        assert_eq!(
            blockhash_queue.get_hashes(),
            &[H256::zero(); MAX_EVM_BLOCKHASHES]
        );
        let hash1 = H256::repeat_byte(1);
        blockhash_queue.insert_hash(hash1);
        for hash in &blockhash_queue.get_hashes()[..MAX_EVM_BLOCKHASHES - 1] {
            assert_eq!(*hash, H256::zero())
        }
        assert_eq!(blockhash_queue.get_hashes()[MAX_EVM_BLOCKHASHES - 1], hash1);

        for i in 0..MAX_EVM_BLOCKHASHES {
            let hash1 = H256::repeat_byte(i as u8);
            blockhash_queue.insert_hash(hash1)
        }

        for (i, hash) in blockhash_queue.get_hashes()[..MAX_EVM_BLOCKHASHES]
            .iter()
            .enumerate()
        {
            let hash1 = H256::repeat_byte(i as u8);
            assert_eq!(*hash, hash1)
        }
    }
}
