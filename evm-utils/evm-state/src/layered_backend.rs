use std::{
    any::type_name, borrow::Cow, collections::BTreeMap, fmt::Debug, marker::PhantomData,
    ops::Deref, path::Path,
};

use log::*;

use evm::backend::Log;

use crate::{
    mb_value::MaybeValue,
    persistent_types,
    storage::{PersistentAssoc, Result as StorageResult, VersionedStorage},
    transactions::TransactionReceipt,
    types::*,
};

pub type Storage = VersionedStorage<Slot>;

// Store every account storage at single place, to use power of versioned map.
// This allows us to save only changed data.
persistent_types! {
    Accounts in "accounts" => H160 : AccountState,
    AccountsStorage in "accounts_storage" => (H160, H256) : H256,
    TransactionReceipts in "txs_receipts" => H256 : TransactionReceipt,
    TransactionsInBlock in "txs_in_block" => Slot : Vec<H256>, // TODO: Key is Slot or U256?
}

pub(crate) struct Layer<M: PersistentAssoc>
where
    M::Key: Ord,
{
    map: BTreeMap<M::Key, MaybeValue<M::Value>>,
    is_frozen: bool,
    _type: PhantomData<M>,
}

impl<M> Layer<M>
where
    M: PersistentAssoc,
    M::Key: Ord,
{
    pub fn empty() -> Self {
        Self {
            map: BTreeMap::new(),
            is_frozen: false,
            _type: PhantomData,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    pub fn insert(&mut self, key: M::Key, value: M::Value)
    where
        M::Key: Debug,
        M::Value: Debug,
    {
        assert!(
            !self.is_frozen,
            "Modification of frozen layer is prohibited"
        );
        trace!(
            "layer :: {} inserts {:?} => {:?}",
            type_name::<M>(),
            key,
            value
        );
        self.map.insert(key, MaybeValue::Value(value));
    }

    pub fn remove(&mut self, key: M::Key)
    where
        M::Key: Debug,
    {
        assert!(
            !self.is_frozen,
            "Modification of frozen layer is prohibited"
        );

        trace!("layer :: {} removes {:?}", type_name::<M>(), key);
        self.map.insert(key, MaybeValue::Removed);
    }

    fn freeze(&mut self) {
        self.is_frozen = true;
    }

    fn dump_into(
        &mut self,
        storage: impl Deref<Target = Storage>,
        version: Slot,
    ) -> StorageResult<()>
    where
        M::Key: Ord + Copy + Debug,
        M::Value: Clone + Debug,
    {
        let storage = storage.deref().typed::<M>();

        for (key, value) in std::mem::replace(self, Self::empty()).map {
            debug!(
                "{}: {:?} {:?} migrates from memory into storage",
                version, key, &value
            );

            storage.insert_with(version, key, value)?;
        }

        Ok(())
    }
}

impl<M: PersistentAssoc> Clone for Layer<M>
where
    M::Key: Clone + Ord,
    M::Value: Clone,
{
    fn clone(&self) -> Self {
        Self {
            map: self.map.clone(),
            is_frozen: false,
            _type: PhantomData,
        }
    }
}

#[derive(Clone)] // TODO: Debug
pub struct EvmState {
    pub(crate) current_slot: Slot,
    pub(crate) previous_slot: Option<Slot>,

    pub(crate) accounts: Layer<Accounts>,
    pub(crate) accounts_storage: Layer<AccountsStorage>,
    pub(crate) txs_receipts: Layer<TransactionReceipts>,
    pub(crate) txs_in_block: Layer<TransactionsInBlock>,
    pub(crate) logs: Vec<Log>, // TODO: migrate into storage

    pub storage: Storage,
}

// TODO: move this logic outside
impl Default for EvmState {
    fn default() -> Self {
        let path = std::env::temp_dir().join("evm-state");
        Self::new(path).expect("Unable to instantiate default EVM state")
    }
}

impl EvmState {
    pub fn freeze(&mut self) {
        debug!("freezing evm state (slot {})", self.current_slot);
        self.dump_all()
            .expect("Unable to dump EVM state layers into storage");

        self.accounts.freeze();
        self.accounts_storage.freeze();
        self.txs_receipts.freeze();
        self.txs_in_block.freeze();

        debug!(
            "new slot {} with previous {:?}",
            self.current_slot, self.previous_slot
        );
        self.storage
            .new_version(self.current_slot, self.previous_slot)
            .expect("Unable to create new version in storage");
    }

    // TODO: dump all
    pub fn try_fork(&self, new_slot: Slot) -> Option<Self> {
        info!(
            "forking evm state from slot {} to slot {}",
            self.current_slot, new_slot
        );

        // TODO: assert that all these maps are empty
        let accounts = self.accounts.clone();
        let accounts_storage = self.accounts_storage.clone();
        let txs_receipts = self.txs_receipts.clone();
        let txs_in_block = self.txs_in_block.clone();

        Some(Self {
            current_slot: new_slot,
            previous_slot: Some(self.current_slot),

            accounts,
            accounts_storage,
            txs_receipts,
            txs_in_block,
            logs: vec![],
            storage: self.storage.clone(),
        })
    }

    #[rustfmt::skip]
    fn dump_all(&mut self) -> anyhow::Result<()> {
        self.accounts.dump_into(&self.storage, self.current_slot)?;
        self.accounts_storage.dump_into(&self.storage, self.current_slot)?;
        self.txs_receipts.dump_into(&self.storage, self.current_slot)?;
        self.txs_in_block.dump_into(&self.storage, self.current_slot)?;
        Ok(())
    }

    // TODO: elide map arg, TBD: maybe typemap
    fn lookup<'a, M: PersistentAssoc>(
        &'a self,
        layer: &'a Layer<M>,
        key: M::Key,
    ) -> Option<Cow<'a, M::Value>>
    where
        M::Key: Copy + Ord + Debug,
        M::Value: Clone + Debug,
    {
        debug!("lookup {} for key {:?}", type_name::<M>(), &key);
        if let Some(mb_value) = layer.map.get(&key) {
            Option::from(mb_value.by_ref()).map(Cow::Borrowed)
        } else {
            let lookup_slot = if self.storage.is_exists(self.current_slot).unwrap() {
                Some(self.current_slot)
            } else {
                self.previous_slot
            };

            if let Some(slot) = lookup_slot {
                if let Some(mb_value) =
                    self.storage
                        .typed::<M>()
                        .get_for(slot, key)
                        .unwrap_or_else(|err| {
                            panic!(
                                "Storage ({} :: Key {} => Value {}) lookup error: {:?}",
                                type_name::<M>(),
                                type_name::<M::Key>(),
                                type_name::<M::Value>(),
                                err
                            );
                        })
                {
                    debug!(
                        "{}: key {:?} was found in storage, value: {:?}",
                        type_name::<M>(),
                        key,
                        &mb_value
                    );
                    Option::from(mb_value).map(Cow::Owned)
                } else {
                    debug!(
                        "{}: key {:?} was not found in storage",
                        type_name::<M>(),
                        key
                    );
                    None
                }
            } else {
                None
            }
        }
    }
}

impl EvmState {
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self, anyhow::Error> {
        //TODO: add flags, to asserts for empty storage.
        Self::load_from(path, 0)
    }

    pub fn load_from<P: AsRef<Path>>(path: P, slot: Slot) -> Result<Self, anyhow::Error> {
        info!(
            "open evm state storage {} for slot {}",
            path.as_ref().display(),
            slot
        );
        let storage = Storage::open(path, COLUMN_NAMES)?;
        let previous_slot = storage.previous_of(slot)?;
        debug!(
            "storage reports: previous of {} is {:?}",
            slot, previous_slot
        );

        Ok(Self {
            current_slot: slot,
            previous_slot,

            accounts: Layer::empty(),
            accounts_storage: Layer::empty(),
            txs_receipts: Layer::empty(),
            txs_in_block: Layer::empty(),
            logs: vec![],
            storage,
        })
    }

    pub fn get_account(&self, address: H160) -> Option<AccountState> {
        self.lookup(&self.accounts, address).map(Cow::into_owned)
    }

    pub fn get_storage(&self, address: H160, index: H256) -> Option<H256> {
        self.lookup(&self.accounts_storage, (address, index))
            .map(Cow::into_owned)
    }

    pub fn get_tx_receipt_by_hash(&self, tx_hash: H256) -> Option<TransactionReceipt> {
        self.lookup(&self.txs_receipts, tx_hash)
            .map(Cow::into_owned)
    }

    pub fn get_txs_in_block(&self, block_num: Slot) -> Option<Vec<H256>> {
        self.lookup(&self.txs_in_block, block_num)
            .map(Cow::into_owned)
    }

    // NOTE: currently used in benches only
    pub fn set_account(&mut self, address: H160, state: AccountState) {
        self.accounts.insert(address, state);
    }

    pub fn swap_commit(&mut self, mut updated: Self) {
        // Assert that updated is newer than current state.
        // Slot can not change, because we allow multiple commits per block.
        // assert!(
        //     updated.current_slot > self.current_slot
        //         || (updated.current_slot == self.current_slot && self.is_empty()),
        //     "Not expected commit: current = slot {}, is_empty {}, updated = slot {}, is_empty {}",
        //     self.current_slot,
        //     self.is_empty(),
        //     updated.current_slot,
        //     updated.is_empty()
        // );

        std::mem::swap(self, &mut updated);
    }

    /// True if current layer has no any update, false otherwise.
    fn is_empty(&self) -> bool {
        self.accounts.is_empty()
            && self.accounts_storage.is_empty()
            && self.txs_receipts.is_empty()
            && self.txs_in_block.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use primitive_types::{H160, H256, U256};
    use rand::rngs::mock::StepRng;
    use rand::Rng;

    use crate::test_utils::TmpDir;
    use anyhow::anyhow;

    use super::*;

    const RANDOM_INCR: u64 = 1; // TODO: replace by rand::SeedableRng implementor
    const MAX_SIZE: usize = 32; // Max size of test collections.

    const SEED: u64 = 1;

    #[test]
    fn it_handles_my_own_expectations() {
        let tmp_dir = TmpDir::new("it_handles_my_own_expectations");
        let evm_state = EvmState::load_from(&tmp_dir, 0).unwrap();
        assert_eq!(evm_state.current_slot, 0);
        assert_eq!(evm_state.previous_slot, None);
        assert_eq!(
            evm_state
                .storage
                .previous_of(evm_state.current_slot)
                .unwrap(),
            None
        );
    }

    fn generate_account_by_seed(seed: u64) -> AccountState {
        let mut rng = StepRng::new(seed * RANDOM_INCR + seed, RANDOM_INCR);
        let nonce: [u8; 32] = rng.gen();
        let balance: [u8; 32] = rng.gen();

        let nonce = U256::from_little_endian(&nonce);
        let balance = U256::from_little_endian(&balance);
        let code_len: usize = rng.gen_range(0, MAX_SIZE);
        let code = (0..code_len).into_iter().map(|_| rng.gen()).collect();

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
            let storage_len = rng.gen_range(0, MAX_SIZE);
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
        state: &mut EvmState,
        accounts: &BTreeMap<H160, Option<AccountState>>,
        storage: &BTreeMap<(H160, H256), Option<H256>>,
    ) {
        for account in accounts {
            match &account.1 {
                Some(v) => state.accounts.insert(*account.0, v.clone()),
                None => state.accounts.remove(*account.0),
            }
        }

        for s in storage {
            match &s.1 {
                Some(v) => state.accounts_storage.insert(*s.0, *v),
                None => state.accounts_storage.remove(*s.0),
            }
        }
    }

    fn assert_state(
        state: &EvmState,
        accounts: &BTreeMap<H160, Option<AccountState>>,
        storage: &BTreeMap<(H160, H256), Option<H256>>,
    ) {
        for (address, expected) in accounts {
            assert_eq!(state.get_account(*address).as_ref(), expected.as_ref())
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

        let tmp_dir = TmpDir::new("add_two_accounts_check_helpers");
        let mut evm_state = EvmState::load_from(tmp_dir, Default::default()).unwrap();

        assert_eq!(
            evm_state
                .get_account(H160::random())
                .unwrap_or_default()
                .balance,
            U256::from(0)
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

        let tmp_dir = TmpDir::new("fork_add_remove_accounts");
        let mut evm_state = EvmState::load_from(tmp_dir, Default::default()).unwrap();

        save_state(&mut evm_state, &accounts_state_diff, &storage_diff);
        evm_state.freeze();

        assert_state(&evm_state, &accounts_state_diff, &storage_diff);

        let mut new_evm_state = evm_state.try_fork(1).unwrap();
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
    fn reads_the_same_after_consequent_dumps() -> anyhow::Result<()> {
        use std::ops::Bound::Included;
        let _ = simple_logger::SimpleLogger::from_env().init();

        const N_VERSIONS: usize = 10;
        const ACCOUNTS_PER_VERSION: usize = 10;

        let accounts = generate_accounts_addresses(SEED, ACCOUNTS_PER_VERSION * N_VERSIONS);
        let accounts_state = generate_accounts_state(SEED, &accounts);
        let accounts_storage = generate_storage(SEED, &accounts);

        let tmp_dir = TmpDir::new("reads_the_same_after_dump");
        let mut evm_state = EvmState::load_from(tmp_dir, 0)?;

        for accounts_per_version in accounts.chunks(N_VERSIONS) {
            for account in accounts_per_version {
                log::debug!("working with account: {:?}", account);
                evm_state
                    .accounts
                    .insert(*account, accounts_state[account].clone());

                for (account_with_index, data) in accounts_storage.range((
                    Included((*account, H256::zero())),
                    Included((*account, H256::repeat_byte(u8::MAX))),
                )) {
                    evm_state
                        .accounts_storage
                        .insert(*account_with_index, *data);
                }
            }

            evm_state.freeze();

            let next_slot = evm_state.current_slot + 1;
            evm_state = evm_state
                .try_fork(next_slot)
                .expect("unable to fork evm state after freeze");
        }

        let accounts_state_diff = to_state_diff(accounts_state, BTreeSet::new());
        let accounts_storage_diff = to_state_diff(accounts_storage, BTreeSet::new());

        assert_state(&evm_state, &accounts_state_diff, &accounts_storage_diff);

        Ok(())
    }

    #[test]
    fn lookups_thru_forks() {
        let _ = simple_logger::SimpleLogger::new().init();

        let tmp_dir = TmpDir::new("lookups_thru_forks");
        let mut state = EvmState::load_from(tmp_dir, 0).unwrap();

        let accounts = generate_accounts_addresses(SEED, 1);
        let account_states = generate_accounts_state(SEED, &accounts);

        let account = accounts.first().copied().unwrap();
        let account_state = account_states[&account].clone();

        state.accounts.insert(account, account_state.clone());

        for _ in 0..42 {
            state.freeze();

            let next_slot = state.current_slot + 1;
            state = state.try_fork(next_slot).unwrap();
        }

        assert_eq!(state.get_account(account), Some(account_state));
    }
}
