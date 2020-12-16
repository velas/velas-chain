use std::borrow::Cow;
use std::path::Path;

use evm::backend::Log;
use primitive_types::{H160, H256, U256};
use serde::{Deserialize, Serialize};

use crate::{
    persistent_types,
    storage::{PersistentAssoc, PersistentMap, VersionedStorage},
    transactions::TransactionReceipt,
    version_map::{KeyResult, Map},
    Slot,
};

/// Vivinity value of a memory backend.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MemoryVicinity {
    /// Gas price.
    pub gas_price: U256,
    /// Origin.
    pub origin: H160,
    /// Chain ID.
    pub chain_id: U256,
    /// Environmental block hashes.
    pub block_hashes: Vec<H256>,
    /// Environmental block number.
    pub block_number: U256,
    /// Environmental coinbase.
    pub block_coinbase: H160,
    /// Environmental block timestamp.
    pub block_timestamp: U256,
    /// Environmental block difficulty.
    pub block_difficulty: U256,
    /// Environmental block gas limit.
    pub block_gas_limit: U256,
}

impl Default for MemoryVicinity {
    fn default() -> Self {
        Self {
            gas_price: U256::zero(),
            origin: H160::default(),
            chain_id: U256::zero(),
            block_hashes: Vec::new(),
            block_number: U256::zero(),
            block_coinbase: H160::default(),
            block_timestamp: U256::zero(),
            block_difficulty: U256::zero(),
            block_gas_limit: U256::max_value(),
        }
    }
}

#[derive(Default, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AccountState {
    /// Account nonce.
    pub nonce: U256,
    /// Account balance.
    pub balance: U256,
    /// Account code.
    pub code: Vec<u8>,
}

// Store every account storage at single place, to use power of versioned map.
// This allows us to save only changed data.
persistent_types! {
    Accounts in "accounts" => H160 : AccountState,
    AccountsStorage in "accounts_storage" => (H160, H256) : H256,
    TransactionReceipts in "txs_receipts" => H256 : TransactionReceipt,
}

type Mapped<M: PersistentAssoc> = Map<Slot, M::Key, M::Value>;

#[derive(Clone)] // TODO: Debug
pub struct EvmState {
    pub(crate) slot: Slot,
    pub(crate) vicinity: MemoryVicinity,
    pub(crate) logs: Vec<Log>,

    pub(crate) accounts: Mapped<Accounts>,
    pub(crate) accounts_storage: Mapped<AccountsStorage>,
    pub(crate) txs_receipts: Mapped<TransactionReceipts>,

    storage: VersionedStorage<Slot>,
}

// TODO: move this logic outside
impl Default for EvmState {
    fn default() -> Self {
        let path = std::env::temp_dir().join("evm-state");
        Self::load_from(path, Slot::default()).expect("Unable to instantiate default EVM state")
    }
}

impl EvmState {
    pub fn freeze(&mut self) {
        self.accounts.freeze();
        self.accounts_storage.freeze();
        self.txs_receipts.freeze();
    }

    pub fn try_fork(&self, new_slot: Slot) -> Option<Self> {
        let accounts = self.accounts.try_fork(new_slot)?;
        let accounts_storage = self.accounts_storage.try_fork(new_slot)?;
        let txs_receipts = self.txs_receipts.try_fork(new_slot)?;

        // TODO: save new_slot in new state and refactor memory map as versionless with inlined get w/o layered map proxy

        Some(Self {
            slot: new_slot,
            vicinity: self.vicinity.clone(),
            logs: vec![],
            accounts,
            accounts_storage,
            txs_receipts,
            storage: self.storage.clone(),
        })
    }

    #[rustfmt::skip]
    pub fn dump_all(&mut self) -> anyhow::Result<()> {
        dump_into(&self.storage.typed::<Accounts>(), &mut self.accounts)?;
        dump_into(&self.storage.typed::<AccountsStorage>(), &mut self.accounts_storage)?;
        dump_into(&self.storage.typed::<TransactionReceipts>(), &mut self.txs_receipts)?;
        Ok(())
    }

    fn lookup<'a, M: PersistentAssoc>(
        &'a self,
        // TODO: elide this arg, TBD: maybe typemap
        map: &'a Mapped<M>,
        key: M::Key,
    ) -> Option<Cow<'a, M::Value>>
    where
        M::Key: Copy + Ord,
        M::Value: Clone,
    {
        match map.get(&key) {
            KeyResult::Found(mb_value) => mb_value.map(Cow::Borrowed),
            KeyResult::NotFound(last_version) => self
                .storage
                .typed::<M>()
                .get_for(*last_version, key)
                .expect("Internal storage error")
                .map(Cow::Owned),
        }
    }

    pub fn basic(&self, account: H160) -> AccountState {
        self.get_account(account).unwrap_or_default()
    }

    pub fn storage(&self, account: H160, key: H256) -> H256 {
        self.get_storage(account, key).unwrap_or_default()
    }

    pub fn code(&self, account: H160) -> Vec<u8> {
        self.get_account(account).unwrap_or_default().code
    }
}

fn dump_into<'a, M: PersistentAssoc>(
    storage: &PersistentMap<'a, Slot, M>,
    map: &mut Mapped<M>,
) -> anyhow::Result<()>
where
    M::Key: Ord + Copy,
    M::Value: Clone,
{
    let mut full_iter = map.full_iter().peekable();
    while let Some((version, kvs)) = full_iter.next() {
        for (key, value) in kvs {
            storage.insert_with(*version, *key, value.cloned())?;
        }

        let previous = full_iter
            .peek()
            .map(|(previous, _)| **previous)
            .or_else(|| storage.previous_of(*version).ok().flatten());
        storage.new_version(*version, previous)?;
    }
    drop(full_iter);

    map.clear();
    Ok(())
}

impl EvmState {
    pub fn load_from<P: AsRef<Path>>(path: P, slot: Slot) -> Result<Self, anyhow::Error> {
        let storage = VersionedStorage::open(path, COLUMN_NAMES)?;

        Ok(Self {
            slot,
            vicinity: MemoryVicinity::default(),
            logs: vec![],

            accounts: Map::empty(slot),
            accounts_storage: Map::empty(slot),
            txs_receipts: Map::empty(slot),

            storage,
        })
    }

    pub fn get_tx_receipt_by_hash(&self, tx_hash: H256) -> Option<TransactionReceipt> {
        self.lookup::<TransactionReceipts>(&self.txs_receipts, tx_hash)
            .map(Cow::into_owned)
    }

    pub fn get_account(&self, address: H160) -> Option<AccountState> {
        self.lookup::<Accounts>(&self.accounts, address)
            .map(Cow::into_owned)
    }

    pub fn get_storage(&self, address: H160, index: H256) -> Option<H256> {
        self.lookup::<AccountsStorage>(&self.accounts_storage, (address, index))
            .map(Cow::into_owned)
    }

    pub fn swap_commit(&mut self, mut updated: Self) {
        // TODO: Assert that updated is newer than current state.
        std::mem::swap(self, &mut updated);
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use primitive_types::{H160, H256, U256};
    use rand::rngs::mock::StepRng;
    use rand::Rng;

    use crate::test_utils::TmpDir;

    use super::*;

    const RANDOM_INCR: u64 = 734512;
    const MAX_SIZE: usize = 32; // Max size of test collections.

    const SEED: u64 = 123;

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

        assert_eq!(evm_state.basic(H160::random()).balance, U256::from(0));
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
}
