use std::collections::BTreeMap;
use std::path::Path;

use evm::backend::{Apply, ApplyBackend, Backend, Basic, Log};
use primitive_types::{H160, H256, U256};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};

use crate::{layered_map::LayeredMap, storage, transactions::TransactionReceipt, Slot};

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

#[derive(Clone)] // TODO: Debug
pub struct EvmState {
    pub(crate) slot: Slot,
    pub(crate) vicinity: MemoryVicinity,
    pub(crate) logs: Vec<Log>,
    // TODO: add Slot
    pub accounts: Map<H160, AccountState>,
    // Store every account storage at single place, to use power of versioned map.
    // This allows us to save only changed data.
    pub(crate) accounts_storage: Map<(H160, H256), H256>,
    pub(crate) txs_receipts: Map<H256, TransactionReceipt>,
    storage: storage::VersionedStorage<Slot>,
}

type Map<K, V> = LayeredMap<Slot, K, V>;
type Storage<K, V> = storage::PersistentMap<Slot, K, Option<V>>;

// TODO: remove this in future
const DEFAULT_STORAGE_PATH: &str = "/tmp/solana/evm-state";

const ACCOUNTS: &str = "accounts";
const ACCOUNTS_STORAGE: &str = "accounts_storage";
const TRANSACTIONS_RECEIPTS: &str = "txs_receipts";

struct FieldsStorages {
    accounts: Storage<H160, AccountState>,
    accounts_storage: Storage<(H160, H256), H256>,
    txs_receipts: Storage<H256, TransactionReceipt>,
}

fn open_storage<P: AsRef<Path>>(
    path: P,
) -> anyhow::Result<(storage::VersionedStorage<Slot>, FieldsStorages)> {
    let storage = storage::VersionedStorage::open(
        path,
        &[ACCOUNTS, ACCOUNTS_STORAGE, TRANSACTIONS_RECEIPTS],
    )?;

    let accounts = storage.typed(ACCOUNTS)?;
    let accounts_storage = storage.typed(ACCOUNTS_STORAGE)?;
    let txs_receipts = storage.typed(TRANSACTIONS_RECEIPTS)?;

    Ok((
        storage,
        FieldsStorages {
            accounts,
            accounts_storage,
            txs_receipts,
        },
    ))
}

impl Default for EvmState {
    fn default() -> Self {
        Self::load_from(DEFAULT_STORAGE_PATH, Slot::default()).unwrap_or_else(|err| {
            panic!("Unable to instantiate default EVM state: {:?}", err);
        })
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

    pub fn dump(&mut self) -> anyhow::Result<()> {
        self.accounts.dump()?;
        self.accounts_storage.dump()?;
        self.txs_receipts.dump()?;
        Ok(())
    }
}

impl EvmState {
    pub fn load_from<P: AsRef<Path>>(path: P, slot: Slot) -> Result<Self, anyhow::Error> {
        let (
            storage,
            FieldsStorages {
                accounts,
                accounts_storage,
                txs_receipts,
            },
        ) = open_storage(path)?;

        let accounts = LayeredMap::wrap(accounts, slot);
        let accounts_storage = LayeredMap::wrap(accounts_storage, slot);
        let txs_receipts = LayeredMap::wrap(txs_receipts, slot);

        Ok(Self {
            slot,
            vicinity: MemoryVicinity::default(),
            logs: vec![],

            accounts,
            accounts_storage,
            txs_receipts,
            storage,
        })
    }

    pub fn get_tx_receipt_by_hash(&self, tx_hash: H256) -> Option<TransactionReceipt> {
        self.txs_receipts.get(tx_hash)
    }

    pub fn apply(
        &mut self,
        updates: (
            (
                impl IntoIterator<Item = Apply<impl IntoIterator<Item = (H256, H256)>>>,
                impl IntoIterator<Item = Log>,
            ),
            BTreeMap<H256, TransactionReceipt>,
        ),
    ) {
        let (patch, txs) = updates;
        ApplyBackend::apply(self, patch.0, patch.1, false);
        for (tx_hash, tx) in txs {
            log::debug!("Register tx in evm = {}", tx_hash);
            self.txs_receipts.insert(tx_hash, tx);
        }
    }
}

impl Backend for EvmState {
    fn gas_price(&self) -> U256 {
        self.vicinity.gas_price
    }
    fn origin(&self) -> H160 {
        self.vicinity.origin
    }
    fn block_hash(&self, number: U256) -> H256 {
        if number >= self.vicinity.block_number
            || self.vicinity.block_number - number - U256::one()
                >= U256::from(self.vicinity.block_hashes.len())
        {
            H256::default()
        } else {
            let index = (self.vicinity.block_number - number - U256::one()).as_usize();
            self.vicinity.block_hashes[index]
        }
    }
    fn block_number(&self) -> U256 {
        self.vicinity.block_number
    }
    fn block_coinbase(&self) -> H160 {
        self.vicinity.block_coinbase
    }
    fn block_timestamp(&self) -> U256 {
        self.vicinity.block_timestamp
    }
    fn block_difficulty(&self) -> U256 {
        self.vicinity.block_difficulty
    }
    fn block_gas_limit(&self) -> U256 {
        self.vicinity.block_gas_limit
    }

    fn chain_id(&self) -> U256 {
        self.vicinity.chain_id
    }

    fn exists(&self, address: H160) -> bool {
        self.accounts.get(address).is_some()
    }

    fn basic(&self, address: H160) -> Basic {
        let a = self.accounts.get(address).unwrap_or_default();
        Basic {
            balance: a.balance,
            nonce: a.nonce,
        }
    }

    fn code_hash(&self, address: H160) -> H256 {
        self.accounts
            .get(address)
            .map(|v| H256::from_slice(Keccak256::digest(&v.code).as_slice()))
            .unwrap_or_else(|| H256::from_slice(Keccak256::digest(&[]).as_slice()))
    }

    fn code_size(&self, address: H160) -> usize {
        self.accounts
            .get(address)
            .map(|v| v.code.len())
            .unwrap_or(0)
    }

    fn code(&self, address: H160) -> Vec<u8> {
        self.accounts
            .get(address)
            .map(|v| v.code)
            .unwrap_or_default()
    }

    fn storage(&self, address: H160, index: H256) -> H256 {
        self.accounts_storage
            .get((address, index))
            .unwrap_or_default()
    }
}

impl ApplyBackend for EvmState {
    fn apply<A, I, L>(&mut self, values: A, logs: L, delete_empty: bool)
    where
        A: IntoIterator<Item = Apply<I>>,
        I: IntoIterator<Item = (H256, H256)>,
        L: IntoIterator<Item = Log>,
    {
        for apply in values {
            match apply {
                Apply::Modify {
                    address,
                    basic,
                    code,
                    storage,
                    reset_storage: _,
                } => {
                    log::debug!("Apply::Modify address = {}, basic = {:?}", address, basic);
                    // TODO: rollback on insert fail.
                    // TODO: clear account storage on delete.
                    let is_empty = {
                        let mut account = self.accounts.get(address).unwrap_or_default();
                        account.balance = basic.balance;
                        account.nonce = basic.nonce;
                        if let Some(code) = code {
                            account.code = code;
                        }
                        let is_empty_state = account.balance == U256::zero()
                            && account.nonce == U256::zero()
                            && account.code.is_empty();

                        self.accounts.insert(address, account);

                        // TODO: Clear storage on reset_storage = true
                        // if reset_storage {
                        // 	account.storage = BTreeMap::new();
                        // }

                        // TODO: Clear zeros data (H256::default())

                        for (index, value) in storage {
                            if value == H256::default() {
                                self.accounts_storage.remove((address, index));
                            } else {
                                self.accounts_storage.insert((address, index), value);
                            }
                        }

                        is_empty_state
                    };

                    if is_empty && delete_empty {
                        self.accounts.remove(address);
                    }
                }
                Apply::Delete { address } => {
                    self.accounts.remove(address);
                }
            }
        }

        self.logs.extend(logs);
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
        for account in accounts {
            assert_eq!(state.accounts.get(*account.0).as_ref(), account.1.as_ref())
        }

        for s in storage {
            assert_eq!(state.accounts_storage.get(*s.0).as_ref(), s.1.as_ref())
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
