use std::{collections::HashMap, fmt::Debug, fs, path::Path};

use log::*;

use ethbloom::{Bloom, Input};
use primitive_types::H256;
use rlp::{Decodable, Encodable};
use rocksdb::DB;
use triedb::{
    empty_trie_hash,
    gc::{ItemCounter, TrieCollection},
    rocksdb::{RocksDatabaseHandle, RocksHandle, RocksMemoryTrieMut},
    FixedSecureTrieMut,
};

use crate::{
    storage::{BlockMetas, Codes, Receipts, Storage as KVS},
    transactions::TransactionReceipt,
    types::*,
};

#[derive(Clone, Debug)]
pub struct EvmState {
    pub slot: Slot,
    pub root: H256,

    pub kvs: KVS,

    /// Maybe::Nothing indicates removed account
    states: HashMap<H160, (Maybe<AccountState>, HashMap<H256, H256>)>,
    bloom: Bloom,
    receipts: HashMap<H256, TransactionReceipt>,
}

/// NOTE: Only for testing purposes.
impl Default for EvmState {
    fn default() -> Self {
        let slot = Slot::default();
        let root = empty_trie_hash();
        let kvs = KVS::create_temporary().expect("Unable to create temporary storage");

        Self {
            slot,
            root,
            kvs,

            states: HashMap::new(),
            bloom: Bloom::default(),
            receipts: HashMap::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Maybe<T> {
    Just(T),
    Nothing,
}

impl<T> From<Maybe<T>> for Option<T> {
    fn from(mb: Maybe<T>) -> Self {
        match mb {
            Maybe::Just(val) => Some(val),
            Maybe::Nothing => None,
        }
    }
}

impl EvmState {
    pub fn commit(&mut self) {
        trace!("commit: before state = {:?}", self);
        let r = RocksHandle::new(RocksDatabaseHandle::new(self.kvs.db.as_ref()));

        let mut storage_tries = TrieCollection::new(r.clone(), StaticEntries::default());
        let mut account_tries = TrieCollection::new(r, StaticEntries::default());

        let mut accounts =
            FixedSecureTrieMut::<_, H160, Account>::new(account_tries.trie_for(self.root));

        for (address, (state, storages)) in std::mem::take(&mut self.states) {
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
                    self.kvs.set::<Codes>(code_hash, code);
                    account.code_hash = code_hash;
                }

                let mut storage = FixedSecureTrieMut::<_, H256, U256>::new(
                    storage_tries.trie_for(account.storage_root),
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
                let storage_root = storage_tries.apply(storage_patch);
                account.storage_root = storage_root;

                accounts.insert(&address, &account);
            } else {
                accounts.delete(&address);
            }
        }

        let accounts_patch = accounts.to_trie().into_patch();
        let new_root = account_tries.apply(accounts_patch);

        // TODO: store only non-empty hashes

        let block_meta = self.get_block_meta(self.slot);

        match block_meta {
            Some(block_meta) if !block_meta.is_empty() => {
                self.kvs.set::<BlockMetas>(self.slot, block_meta);
            }
            Some(block_meta) => {
                assert!(block_meta.transactions.is_empty());
                assert!(block_meta.bloom.is_empty());
            }
            None => {}
        }

        for (hash, receipt) in std::mem::take(&mut self.receipts) {
            self.kvs.set::<Receipts>(hash, receipt);
        }

        self.root = new_root;
        self.bloom = Bloom::default();
        trace!("commit: after state = {:?}", self);
    }

    /// Ignores all unapplied updates.
    pub fn fork(&self, new_slot: Slot) -> Self {
        Self {
            slot: new_slot,
            root: self.root,
            kvs: self.kvs.clone(),

            states: HashMap::new(),
            bloom: Bloom::default(),
            receipts: HashMap::new(),
        }
    }

    fn typed_for<K: AsRef<[u8]>, V: Encodable + Decodable>(
        &self,
        root: H256,
    ) -> FixedSecureTrieMut<RocksMemoryTrieMut<&DB>, K, V> {
        FixedSecureTrieMut::new(RocksMemoryTrieMut::new(self.kvs.db.as_ref(), root))
    }
}

impl EvmState {
    pub fn get_account_state(&self, address: H160) -> Option<AccountState> {
        self.states
            .get(&address)
            .map(|(state, _)| state.clone().into())
            .unwrap_or_else(|| {
                self.typed_for(self.root).get(&address).map(
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
            })
    }

    // TODO: hide this method and add some test only methods for set-up account state via transaction
    pub fn set_account_state(&mut self, address: H160, account_state: AccountState) {
        use std::collections::hash_map::Entry::*;

        match self.states.entry(address) {
            Occupied(mut e) => {
                e.get_mut().0 = Maybe::Just(account_state);
            }
            Vacant(e) => {
                e.insert((Maybe::Just(account_state), HashMap::new()));
            }
        };
    }

    pub fn remove_account(&mut self, address: H160) {
        self.states
            .entry(address)
            .and_modify(|(state, _)| *state = Maybe::Nothing)
            .or_insert_with(|| (Maybe::Nothing, HashMap::new()));
    }

    pub fn get_storage(&self, address: H160, index: H256) -> Option<H256> {
        self.states
            .get(&address)
            .and_then(|(_, indices)| indices.get(&index))
            .copied()
            .or_else(|| {
                self.typed_for(self.root).get(&address).and_then(
                    |Account { storage_root, .. }| {
                        FixedSecureTrieMut::new(RocksMemoryTrieMut::new(
                            self.kvs.db.as_ref(),
                            storage_root,
                        ))
                        .get(&index)
                        .map(|value: U256| {
                            let mut encoded = H256::default();
                            value.to_big_endian(encoded.as_bytes_mut());
                            encoded
                        })
                    },
                )
            })
    }

    pub fn ext_storage(
        &mut self,
        address: H160,
        indexed_values: impl IntoIterator<Item = (H256, H256)>,
    ) {
        let (_, storage) = self
            .states
            .entry(address)
            .or_insert_with(|| (Maybe::Just(AccountState::default()), HashMap::new()));

        storage.extend(indexed_values);
    }

    pub fn get_block_meta(&self, block: Slot) -> Option<BlockMeta> {
        let mut block_meta = self.kvs.get::<BlockMetas>(block);

        debug_assert!(self.receipts.values().all(|receipt| {
            receipt.logs.iter().all(|log| {
                self.bloom
                    .contains_input(Input::Raw(log.address.as_bytes()))
                    && log.topics.iter().all(|topic| {
                        self.bloom
                            .contains_input(Input::Hash(topic.as_fixed_bytes()))
                    })
            })
        }));

        if block == self.slot {
            let meta_addition = BlockMeta {
                bloom: self.bloom,
                transactions: self.receipts.keys().copied().collect(),
            };
            block_meta = Some(block_meta.unwrap_or_default() + meta_addition);
        }

        block_meta
    }

    // Transaction Receipts

    pub fn get_transaction_receipt(&self, transaction: H256) -> Option<TransactionReceipt> {
        self.receipts
            .get(&transaction)
            .cloned()
            .or_else(|| self.kvs.get::<Receipts>(transaction))
    }

    pub fn set_transaction_receipt(&mut self, transaction: H256, receipt: TransactionReceipt) {
        log::debug!("Transaction receipt {}: {:?}", transaction, receipt);

        receipt.logs.iter().for_each(|log| {
            self.bloom.accrue(Input::Raw(log.address.as_bytes()));
            log.topics
                .iter()
                .for_each(|topic| self.bloom.accrue(Input::Hash(topic.as_fixed_bytes())));
        });
        self.receipts.insert(transaction, receipt);
    }
}

impl EvmState {
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self, anyhow::Error> {
        let evm_state = path.as_ref().join("evm-state");

        if evm_state.is_dir() && evm_state.exists() {
            warn!("deleting existing state {}", evm_state.display());
            fs::remove_dir_all(&evm_state)?;
            fs::create_dir(&evm_state)?;
        }

        Self::load_from(evm_state, Slot::default(), empty_trie_hash())
    }

    pub fn new_from_genesis(
        evm_state: impl AsRef<Path>,
        evm_genesis: impl AsRef<Path>,
        root_hash: H256,
    ) -> Result<Self, anyhow::Error> {
        let evm_state = evm_state.as_ref();
        if evm_state.is_dir() && evm_state.exists() {
            warn!("deleting existing state {}", evm_state.display());
            fs::remove_dir_all(&evm_state)?;
            fs::create_dir(&evm_state)?;
        }

        KVS::restore_from(evm_genesis, &evm_state)?;
        Self::load_from(evm_state, Slot::default(), root_hash)
    }

    pub fn load_from<P: AsRef<Path>>(
        path: P,
        slot: Slot,
        root: H256,
    ) -> Result<Self, anyhow::Error> {
        info!("Open EVM storage {}", path.as_ref().display());

        let kvs = KVS::open_persistent(path)?;

        Ok(Self {
            slot,
            root,
            kvs,

            states: HashMap::new(),
            bloom: Bloom::default(),
            receipts: HashMap::new(),
        })
    }

    // TODO: Check topics query limits <= 4.
    pub fn get_logs(&self, filter: LogFilter) -> Vec<LogWithLocation> {
        let masks = filter.bloom_possibilities();

        (filter.from_block..=filter.to_block)
            .flat_map(|block| {
                self.get_block_meta(block)
                    .map(|block_meta| (block, block_meta))
            })
            .filter(|(_, block_meta)| {
                masks
                    .iter()
                    .any(|mask| block_meta.bloom.contains_bloom(mask))
            })
            .flat_map(|(block, BlockMeta { transactions, .. })| {
                transactions
                    .into_iter()
                    .map(|tx| {
                        let receipt = self
                            .get_transaction_receipt(tx)
                            .expect("Transacton not found by hash, while exist by number");
                        (tx, receipt)
                    })
                    .enumerate()
                    .flat_map(move |(id, (tx, receipt))| {
                        receipt.logs.into_iter().map(move |log| LogWithLocation {
                            transaction_hash: tx,
                            transaction_id: id as u64,
                            block_num: block,
                            data: log.data,
                            topics: log.topics,
                            address: log.address,
                        })
                    })
            })
            .collect()
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
    }
}

#[derive(Default)]
struct StaticEntries {}

impl ItemCounter for StaticEntries {
    fn increase(&mut self, _: H256) -> usize {
        1
    }
    fn decrease(&mut self, _: H256) -> usize {
        1
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::{BTreeMap, BTreeSet},
        str::FromStr,
    };

    use primitive_types::{H160, H256, U256};
    use rand::rngs::mock::StepRng;
    use rand::Rng;

    use super::*;

    const RANDOM_INCR: u64 = 1; // TODO: replace by rand::SeedableRng implementor
    const MAX_SIZE: usize = 32; // Max size of test collections.

    const SEED: u64 = 1;

    impl EvmState {
        fn get_account(&self, address: H160) -> Option<Account> {
            self.typed_for(self.root).get(&address)
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
        state: &mut EvmState,
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

    fn assert_state(
        state: &EvmState,
        accounts: &BTreeMap<H160, Option<AccountState>>,
        storage: &BTreeMap<(H160, H256), Option<H256>>,
    ) {
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

        let mut evm_state = EvmState::default();

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

        let mut evm_state = EvmState::default();

        save_state(&mut evm_state, &accounts_state_diff, &storage_diff);
        evm_state.commit();

        assert_state(&evm_state, &accounts_state_diff, &storage_diff);

        let mut new_evm_state = evm_state.fork(evm_state.slot + 1);
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
        let _ = simple_logger::SimpleLogger::from_env().init();

        const N_VERSIONS: usize = 10;
        const ACCOUNTS_PER_VERSION: usize = 10;

        let accounts = generate_accounts_addresses(SEED, ACCOUNTS_PER_VERSION * N_VERSIONS);
        let accounts_state = generate_accounts_state(SEED, &accounts);
        let accounts_storage = generate_storage(SEED, &accounts);

        let mut evm_state = EvmState::default();

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

            evm_state.commit();
            evm_state = evm_state.fork(evm_state.slot + 1);
        }

        let accounts_state_diff = to_state_diff(accounts_state, BTreeSet::new());
        let accounts_storage_diff = to_state_diff(accounts_storage, BTreeSet::new());

        assert_state(&evm_state, &accounts_state_diff, &accounts_storage_diff);
    }

    #[test]
    fn lookups_thru_forks() {
        let _ = simple_logger::SimpleLogger::new().init();

        let mut state = EvmState::default();

        let accounts = generate_accounts_addresses(SEED, 1);
        let account_states = generate_accounts_state(SEED, &accounts);

        let account = accounts.first().copied().unwrap();
        let account_state = account_states[&account].clone();

        state.set_account_state(account, account_state.clone());

        for _ in 0..42 {
            state.commit();
            state = state.fork(state.slot + 1);
        }

        let recv_state = state.get_account_state(account).unwrap();
        assert_eq!(recv_state, account_state);
    }

    #[test]
    fn it_handles_accounts_state_get_set_expectations() {
        let _ = simple_logger::SimpleLogger::new().init();

        let mut state = EvmState::default();

        let addr = H160::random();
        assert_eq!(state.get_account_state(addr), None);

        let new_state = AccountState {
            nonce: U256::from(1),
            ..Default::default()
        };

        state.set_account_state(addr, new_state.clone());
        assert_eq!(state.get_account_state(addr), Some(new_state.clone()));

        state.commit();

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

        state.commit();

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

        let mut state = EvmState::default();
        state.set_account_state(address, account_state);
        state.ext_storage(address, storage_mod);

        state.commit();
        let account = state.get_account(address).unwrap();

        assert_eq!(
            state.get_storage(address, H256::zero()),
            Some(H256::from_low_u64_be(0x1234))
        );
        assert_eq!(
            state.get_storage(address, H256::from_low_u64_be(0x01)),
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

        let mut state = EvmState::default();
        state.set_account_state(address, account_state);
        state.ext_storage(address, storage_mod);

        state.commit();
        let account = state.get_account(address).unwrap();

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

        let mut state = EvmState::default();
        state.set_account_state(address, account_state);

        state.ext_storage(
            address,
            Some((H256::from_low_u64_be(0), H256::from_low_u64_be(0x1234))),
        );
        state.commit();

        state.ext_storage(
            address,
            Some((H256::from_low_u64_be(1), H256::from_low_u64_be(0x1234))),
        );
        state.commit();

        state.ext_storage(
            address,
            Some((H256::from_low_u64_be(1), H256::from_low_u64_be(0))),
        );
        state.commit();

        let account = state.get_account(address).unwrap();

        assert_eq!(
            account.storage_root,
            H256::from_str("c57e1afb758b07f8d2c8f13a3b6e44fa5ff94ab266facc5a4fd3f062426e50b2")
                .unwrap()
        );
    }
}
