use std::{collections::HashMap, fmt::Debug, fs, path::Path, sync::Arc};

use log::*;

use primitive_types::H256;
use rlp::{Decodable, Encodable};
use rocksdb::DB;
use triedb::{empty_trie_hash, rocksdb::RocksMemoryTrieMut, FixedTrieMut};

use crate::{
    storage::{Codes, Receipts, Storage as KVS, TransactionHashesPerBlock, Transactions},
    transactions::TransactionReceipt,
    types::*,
};

#[derive(Clone, Debug)]
pub struct EvmState {
    pub slot: Slot,
    pub root: H256,

    pub kvs: KVS,

    /// None indicates removed account
    accounts: HashMap<H160, Option<AccountState>>,
    storages: HashMap<H160, HashMap<H256, H256>>,

    transactions: HashMap<H256, TransactionChunks>,
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

            accounts: HashMap::new(),
            storages: HashMap::new(),

            transactions: HashMap::new(),
            receipts: HashMap::new(),
        }
    }
}

impl EvmState {
    pub fn apply(&mut self) {
        let mut accounts_trie = self.typed_for::<H160, Account>(self.root);

        for (address, account_state) in std::mem::take(&mut self.accounts) {
            if let Some(AccountState {
                nonce,
                balance,
                code,
            }) = account_state
            {
                // TODO: Self::get_account if applicable
                let mut account = accounts_trie.get(&address).unwrap_or_default();

                account.nonce = nonce;
                account.balance = balance;

                if !code.is_empty() {
                    let code_hash = code.hash();
                    self.kvs.set::<Codes>(code_hash, code);
                    account.code_hash = code_hash;
                }

                let mut storage_trie = self.typed_for::<H256, H256>(account.storage_root);
                for (index, value) in self.storages.remove(&address).into_iter().flatten() {
                    if value != H256::default() {
                        storage_trie.insert(&index, &value);
                    } else {
                        storage_trie.delete(&index);
                    }
                }
                let storage_root = storage_trie
                    .to_trie()
                    .apply()
                    .expect("Unable to apply storage updates");
                account.storage_root = storage_root;

                accounts_trie.insert(&address, &account);
            } else {
                accounts_trie.delete(&address);
            }
        }

        debug_assert!(
            self.storages.is_empty(),
            "There is some unhanled data in storage"
        );

        let new_root = accounts_trie
            .to_trie()
            .apply()
            .expect("Unable to apply accounts updates");

        self.kvs.set::<TransactionHashesPerBlock>(
            self.slot,
            self.transactions.keys().copied().collect(),
        );

        for (hash, transaction) in self.transactions.iter() {
            self.kvs.set::<Transactions>(*hash, transaction.to_vec());
        }

        // for (hash, transaction) in std::mem::take(&mut self.transactions) {
        //     // assert_eq!(hash, transaction.hash());
        //     self.kvs.set::<Transactions>(hash, transaction);
        // }

        for (hash, receipt) in std::mem::take(&mut self.receipts) {
            self.kvs.set::<Receipts>(hash, receipt);
        }

        self.root = new_root;
    }

    /// Ignores all unapplied updates.
    pub fn fork(&self, new_slot: Slot) -> Self {
        Self {
            slot: new_slot,
            root: self.root,
            kvs: self.kvs.clone(),

            accounts: HashMap::new(),
            storages: HashMap::new(),

            transactions: HashMap::new(),
            receipts: HashMap::new(),
        }
    }

    fn typed_for<K: Encodable, V: Encodable + Decodable>(
        &self,
        root: H256,
    ) -> FixedTrieMut<RocksMemoryTrieMut<Arc<DB>>, K, V> {
        FixedTrieMut::new(RocksMemoryTrieMut::new(self.kvs.db.clone(), root))
    }
}

impl EvmState {
    pub fn get_account_state(&self, address: H160) -> Option<AccountState> {
        self.accounts.get(&address).cloned().unwrap_or_else(|| {
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

    pub fn set_account_state(&mut self, address: H160, account_state: AccountState) {
        self.accounts.insert(address, Some(account_state));
    }

    pub fn remove_account(&mut self, address: H160) {
        self.accounts.insert(address, None);
    }

    pub fn get_storage(&self, address: H160, index: H256) -> Option<H256> {
        self.storages
            .get(&address)
            .and_then(|indices| indices.get(&index))
            .copied()
            .or_else(|| {
                self.typed_for(self.root).get(&address).and_then(
                    |Account { storage_root, .. }| {
                        FixedTrieMut::new(RocksMemoryTrieMut::new(
                            self.kvs.db.as_ref(),
                            storage_root,
                        ))
                        .get(&index)
                    },
                )
            })
    }

    pub fn ext_storage(
        &mut self,
        address: H160,
        indexed_values: impl IntoIterator<Item = (H256, H256)>,
    ) {
        self.storages
            .entry(address)
            .or_default()
            .extend(indexed_values);
    }

    // Transactions

    pub fn get_transaction(&self, address: H256) -> Option<TransactionChunks> {
        self.transactions
            .get(&address)
            .cloned()
            .or_else(|| self.kvs.get::<Transactions>(address))
    }

    // TODO: reflect some usages logic: allocate storage / extend storage
    pub fn set_transaction(&mut self, address: H256, transaction: TransactionChunks) {
        self.transactions.insert(address, transaction);
    }

    // TODO: persist it!
    pub fn get_transaction_mut(&mut self, address: H256) -> Option<&mut TransactionChunks> {
        self.transactions.get_mut(&address)
    }

    pub fn take_transaction(&mut self, address: H256) -> Option<TransactionChunks> {
        self.transactions.remove(&address)
    }

    // Transaction Receipts

    pub fn get_transaction_receipt(&self, transaction: H256) -> Option<TransactionReceipt> {
        self.receipts
            .get(&transaction)
            .cloned()
            .or_else(|| self.kvs.get::<Receipts>(transaction))
    }

    pub fn set_transaction_receipt(&mut self, transaction: H256, receipt: TransactionReceipt) {
        self.receipts.insert(transaction, receipt);
    }
}

impl EvmState {
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self, anyhow::Error> {
        let path = path.as_ref();

        if path.is_dir() && path.exists() {
            warn!("deleting existing state {}", path.display());
            fs::remove_dir_all(path)?;
            fs::create_dir(path)?;
        }

        Self::load_from(path, Slot::default(), empty_trie_hash())
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

            accounts: HashMap::new(),
            storages: HashMap::new(),

            transactions: HashMap::new(),
            receipts: HashMap::new(),
        })
    }

    pub fn get_transactions_in_block(&self, block_num: Slot) -> Option<Vec<H256>> {
        if self.slot == block_num {
            Some(self.transactions.keys().copied().collect())
        } else {
            self.kvs.get::<TransactionHashesPerBlock>(block_num)
        }
    }

    // TODO: Optimize, using bloom filters.
    // TODO: Check topics query limits <= 4.
    // TODO: Filter by address, topics
    pub fn get_logs(&self, log_filter: LogFilter) -> Vec<LogWithLocation> {
        let mut result = Vec::new();

        for (block_id, txs) in (log_filter.from_block..=log_filter.to_block)
            .filter_map(|b| self.get_transactions_in_block(b).map(|txs| (b, txs)))
        {
            txs.into_iter()
                .map(|tx_hash| {
                    (
                        tx_hash,
                        self.get_transaction_receipt(tx_hash)
                            .expect("Transacton not found by hash, while exist by number"),
                    )
                })
                .enumerate()
                .for_each(|(tx_id, (tx_hash, receipt))| {
                    for log in receipt.logs {
                        let log_entry = LogWithLocation {
                            transaction_hash: tx_hash,
                            transaction_id: tx_id as u64,
                            block_num: block_id,
                            data: log.data,
                            topics: log.topics,
                            address: log.address,
                        };
                        result.push(log_entry)
                    }
                });
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use primitive_types::{H160, H256, U256};
    use rand::rngs::mock::StepRng;
    use rand::Rng;

    use super::*;

    const RANDOM_INCR: u64 = 1; // TODO: replace by rand::SeedableRng implementor
    const MAX_SIZE: usize = 32; // Max size of test collections.

    const SEED: u64 = 1;

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
        evm_state.apply();

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

            evm_state.apply();
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
            state.apply();
            state = state.fork(state.slot + 1);
        }

        let recv_state = state.get_account_state(account).unwrap();
        assert_eq!(recv_state, account_state);
    }
}
