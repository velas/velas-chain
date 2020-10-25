use serde::{Serialize, Deserialize};
use evm::backend::{Apply, Basic, Backend, ApplyBackend, Log};
use primitive_types::{H160, U256, H256};
use sha3::{Digest, Keccak256};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::{Mutex, MutexGuard};

use super::backend::MemoryVicinity;
use super::version_map::Map;

#[derive(Default, Clone, Debug, Eq, PartialEq)]
pub struct AccountState {
	/// Account nonce.
	pub nonce: U256,
	/// Account balance.
	pub balance: U256,
	/// Account code.
	pub code: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct EvmState {
	vicinity: MemoryVicinity,
    accounts: Arc<Map<H160, AccountState>>,
    // Store every account storage at single place, to use power of versioned map. (This allows us to save only changed data).
    storage: Arc<Map<(H160, H256), H256>>,
    logs: Vec<Log>,
}

#[derive(Debug)]
pub struct EvmAccountsLocked<'a> {
    accounts: &'a mut Map<H160, AccountState>,
    storage: &'a mut Map<(H160, H256), H256>
}

#[derive(Debug)]
pub struct LockedState<'a> {
    state: EvmState,
    guard: MutexGuard<'a, ()>
}

impl EvmState {
    pub fn new_from_parent(&self) -> Self {
        EvmState {
            vicinity: self.vicinity.clone(),
            accounts: Arc::new(Map::new_from_parent(self.accounts.clone())),
            storage: Arc::new(Map::new_from_parent(self.storage.clone())),
            logs: Vec::new(),
        }
    }

    pub fn try_lock<'a> (&'a self, evm_mutex: &'a Mutex<()>) -> Option<LockedState<'a> > {
        let guard = evm_mutex.try_lock().ok()?;
        Some(LockedState{
            state: self.clone(),
            guard
        })
    }
}

impl<'a> LockedState<'a> {
    fn fork_mut<'b>(&'b mut self) -> EvmAccountsLocked<'b> {
        EvmAccountsLocked {
            accounts: Arc::make_mut(&mut self.state.accounts),
            storage: Arc::make_mut(&mut self.state.storage)
        }
    }
}

impl Backend for EvmState {
	fn gas_price(&self) -> U256 { self.vicinity.gas_price }
	fn origin(&self) -> H160 { self.vicinity.origin }
	fn block_hash(&self, number: U256) -> H256 {
		if number >= self.vicinity.block_number ||
			self.vicinity.block_number - number - U256::one() >= U256::from(self.vicinity.block_hashes.len())
		{
			H256::default()
		} else {
			let index = (self.vicinity.block_number - number - U256::one()).as_usize();
			self.vicinity.block_hashes[index]
		}
	}
	fn block_number(&self) -> U256 { self.vicinity.block_number }
	fn block_coinbase(&self) -> H160 { self.vicinity.block_coinbase }
	fn block_timestamp(&self) -> U256 { self.vicinity.block_timestamp }
	fn block_difficulty(&self) -> U256 { self.vicinity.block_difficulty }
	fn block_gas_limit(&self) -> U256 { self.vicinity.block_gas_limit }

	fn chain_id(&self) -> U256 { self.vicinity.chain_id }

	fn exists(&self, address: H160) -> bool {
		self.accounts.get(&address).is_some()
	}

	fn basic(&self, address: H160) -> Basic {
		self.accounts.get(&address).map(|a| {
			Basic { balance: a.balance, nonce: a.nonce }
		}).unwrap_or_default()
	}

	fn code_hash(&self, address: H160) -> H256 {
		self.accounts.get(&address).map(|v| {
			H256::from_slice(Keccak256::digest(&v.code).as_slice())
		}).unwrap_or(H256::from_slice(Keccak256::digest(&[]).as_slice()))
	}

	fn code_size(&self, address: H160) -> usize {
		self.accounts.get(&address).map(|v| v.code.len()).unwrap_or(0)
	}

	fn code(&self, address: H160) -> Vec<u8> {
		self.accounts.get(&address).map(|v| v.code.clone()).unwrap_or_default()
	}

	fn storage(&self, address: H160, index: H256) -> H256 {
		self.storage.get(&(address, index)).cloned().unwrap_or(H256::default())
	}
}


impl<'a> ApplyBackend for LockedState<'a> {
	fn apply<A, I, L>(
		&mut self,
		values: A,
		logs: L,
		delete_empty: bool,
	) where
		A: IntoIterator<Item=Apply<I>>,
		I: IntoIterator<Item=(H256, H256)>,
		L: IntoIterator<Item=Log>,
	{
        let state = self.fork_mut();
		for apply in values {
			match apply {
				Apply::Modify {
					address, basic, code, storage, reset_storage,
				} => {
                    // TODO: rollback on insert fail.
                    // TODO: clear account storage on delete.
					let is_empty = {
                        let mut account = state.accounts.get(&address).cloned().unwrap_or(Default::default());
						account.balance = basic.balance;
						account.nonce = basic.nonce;
						if let Some(code) = code {
                            account.code = code;
                        }
                        let is_empty_state = account.balance == U256::zero() &&
                        account.nonce == U256::zero() &&
                        account.code.len() == 0;

                        state.accounts.insert(address, account);
                        

                        // TODO: Clear storage on reset_storage = true
						// if reset_storage {
						// 	account.storage = BTreeMap::new();
                        // }
                        
                        // TODO: Clear zeros data (H256::default())

						for (index, value) in storage {
							if value == H256::default() {
								state.storage.remove((address, index));
							} else {
								state.storage.insert((address, index), value);
							}
						}

						is_empty_state
					};

					if is_empty && delete_empty {
						state.accounts.remove(address);
					}
				},
				Apply::Delete {
					address,
				} => {
					state.accounts.remove(address);
				},
			}
		}

		for log in logs {
			self.state.logs.push(log);
		}
	}
}

#[cfg(test)]
mod test {
    use super::*;
    use rand::rngs::mock::StepRng;
    use rand::Rng;
    use std::collections::{BTreeSet, BTreeMap};
    use primitive_types::{H160, H256, U256};
    const RANDOM_INCR: u64 = 734512;
    const MAX_SIZE: usize = 32; // Max size of test collections.

    const SEED:u64 = 123;

    impl EvmState {
        pub(crate) fn testing_default() -> EvmState {
            EvmState {
                vicinity: Default::default(),
                accounts: Default::default(),
                storage: Default::default(),
                logs: Default::default(),
            }
        }
    }

    fn generate_account_by_seed(seed: u64) -> AccountState {
        let mut rng = StepRng::new(seed * RANDOM_INCR + seed, RANDOM_INCR);
        let nonce: [u8;32] = rng.gen();
        let balance: [u8;32] = rng.gen();
        
        let nonce = U256::from_little_endian(&nonce);
        let balance = U256::from_little_endian(&balance);
        let code_len: usize = rng.gen_range(0, MAX_SIZE);
        let code = (0..code_len).into_iter().map(|_| rng.gen()).collect();

        AccountState {
            nonce,
            balance,
            code
        }
    }

    fn generate_accounts_state(seed:u64, accounts: &[H160]) -> BTreeMap<H160, AccountState> {
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
                let addr: [u8;32] = rng.gen();
                let data: [u8;32] = rng.gen();

                let addr = H256::from_slice(&addr);
                let data = H256::from_slice(&data);
                map.insert((*acc, addr), data);
            }
        }
        map
    }

    fn generate_accounts_addresses(seed: u64, count: usize) -> Vec<H160> {
        let mut rng = StepRng::new(seed, RANDOM_INCR);
        (0..count).into_iter().map(|_| H256::from_slice(&rng.gen::<[u8;32]>()).into()).collect()
    }


    fn to_state_diff<K: Ord, Mv>(inserts: BTreeMap<K, Mv>, removes: BTreeSet<K>) -> BTreeMap<K, Option<Mv>> {
        let len = inserts.len() + removes.len();
        let mut map = BTreeMap::new();
        for insert in inserts {
            assert!(map.insert(insert.0, Some(insert.1)).is_none(), "double insert");
        }

        for insert in removes {
            assert!(map.insert(insert, None).is_none(), "delete after insert is not allowed");
        }
        assert_eq!(map.len(), len, "length differ from inserts + removes len");
        map
        
    }

    fn save_state(state: &mut EvmState, accounts: &BTreeMap<H160, Option<AccountState>>, storage: &BTreeMap<(H160, H256), Option<H256>>) {
        for account in accounts {
            match &account.1 {
                Some(v) => Arc::make_mut(&mut state.accounts).insert(*account.0, v.clone()),
                None => Arc::make_mut(&mut state.accounts).remove(*account.0)
            }
        }

        for s in storage {
            match &s.1 {
                Some(v) => Arc::make_mut(&mut state.storage).insert(*s.0, *v),
                None => Arc::make_mut(&mut state.storage).remove(*s.0)
            }
        }

    }

    fn assert_state(state: &EvmState, accounts: &BTreeMap<H160, Option<AccountState>>, storage: &BTreeMap<(H160, H256), Option<H256>>) {
        for account in accounts {
            assert_eq!(state.accounts.get(account.0), account.1.as_ref())
        }

        for s in storage {
            assert_eq!(state.storage.get(s.0), s.1.as_ref())
        }

    }


    #[test]
    fn add_two_accounts_check_helpers() {
        let accounts = generate_accounts_addresses(SEED, 2);

        let storage = generate_storage(SEED, &accounts);
        let accounts_state = generate_accounts_state(SEED, &accounts);
        let storage_diff = to_state_diff(storage, BTreeSet::new());
        let accounts_state_diff = to_state_diff(accounts_state, BTreeSet::new());

        let mut evm_state = EvmState::testing_default();
        save_state(&mut evm_state, &accounts_state_diff, &storage_diff);

        assert_state(& evm_state, &accounts_state_diff, &storage_diff);

    }



    #[test]
    fn fork_add_remove_accounts() {
        let accounts = generate_accounts_addresses(SEED, 10);

        let storage = generate_storage(SEED, &accounts);
        let accounts_state = generate_accounts_state(SEED, &accounts);
        let storage_diff = to_state_diff(storage, BTreeSet::new());
        let accounts_state_diff = to_state_diff(accounts_state, BTreeSet::new());

        let mut evm_state = EvmState::testing_default();
        save_state(&mut evm_state, &accounts_state_diff, &storage_diff);

        assert_state(& evm_state, &accounts_state_diff, &storage_diff);
        let mut new_evm_state = evm_state.new_from_parent();

        assert_state(& new_evm_state, &accounts_state_diff, &storage_diff);

        let new_accounts = generate_accounts_addresses(SEED + 1, 2);
        let new_accounts_state = generate_accounts_state(SEED + 1, &new_accounts);
        let removed_accounts: BTreeSet<_> = accounts[0..2].iter().copied().collect();
        let new_accounts_state_diff = to_state_diff(new_accounts_state, removed_accounts);

        save_state(&mut new_evm_state, &new_accounts_state_diff, &BTreeMap::new());

        assert_state(& new_evm_state, &new_accounts_state_diff, &BTreeMap::new());

    }

}