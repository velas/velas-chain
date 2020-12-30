use crate::EvmState;
use evm::backend::{Apply, ApplyBackend, Backend, Basic, Log};
use primitive_types::{H160, H256, U256};
use sha3::{Digest, Keccak256};

use crate::types::MemoryVicinity;

pub struct EvmBackend {
    pub(crate) evm_state: EvmState,
    pub(crate) tx_info: MemoryVicinity,
}

impl EvmBackend {
    pub fn new_from_state(evm_state: EvmState, tx_info: MemoryVicinity) -> Self {
        Self { evm_state, tx_info }
    }

    fn tx_info(&self) -> &MemoryVicinity {
        &self.tx_info
    }
}

impl Backend for EvmBackend {
    fn gas_price(&self) -> U256 {
        self.tx_info().gas_price
    }
    fn origin(&self) -> H160 {
        self.tx_info().origin
    }
    fn block_hash(&self, number: U256) -> H256 {
        if number >= self.tx_info().block_number
            || self.tx_info().block_number - number - U256::one()
                >= U256::from(self.tx_info().block_hashes.len())
        {
            H256::default()
        } else {
            let index = (self.tx_info().block_number - number - U256::one()).as_usize();
            self.tx_info().block_hashes[index]
        }
    }
    fn block_number(&self) -> U256 {
        self.tx_info().block_number
    }
    fn block_coinbase(&self) -> H160 {
        self.tx_info().block_coinbase
    }
    fn block_timestamp(&self) -> U256 {
        self.tx_info().block_timestamp
    }
    fn block_difficulty(&self) -> U256 {
        self.tx_info().block_difficulty
    }
    fn block_gas_limit(&self) -> U256 {
        self.tx_info().block_gas_limit
    }

    fn chain_id(&self) -> U256 {
        self.tx_info().chain_id
    }

    fn exists(&self, address: H160) -> bool {
        self.evm_state.get_account(address).is_some()
    }

    fn basic(&self, address: H160) -> Basic {
        let a = self.evm_state.get_account(address).unwrap_or_default();
        Basic {
            balance: a.balance,
            nonce: a.nonce,
        }
    }

    fn code_hash(&self, address: H160) -> H256 {
        self.evm_state
            .get_account(address)
            .map(|v| H256::from_slice(Keccak256::digest(&v.code).as_slice()))
            .unwrap_or_else(|| H256::from_slice(Keccak256::digest(&[]).as_slice()))
    }

    fn code_size(&self, address: H160) -> usize {
        self.evm_state
            .get_account(address)
            .map(|v| v.code.len())
            .unwrap_or(0)
    }

    fn code(&self, address: H160) -> Vec<u8> {
        self.evm_state
            .get_account(address)
            .map(|v| v.code)
            .unwrap_or_default()
    }

    fn storage(&self, address: H160, index: H256) -> H256 {
        self.evm_state
            .get_storage(address, index)
            .unwrap_or_default()
    }
}

impl ApplyBackend for EvmBackend {
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
                        let mut account = self.evm_state.get_account(address).unwrap_or_default();
                        account.balance = basic.balance;
                        account.nonce = basic.nonce;
                        if let Some(code) = code {
                            account.code = code;
                        }
                        let is_empty_state = account.balance == U256::zero()
                            && account.nonce == U256::zero()
                            && account.code.is_empty();

                        self.evm_state.accounts.insert(address, account);

                        // TODO: Clear storage on reset_storage = true
                        // if reset_storage {
                        // 	account.storage = BTreeMap::new();
                        // }

                        // TODO: Clear zeros data (H256::default())

                        for (index, value) in storage {
                            if value == H256::default() {
                                self.evm_state.accounts_storage.remove((address, index));
                            } else {
                                self.evm_state
                                    .accounts_storage
                                    .insert((address, index), value);
                            }
                        }

                        is_empty_state
                    };

                    if is_empty && delete_empty {
                        self.evm_state.accounts.remove(address);
                    }
                }
                Apply::Delete { address } => {
                    self.evm_state.accounts.remove(address);
                }
            }
        }

        self.evm_state.logs.extend(logs);
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::EvmBackend;
    use crate::EvmState;

    #[test]
    fn check_that_balance_zero_by_default() {
        let evm_backend = EvmBackend::new_from_state(EvmState::default(), Default::default());
        assert_eq!(evm_backend.basic(H160::random()).balance, U256::from(0));
    }
}
