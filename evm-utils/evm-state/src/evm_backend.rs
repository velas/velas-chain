use std::{collections::HashMap, iter::FromIterator};

use evm::backend::{Apply, Backend, Basic};
use primitive_types::{H160, H256, U256};

use log::*;

use crate::{types::*, EvmState};

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

    pub fn apply<A, I>(&mut self, values: A, _delete_empty: bool)
    where
        A: IntoIterator<Item = Apply<I>>,
        I: IntoIterator<Item = (H256, H256)>,
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
                    debug!("Apply::Modify address = {}, basic = {:?}", address, basic);

                    let storage = HashMap::<H256, H256>::from_iter(storage);
                    debug!("Apply::Modify storage = {:?}", storage);

                    // TODO: Rollback on insert fail.
                    // TODO: Clear account storage on delete.

                    let mut account_state = self
                        .evm_state
                        .get_account_state(address)
                        .unwrap_or_default();

                    account_state.nonce = basic.nonce;
                    account_state.balance = basic.balance;

                    if let Some(code) = code {
                        account_state.code = code.into();
                    }

                    self.evm_state.ext_storage(address, storage);

                    if !account_state.is_empty() {
                        self.evm_state.set_account_state(address, account_state);
                    } else {
                        self.evm_state.remove_account(address);
                    }

                    // TODO: Clear storage on reset_storage = true
                    // TODO: Clear zeros data (H256::default())
                }
                Apply::Delete { address } => {
                    self.evm_state.remove_account(address);
                }
            }
        }
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
        self.evm_state.get_account_state(address).is_some()
    }

    fn basic(&self, address: H160) -> Basic {
        let AccountState { balance, nonce, .. } = self
            .evm_state
            .get_account_state(address)
            .unwrap_or_default();

        Basic { balance, nonce }
    }

    fn code(&self, address: H160) -> Vec<u8> {
        self.evm_state
            .get_account_state(address)
            .map(|account_state| account_state.code)
            .unwrap_or_else(Code::empty)
            .into()
    }

    fn storage(&self, address: H160, index: H256) -> H256 {
        self.evm_state
            .get_storage(address, index)
            .unwrap_or_default()
    }

    fn original_storage(&self, address: H160, index: H256) -> Option<H256> {
        Some(self.storage(address, index))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{EvmBackend, EvmState};

    #[test]
    fn check_that_balance_zero_by_default() {
        let evm_backend = EvmBackend::new_from_state(EvmState::default(), Default::default());
        for _ in 0..1000 {
            let address = H160::random();
            assert_eq!(evm_backend.basic(address).balance, U256::zero());
        }
    }
}
