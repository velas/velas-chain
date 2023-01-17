use super::*;
use borsh::{BorshDeserialize, BorshSerialize};
use solana_sdk::{
    program_pack::IsInitialized,
    pubkey::Pubkey,
};
use crate::instruction::TxFilter;

pub const MAX_FILTERS: usize = 10;

pub fn get_state_size(filters: &Vec<TxFilter>) -> usize {
    let mut bytes = vec![];
    BorshSerialize::serialize(filters, &mut bytes).unwrap();
    bytes.len() + 64
}

#[repr(C)]
#[derive(BorshDeserialize, BorshSerialize, Debug)]
pub struct Payer {
    /// The owner of this account.
    pub owner: Pubkey,
    /// Account that will pay for evm transaction
    pub payer: Pubkey,
    /// List of filters to define what transactions will be paid by this payer
    pub filters: Vec<TxFilter>,
}

impl Payer {
    pub fn do_filter_match(&self, tx: &evm_types::Transaction) -> bool {
        self.filters.iter().any(|f| { f.is_match(tx) })
    }
}

impl IsInitialized for Payer {
    fn is_initialized(&self) -> bool {
        !self.filters.is_empty()
    }
}
