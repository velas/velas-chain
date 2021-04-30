use std::convert::TryFrom;

use borsh::{BorshDeserialize, BorshSchema, BorshSerialize};
use serde::{Deserialize, Serialize};

use solana_sdk::{clock::UnixTimestamp, pubkey::Pubkey};

solana_sdk::declare_id!("VAcccHVjpknkW5N5R9sfRppQxYJrJYVV7QJGKchkQj5");

/// A wrapper enum for consistency across programs
#[derive(Debug, PartialEq)]
#[derive(BorshSerialize, BorshDeserialize, BorshSchema)]
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "type", content = "info")]
pub enum VelasAccountType {
    Account(VAccountInfo),
    Storage(VAccountStorage),
}

/// Program states.
#[repr(C)]
#[derive(PartialEq, Debug, Clone)]
#[derive(BorshSerialize, BorshDeserialize, BorshSchema)]
#[derive(Serialize, Deserialize)]
pub struct VAccountInfo {
    /// Vaccount version
    pub version: u8,
    /// Genegis owner key that generate Vaccount address
    pub genesis_seed_key: Pubkey,
    /// Storage version
    pub storage_version: u16,
    /// Storage address
    pub storage: Pubkey,
}

/// Storage of the basic Vaccount information.
#[repr(C)]
#[derive(PartialEq, Debug, Clone)]
#[derive(BorshSerialize, BorshDeserialize, BorshSchema)]
#[derive(Serialize, Deserialize)]
pub struct VAccountStorage {
    /// Owner key in not extended VAccount
    pub owners: Vec<Pubkey>,
    /// Operational in not extended VAccount
    pub operationals: Vec<Operational>,
}

/// Operational key state.
#[repr(C)]
#[derive(Clone, Debug, Default, PartialEq)]
#[derive(BorshDeserialize, BorshSerialize, BorshSchema)]
#[derive(Serialize, Deserialize)]
pub struct Operational {
    /// Operational key
    pub pubkey: Pubkey,
    /// Operational key state
    pub state: OperationalState,
    /// Type of the agent session associated with an operational key
    pub agent_type: Vec<u8>,
    /// Allowed instruction for operational key
    pub scopes: Vec<u8>,
    /// Allowed programs to call
    pub whitelist_programs: Vec<ExternalProgram>,
    /// Allowed token accounts
    pub whitelist_tokens: Vec<ExternalToken>,
    /// Master key is allowed to call any instruction in Vaccount
    pub is_master_key: bool,
}

/// Operational key state.
#[repr(C)]
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
#[derive(BorshDeserialize, BorshSerialize, BorshSchema)]
#[derive(Serialize, Deserialize)]
pub struct ExternalProgram {
    /// Allowed to call program code id
    pub program_id: Pubkey,
    /// Allowed to call instruction inside program
    pub scopes: Vec<u8>,
}

/// Operational key state.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq)]
#[derive(BorshDeserialize, BorshSerialize, BorshSchema)]
#[derive(Serialize, Deserialize)]
pub enum OperationalState {
    /// Operational key is initialized
    Initialized,
    /// Operational has been frozen by the owner/operational freeze authority.
    Frozen,
}

/// Token account.
#[repr(C)]
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
#[derive(BorshSchema, BorshSerialize, BorshDeserialize)]
#[derive(Serialize, Deserialize)]
pub struct ExternalToken {
    /// Token account with daily transfer limit
    pub account: TokenAccount,
    /// Last uses of transfer
    pub last_transfer: UnixTimestamp,
}

/// Token daily limit.
#[repr(C)]
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
#[derive(BorshSchema, BorshSerialize, BorshDeserialize)]
#[derive(Serialize, Deserialize)]
pub struct TokenAccount {
    /// Token address with vaccount authority
    pub token_account: Pubkey,
    /// The remainder of the daily limit lamports for transfer
    pub remainder_daily_limit: u64,
}

impl Default for OperationalState {
    fn default() -> Self {
        OperationalState::Initialized
    }
}

// TODO: try to avoid direct size hardcodes
pub const ACCOUNT_LEN: usize = 67;

#[derive(Debug)]
pub enum ParseError {
    AccountNotParsable,
}

impl TryFrom<&[u8]> for VelasAccountType {
    type Error = ParseError;

    fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
        if data.len() == ACCOUNT_LEN {
            VAccountInfo::try_from_slice(data).map(VelasAccountType::Account)
        } else {
            VAccountStorage::try_from_slice(data).map(VelasAccountType::Storage)
        }
        .map_err(|_| ParseError::AccountNotParsable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore] // TODO
    fn it_checks_account_len() {
        assert_eq!(std::mem::size_of::<VAccountInfo>(), ACCOUNT_LEN);
    }
}
