use std::convert::TryFrom;

use crate::parse_account_data::{ParsableAccount, ParseAccountError};

use borsh::BorshDeserialize;
use velas_account::*;

pub const ACCOUNT_LEN: usize = 67;

impl TryFrom<&[u8]> for VelasAccountType {
    type Error = ParseAccountError;

    fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
        if data.len() == ACCOUNT_LEN {
            VAccountInfo::try_from_slice(data).map(VelasAccountType::Account)
        } else {
            VAccountStorage::try_from_slice(data).map(VelasAccountType::Storage)
        }
        .map_err(|_| ParseAccountError::AccountNotParsable(ParsableAccount::VelasAccount))
    }
}

pub fn parse_velas_account(data: &[u8]) -> Result<VelasAccountType, ParseAccountError> {
    let account =
        if data.len() == ACCOUNT_LEN {
            VelasAccountType::Account(VAccountInfo::try_from_slice(data).map_err(|_| {
                ParseAccountError::AccountNotParsable(ParsableAccount::VelasAccount)
            })?)
        } else {
            VelasAccountType::Storage(VAccountStorage::try_from_slice(data).map_err(|_| {
                ParseAccountError::AccountNotParsable(ParsableAccount::VelasAccount)
            })?)
        };
    Ok(account)
}

/// A wrapper enum for consistency across programs
#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", tag = "type", content = "info")]
pub enum VelasAccountType {
    Account(VAccountInfo),
    Storage(VAccountStorage),
}

pub mod velas_account {
    use borsh::{BorshDeserialize, BorshSchema, BorshSerialize};
    use serde::{Deserialize, Serialize};
    use solana_sdk::{clock::UnixTimestamp, pubkey::Pubkey};

    /// Program states.
    #[repr(C)]
    #[derive(
        Serialize,
        Deserialize,
        BorshSerialize,
        BorshDeserialize,
        BorshSchema,
        PartialEq,
        Debug,
        Clone,
    )]
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
    #[derive(
        Serialize,
        Deserialize,
        BorshSerialize,
        BorshDeserialize,
        BorshSchema,
        PartialEq,
        Debug,
        Clone,
    )]
    pub struct VAccountStorage {
        /// Owner key in not extended VAccount
        pub owners: Vec<Pubkey>,
        /// Operational in not extended VAccount
        pub operationals: Vec<Operational>,
    }

    /// Operational key state.
    #[repr(C)]
    #[derive(
        Serialize,
        Deserialize,
        Clone,
        Debug,
        Default,
        PartialEq,
        BorshDeserialize,
        BorshSerialize,
        BorshSchema,
    )]
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
    #[derive(
        Serialize,
        Deserialize,
        Clone,
        Debug,
        Default,
        PartialEq,
        Eq,
        Hash,
        BorshDeserialize,
        BorshSerialize,
        BorshSchema,
    )]
    pub struct ExternalProgram {
        /// Allowed to call program code id
        pub program_id: Pubkey,
        /// Allowed to call instruction inside program
        pub scopes: Vec<u8>,
    }

    /// Operational key state.
    #[repr(u8)]
    #[derive(
        Serialize,
        Deserialize,
        Clone,
        Copy,
        Debug,
        PartialEq,
        BorshDeserialize,
        BorshSerialize,
        BorshSchema,
    )]
    pub enum OperationalState {
        /// Operational key is initialized
        Initialized,
        /// Operational has been frozen by the owner/operational freeze authority.
        Frozen,
    }

    /// Token account.
    #[repr(C)]
    #[derive(
        Serialize,
        Deserialize,
        Clone,
        Debug,
        Default,
        PartialEq,
        Eq,
        Hash,
        BorshDeserialize,
        BorshSerialize,
        BorshSchema,
    )]
    pub struct ExternalToken {
        /// Token account with daily transfer limit
        pub account: TokenAccount,
        /// Last uses of transfer
        pub last_transfer: UnixTimestamp,
    }

    /// Token daily limit.
    #[repr(C)]
    #[derive(
        Serialize,
        Deserialize,
        Clone,
        Debug,
        Default,
        PartialEq,
        Eq,
        Hash,
        BorshDeserialize,
        BorshSerialize,
        BorshSchema,
    )]
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
}
