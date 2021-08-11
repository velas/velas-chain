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
    ///
    pub owners: [Pubkey; 3],
    /// Genegis owner key that generate Vaccount address
    pub genesis_seed_key: Pubkey,
    /// Storage version
    pub operational_storage_nonce: u16,
    /// Token storage nonce
    pub token_storage_nonce: u16,
    /// Programs storage nonce
    pub programs_storage_nonce: u16,
}

/// Storage of the basic Vaccount information.
#[repr(C)]
#[derive(PartialEq, Debug, Clone)]
#[derive(BorshSerialize, BorshDeserialize, BorshSchema)]
#[derive(Serialize, Deserialize)]
pub struct VAccountStorage {
    /// Operational in not extended VAccount
    pub operationals: Vec<Operational>
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
    pub agent_type: [u8; 32],
    /// Allowed instruction for operational key
    pub scopes: [u8; 4],
    /// Allowed tokens
    pub tokens_indices: [u8; 32],
    /// Allowed program addresses
    pub external_programs_indices: [u8; 32],
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
pub const ACCOUNT_LEN: usize = 135;

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

    #[test]
    fn it_checks_account_len2() {
        assert_eq!(solana_sdk::borsh::get_packed_len::<VAccountInfo>(), ACCOUNT_LEN)
    }

    #[test]
    fn deserialize_vaccount_and_storage() {
        // let vacc_data_base64 = "AX+L2di/S0km7vwWVWzabHtKq/S5CjWr58iCk6H+KxZqAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAH+L2di/S0km7vwWVWzabHtKq/S5CjWr58iCk6H+KxZqGQABAAEA";
        // let vacc_data = base64::decode(vacc_data_base64).unwrap();
        // let vacc: VAccountInfo = borsh::de::BorshDeserialize::try_from_slice(&vacc_data[..]).unwrap();

        // assert_eq!(
        //     vacc,
        //     VAccountInfo {
        //         version: 1,
        //         owners: [
        //             Pubkey::from_str("9atTpuaX8WoxWr7xDanvMmE41bPWkCLnSM4V4CMTu4Lq").unwrap(),
        //             Pubkey::default(),
        //             Pubkey::default()
        //         ],
        //         genesis_seed_key: Pubkey::from_str("9atTpuaX8WoxWr7xDanvMmE41bPWkCLnSM4V4CMTu4Lq").unwrap(),
        //         operational_storage_nonce: 25,
        //         token_storage_nonce: 1,
        //         programs_storage_nonce: 1
        //     }
        // );

        let storage_data_base64 = "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";

        let mut storage_data = vec![24u8, 0, 0, 0];
        let mut storage_data = vec![];
        storage_data.extend(base64::decode(storage_data_base64).unwrap());

        println!("{:?}", &storage_data.len());

        println!("{:?}", &storage_data);
        
        let storage: VAccountStorage = borsh::de::BorshDeserialize::try_from_slice(&storage_data[..]).unwrap();

        println!("{:?}", &storage);
    }
}
