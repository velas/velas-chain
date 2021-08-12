use std::convert::TryFrom;

use borsh::{BorshDeserialize, BorshSchema, BorshSerialize};
use serde::{Deserialize, Serialize};

use solana_sdk::pubkey::Pubkey;

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
    /// Genesis owner key that generates Vaccount address
    pub genesis_seed_key: Pubkey,
    /// Storage version
    pub operational_storage_nonce: u16,
    /// Token storage nonce
    pub token_storage_nonce: u16,
    /// Programs storage nonce
    pub programs_storage_nonce: u16,
}

impl VAccountInfo {
    pub fn find_storage_key(&self, vaccount: &Pubkey) -> Pubkey {
        Pubkey::find_program_address(
            &[
                &vaccount.to_bytes(),
                b"storage",
                &self.programs_storage_nonce.to_le_bytes()
            ],
            &crate::id()
        ).0
    }
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

impl VAccountStorage {
    pub const LEN: usize = std::mem::size_of::<Operational>();

    pub fn deserialize_stream_array(data: &[u8]) -> Result<Self, std::io::Error> {
        let number_operationals = data.len() / Self::LEN;
        let mut operationals = Vec::new();
        for index in 0..number_operationals {
            let start_from = Self::LEN * index;

            operationals.push(Operational::try_from_slice(
                &data[start_from..start_from + Self::LEN],
            )?)
        }
        Ok(Self { operationals })
    }
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
            VAccountStorage::deserialize_stream_array(data).map(VelasAccountType::Storage)
        }
        .map_err(|_| ParseError::AccountNotParsable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    use std::str::FromStr;

    #[test]
    #[ignore] // TODO
    fn it_checks_account_len() {
        assert_eq!(std::mem::size_of::<VAccountInfo>(), ACCOUNT_LEN);
        assert_eq!(solana_sdk::borsh::get_packed_len::<VAccountInfo>(), ACCOUNT_LEN)
    }

    #[test]
    fn test_deserialize_vaccountinfo() {
        let vacc_data_base64 = include_str!("../tests_data/account_info.txt");
        let vacc_data = base64::decode(vacc_data_base64).unwrap();
        let vacc: VAccountInfo = borsh::BorshDeserialize::try_from_slice(&vacc_data[..]).unwrap();

        assert_eq!(
            vacc,
            VAccountInfo {
                version: 1,
                owners: [
                    Pubkey::from_str("9atTpuaX8WoxWr7xDanvMmE41bPWkCLnSM4V4CMTu4Lq").unwrap(),
                    Pubkey::default(),
                    Pubkey::default()
                ],
                genesis_seed_key: Pubkey::from_str("9atTpuaX8WoxWr7xDanvMmE41bPWkCLnSM4V4CMTu4Lq").unwrap(),
                operational_storage_nonce: 25,
                token_storage_nonce: 1,
                programs_storage_nonce: 1
            }
        );
    }

    #[test]
    fn test_deserialize_vaccountstorage() {
        let storage_data_base64 = include_str!("../tests_data/account_storage.txt");
        let storage_data = base64::decode(storage_data_base64).unwrap();

        let vstorage = VAccountStorage::deserialize_stream_array(&storage_data).unwrap();

        assert_eq!(vstorage.operationals.len(), 24);
        assert_eq!(
            vstorage.operationals[0],
            Operational {
                pubkey: Pubkey::from_str("6kNwJXdAuDuXzFKKhYzMpQY5yGSFyus4eXPxxWJkDe2C").unwrap(),
                state: OperationalState::Initialized,
                agent_type: [0, 1, 2, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                scopes: [127, 250, 0, 0],
                tokens_indices: [0; 32],
                external_programs_indices: [0; 32],
                is_master_key: false,
            }
        );
    }
}
