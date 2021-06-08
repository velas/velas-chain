use std::convert::TryFrom;

use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use serde_with::DisplayFromStr;

use {
    borsh::{BorshDeserialize, BorshSchema, BorshSerialize},
    solana_program::{program_pack::IsInitialized, pubkey::Pubkey},
};
solana_program::declare_id!("9fH5EdMT9ovEGvvd8NUhxT1XfyotiQvz3aHWNgWxyHZd");

/// Struct provided metadata of the related program
#[serde_as]
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize, BorshSchema, PartialEq)]
#[derive(Serialize, Deserialize)]
pub struct RelyingPartyData {
    /// Struct version, allows for upgrades to the program
    pub version: u8,
    /// The account allowed to update the data
    #[serde_as(as = "DisplayFromStr")]
    pub authority: Pubkey,
    /// The metadata of the related program
    pub related_program_data: RelatedProgramInfo,
}

/// Metadata of the some program to show for Vaccount
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize, BorshSchema, PartialEq)]
#[derive(Serialize, Deserialize)]
pub struct RelatedProgramInfo {
    /// Name of the program to show in Vaccount
    pub name: String,
    /// Icon content identifier
    pub icon_cid: Vec<u8>,
    /// Domain name of the related program
    pub domain_name: String,
    /// Allowed redirect URI for Vaccount in program
    pub redirect_uri: Vec<String>,
}

impl RelatedProgramInfo {
    /// https://en.wikipedia.org/wiki/Domain_name#Domain_name_syntax
    pub const MAX_DOMAIN_LEN: u8 = 253;
    /// Is valid domain name
    pub fn is_valid_domain_name(domain_name: &str) -> bool {
        if domain_name.len() > Self::MAX_DOMAIN_LEN as usize {
            return false;
        }
        true
    }
}

impl RelyingPartyData {
    /// Version to fill in on new created accounts
    pub const CURRENT_VERSION: u8 = 1;
}

impl IsInitialized for RelyingPartyData {
    /// Is initialized
    fn is_initialized(&self) -> bool {
        self.version == Self::CURRENT_VERSION
    }
}

#[derive(Debug)]
pub enum ParseError {
    AccountNotParsable,
}

impl TryFrom<&[u8]> for RelyingPartyData {
    type Error = ParseError;

    fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
        RelyingPartyData::try_from_slice(data).map_err(|_| ParseError::AccountNotParsable)
    }
}
