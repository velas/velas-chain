use derive_more::{From, Into};
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};

use triedb::empty_trie_hash;

pub use primitive_types::{H160, H256, U256};

pub type Slot = u64; // TODO: re-use existing one from sdk package

#[derive(Default, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountState {
    /// Account nonce.
    pub nonce: U256,
    /// Account balance.
    pub balance: U256,
    /// Account code.
    pub code: Code,
}

impl AccountState {
    pub fn is_empty(&self) -> bool {
        self.nonce == U256::zero() && self.balance == U256::zero() && self.code.is_empty()
    }
}

impl Encodable for AccountState {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_list(3)
            .append(&self.nonce)
            .append(&self.balance)
            .append(&self.code);
    }
}

impl Decodable for AccountState {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        Ok(Self {
            nonce: rlp.val_at(0)?,
            balance: rlp.val_at(1)?,
            code: rlp.val_at(2)?,
        })
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq, From, Into, Serialize, Deserialize)]
pub struct Code(Vec<u8>);

impl Code {
    pub fn empty() -> Self {
        Self(vec![])
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn size(&self) -> usize {
        self.0.len()
    }

    pub fn hash(&self) -> H256 {
        H256::from_slice(Keccak256::digest(self.0.as_slice()).as_slice())
    }
}

impl Encodable for Code {
    fn rlp_append(&self, s: &mut RlpStream) {
        self.0.rlp_append(s)
    }
}

impl Decodable for Code {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        <_>::decode(rlp).map(Self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
// TODO: restrict roots modification anywhere outside State Apply logic
pub struct Account {
    pub nonce: U256,
    pub balance: U256,
    pub storage_root: H256,
    pub code_hash: H256,
}

impl Account {
    pub fn is_empty(&self) -> bool {
        self.nonce == U256::zero()
            && self.balance == U256::zero()
            && self.storage_root == empty_trie_hash()
            && self.code_hash == Code::empty().hash()
    }
}

impl Default for Account {
    fn default() -> Self {
        Self {
            nonce: U256::zero(),
            balance: U256::zero(),
            storage_root: empty_trie_hash(),
            code_hash: Code::empty().hash(),
        }
    }
}

impl Encodable for Account {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_list(4)
            .append(&self.nonce)
            .append(&self.balance)
            .append(&self.storage_root)
            .append(&self.code_hash);
    }
}

impl Decodable for Account {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        Ok(Self {
            nonce: rlp.val_at(0)?,
            balance: rlp.val_at(1)?,
            storage_root: rlp.val_at(2)?,
            code_hash: rlp.val_at(3)?,
        })
    }
}

pub struct LogWithLocation {
    pub transaction_hash: H256,
    pub transaction_id: u64,
    pub block_num: u64,
    pub address: H160,
    pub data: Vec<u8>,
    pub topics: Vec<H256>,
}

pub struct LogFilter {
    pub from_block: u64,
    pub to_block: u64,
    pub address: Option<H160>,
    pub topics: Vec<H256>,
}

#[cfg(test)]
mod tests {
    use super::*;

    use quickcheck::{Arbitrary, Gen};
    use quickcheck_macros::quickcheck;

    impl Arbitrary for Account {
        fn arbitrary<G: Gen>(g: &mut G) -> Self {
            Self {
                nonce: U256::from(usize::arbitrary(g)),
                balance: U256::from(usize::arbitrary(g)),
                storage_root: H256::from_low_u64_ne(u64::arbitrary(g)),
                code_hash: H256::from_low_u64_ne(u64::arbitrary(g)),
            }
        }
    }

    impl Arbitrary for AccountState {
        fn arbitrary<G: Gen>(g: &mut G) -> Self {
            Self {
                nonce: U256::from(usize::arbitrary(g)),
                balance: U256::from(usize::arbitrary(g)),
                code: Arbitrary::arbitrary(g),
            }
        }
    }

    impl Arbitrary for Code {
        fn arbitrary<G: Gen>(g: &mut G) -> Self {
            Self(Arbitrary::arbitrary(g))
        }
    }

    #[quickcheck]
    fn qc_encode_decode_account_works(account: Account) {
        let bytes = rlp::encode(&account);
        let decoded = rlp::decode::<Account>(bytes.as_ref()).unwrap();
        assert_eq!(account, decoded);
    }

    #[quickcheck]
    fn qc_encode_decode_account_state_works(account_state: AccountState) {
        let bytes = rlp::encode(&account_state);
        let decoded = rlp::decode::<AccountState>(bytes.as_ref()).unwrap();
        assert_eq!(account_state, decoded);
    }
}
