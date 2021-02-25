use derive_more::{From, Into};
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};

use triedb::empty_trie_hash;

pub use primitive_types::{H160, H256, U256};

pub type Slot = u64; // TODO: re-use existing one from sdk package

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransactionChunks(Vec<Option<u8>>);

impl TransactionChunks {
    pub fn new(size: usize) -> Self {
        Self(std::iter::repeat(None).take(size).collect())
    }

    pub fn extend(&mut self, offset: usize, data: impl AsRef<[u8]>) {
        let data = data.as_ref();

        assert!(offset + data.len() <= self.0.len());

        self.0[offset..(offset + data.len())]
            .iter_mut()
            .zip(data.iter())
            .for_each(|(hole, byte)| {
                if hole.is_some() {
                    log::warn!("Overriding some already existed data in transaction chunks");
                }
                *hole = Some(*byte);
            });
    }

    pub fn size(&self) -> usize {
        self.0.len()
    }

    fn is_complete(&self) -> bool {
        self.0.iter().all(|hole| hole.is_some())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Into)]
pub struct CompleteTransaction(Vec<u8>);

impl From<TransactionChunks> for CompleteTransaction {
    fn from(chunks: TransactionChunks) -> Self {
        if !chunks.is_complete() {
            log::warn!("Making complete transaction from chunks with holes");
        }

        Self(chunks.0.into_iter().map(|hole| hole.unwrap_or(0)).collect())
    }
}

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

/// Vivinity value of a memory backend.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MemoryVicinity {
    /// Gas price.
    pub gas_price: U256,
    /// Origin.
    pub origin: H160,
    /// Chain ID.
    pub chain_id: U256,
    /// Environmental block hashes.
    pub block_hashes: Vec<H256>,
    /// Environmental block number.
    pub block_number: U256,
    /// Environmental coinbase.
    pub block_coinbase: H160,
    /// Environmental block timestamp.
    pub block_timestamp: U256,
    /// Environmental block difficulty.
    pub block_difficulty: U256,
    /// Environmental block gas limit.
    pub block_gas_limit: U256,
}

impl Default for MemoryVicinity {
    fn default() -> Self {
        Self {
            gas_price: U256::zero(),
            origin: H160::default(),
            chain_id: U256::zero(),
            block_hashes: Vec::new(),
            block_number: U256::zero(),
            block_coinbase: H160::default(),
            block_timestamp: U256::zero(),
            block_difficulty: U256::zero(),
            block_gas_limit: U256::max_value(),
        }
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
