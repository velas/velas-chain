use derive_more::{From, Into};
use itertools::Itertools;
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};

use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};

use triedb::empty_trie_hash;

use crate::TransactionReceipt;
use auto_enums::auto_enum;
use ethbloom::{Bloom, Input};
use evm::backend::Log;
pub use evm::backend::MemoryAccount;
pub use primitive_types::{H160, H256, U256};

pub type BlockNum = u64; // TODO: re-use existing one from sdk package

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

#[derive(Debug)]
pub struct LogFilter {
    pub from_block: u64,
    pub to_block: u64,
    pub address: Option<H160>,
    pub topics: Vec<LogFilterTopicEntry>, // None - mean any topic
}

#[derive(Clone, Debug)]
pub enum LogFilterTopicEntry {
    Any,
    One(H256),
    Or(Vec<H256>),
}

impl LogFilterTopicEntry {
    // Use custom method, because trait didin't support impl Trait
    /// Convert to iterator, set None - when any of topic can be used.
    /// None should be saved to keep order of topic right, on product.
    #[auto_enum(Iterator, Clone)]
    fn into_iter(self) -> impl Iterator<Item = Option<H256>> + Clone {
        match self {
            LogFilterTopicEntry::One(topic) => std::iter::once(Some(topic)),
            LogFilterTopicEntry::Or(b) => b.into_iter().map(Some),
            LogFilterTopicEntry::Any => std::iter::once(None),
        }
    }

    fn match_topic(&self, topic: &H256) -> bool {
        match self {
            Self::Any => true,
            Self::One(self_topic) => self_topic == topic,
            Self::Or(topics) => topics.iter().any(|self_topic| self_topic == topic),
        }
    }
}

// A note on specifying topic filters:

// Topics are order-dependent. A transaction with a log with topics [A, B] will be matched by the following topic filters:

//     [] “anything”
//     [A] “A in first position (and anything after)”
//     [null, B] “anything in first position AND B in second position (and anything after)”
//     [A, B] “A in first position AND B in second position (and anything after)”
//     [[A, B], [A, B]] “(A OR B) in first position AND (A OR B) in second position (and anything after)”

impl LogFilter {
    // TODO: Check topic size in each
    const LIMIT_FILTER_ITEMS: usize = 8;

    /// Convert topics filter to its cartesian_product
    ///
    /// This product can be later combined into array of Bloom filters.
    ///
    /// Example:
    /// [[A, B], [C, B]] become [[A, C], [A, B], [B, C], [B, B]],
    /// [None, [C, B]] become [[None, C], [None, B]],
    ///
    fn topic_product(&self) -> impl Iterator<Item = Vec<Option<H256>>> + '_ {
        self.topics
            .iter()
            .cloned()
            .map(|i| i.into_iter())
            .multi_cartesian_product()
    }

    pub fn bloom_possibilities(&self) -> Vec<Bloom> {
        let bloom_addr = if let Some(address) = self.address {
            Bloom::from(Input::Raw(address.as_bytes()))
        } else {
            Bloom::default()
        };

        if self.topics.is_empty() {
            return vec![bloom_addr];
        }

        self.topic_product()
            .map(|topics| {
                topics
                    .into_iter()
                    .flatten()
                    .fold(bloom_addr, |bloom, topic| {
                        log::info!("Starting bloom = {:?}, adding topic ={:?}", bloom, topic);
                        let result = bloom | Bloom::from(Input::Hash(topic.as_fixed_bytes()));
                        log::info!("Resulting bloom = {:?}", result);
                        result
                    })
            })
            .take(Self::LIMIT_FILTER_ITEMS)
            .collect()
    }

    pub fn is_log_match(&self, log: &Log) -> bool {
        if let Some(address) = self.address {
            if log.address != address {
                return false;
            }
        }
        for (log_topic, self_topic) in log.topics.iter().zip(&self.topics) {
            if !self_topic.match_topic(log_topic) {
                return false;
            }
        }
        true
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockHeader {
    pub parent_hash: H256,
    pub state_root: H256,
    pub native_chain_hash: H256,
    pub transactions: Vec<H256>,
    pub transactions_root: H256,
    pub receipts_root: H256,
    pub logs_bloom: Bloom,
    pub block_number: u64,
    pub gas_limit: u64,
    pub gas_used: u64,
    pub timestamp: u64,
    pub native_chain_slot: u64,
}

// TODO: Add transactions in block
impl BlockHeader {
    pub fn new<'a>(
        parent_hash: H256,
        gas_limit: u64,
        state_root: H256,
        block_number: u64,
        gas_used: u64,
        timestamp: u64,
        native_chain_slot: u64,
        native_chain_hash: H256,
        processed_transactions: impl Iterator<Item = &'a (H256, TransactionReceipt)>,
    ) -> BlockHeader {
        let transaction_receipts: Vec<_> = processed_transactions.collect();
        let transactions: Vec<H256> = transaction_receipts.iter().map(|(k, _)| *k).collect();

        let mut logs_bloom = Bloom::default();
        for (_, receipt) in transaction_receipts {
            logs_bloom.accrue_bloom(&receipt.logs_bloom)
        }

        BlockHeader {
            parent_hash,
            gas_limit,
            block_number,
            gas_used,
            state_root,
            timestamp,
            native_chain_slot,
            native_chain_hash,
            transactions,
            logs_bloom,
            // TODO: Add real transaction receipts and transaction list
            receipts_root: H256::zero(),
            transactions_root: H256::zero(),
        }
    }

    pub fn hash(&self) -> H256 {
        let mut stream = RlpStream::new();
        self.rlp_append(&mut stream);
        H256::from_slice(Keccak256::digest(&stream.as_raw()).as_slice())
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Block {
    pub header: BlockHeader,
    pub transactions: Vec<(crate::H256, TransactionReceipt)>,
}

impl Encodable for BlockHeader {
    fn rlp_append(&self, s: &mut RlpStream) {
        const EMPTH_HASH: H256 = H256::zero();
        const EXTRA_DATA: &[u8; 32] = b"Velas EVM compatibility layer...";
        let extra_data = H256::from_slice(EXTRA_DATA);
        s.begin_list(15);
        s.append(&self.parent_hash);
        s.append(&EMPTH_HASH); // ommers/unkles is impossible
        s.append(&H160::from(EMPTH_HASH)); // Beneficiar address is empty, because reward received in native chain
        s.append(&self.state_root);
        s.append(&self.transactions_root);
        s.append(&self.receipts_root);
        s.append(&self.logs_bloom);
        s.append(&EMPTH_HASH); // difficulty, is emtpy
        s.append(&U256::from(self.block_number));
        s.append(&U256::from(self.gas_limit));
        s.append(&U256::from(self.gas_used));
        s.append(&self.timestamp);
        s.append(&extra_data);
        s.append(&self.native_chain_hash); // mix hash is not available in PoS chains, using native chain hash.
        s.append(&self.native_chain_slot); // nonce like mix hash is not available in PoS, using native chain slot.
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Maybe<T> {
    Just(T),
    Nothing,
}

impl<T> From<Maybe<T>> for Option<T> {
    fn from(rhs: Maybe<T>) -> Option<T> {
        match rhs {
            Maybe::Just(val) => Some(val),
            Maybe::Nothing => None,
        }
    }
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

    #[test]
    fn test_log_entry_iterator() {
        let empty = LogFilterTopicEntry::Any;
        let empty_vec: Vec<_> = empty.into_iter().collect();
        assert_eq!(empty_vec, vec![None]);
        let simple = LogFilterTopicEntry::One(H256::zero());
        let simple_vec: Vec<_> = simple.into_iter().collect();
        assert_eq!(simple_vec, vec![Some(H256::zero())]);
        let multi = LogFilterTopicEntry::Or(vec![
            H256::zero(),
            H256::repeat_byte(1),
            H256::repeat_byte(2),
        ]);
        let multi_vec: Vec<_> = multi.into_iter().collect();
        assert_eq!(
            multi_vec,
            vec![
                Some(H256::zero()),
                Some(H256::repeat_byte(1)),
                Some(H256::repeat_byte(2))
            ]
        )
    }

    #[test]
    fn test_log_entry_filter() {
        let log_entry_empty = LogFilter {
            from_block: 0,
            to_block: 0,
            address: None,
            topics: vec![], // None - mean any topic
        };

        let topic1 = LogFilterTopicEntry::Or(vec![H256::repeat_byte(1), H256::repeat_byte(2)]); // first topic 1 or 2

        let topic2 = LogFilterTopicEntry::Or(vec![
            H256::repeat_byte(3),
            H256::repeat_byte(5),
            H256::repeat_byte(6),
        ]); // second topic 3, 5 or 6
        let topic3 = LogFilterTopicEntry::One(H256::repeat_byte(10));
        let topic4 = LogFilterTopicEntry::Any;
        let log_entry = LogFilter {
            topics: vec![topic1, topic2, topic3, topic4],
            ..log_entry_empty
        };

        let mut iters = log_entry.topic_product();
        assert_eq!(
            iters.next().unwrap(),
            vec![
                Some(H256::repeat_byte(1)),
                Some(H256::repeat_byte(3)),
                Some(H256::repeat_byte(10)),
                None
            ]
        );
    }

    #[test]
    fn test_is_log_match() {
        use std::str::FromStr;
        let fixed_addr = H160::from_str("0x99f3f75da23bb250e4868c7889b8349f8bbfe72b").unwrap();
        let topic1 =
            H256::from_str("0xfb5a77ff5da352f242c9eb0481ce3b43d0289b0daae76d3c67046fc92fb215cc")
                .unwrap();
        let fake_topic1 =
            H256::from_str("0xe762c7c6ad44bf64dd9f998228fe1bf5218e470864dcfff5544c541c5b6c649d")
                .unwrap();
        let fake_topic2 =
            H256::from_str("0xe762c7c6ad44bf64dd9f998228ae1bf5218e470864dcfff5544c541c5b6c649c")
                .unwrap();
        let log_entry_empty = LogFilter {
            from_block: 0,
            to_block: 0,
            address: Some(fixed_addr),
            topics: vec![
                LogFilterTopicEntry::One(fake_topic1),
                LogFilterTopicEntry::One(fake_topic2),
            ], // None - mean any topic
        };

        let log = Log {
            address: fixed_addr,
            topics: vec![topic1],
            data: vec![],
        };
        assert!(!log_entry_empty.is_log_match(&log))
    }
}
