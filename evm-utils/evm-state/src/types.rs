use {
    crate::TransactionReceipt,
    auto_enums::auto_enum,
    derive_more::{AsRef, From, Into},
    ethbloom::{Bloom, Input},
    evm::backend::Log,
    fixed_hash::construct_fixed_hash,
    impl_rlp::impl_fixed_hash_rlp,
    itertools::Itertools,
    rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream},
    serde::{Deserialize, Serialize},
    sha3::{Digest, Keccak256},
    std::convert::TryFrom,
    triedb::empty_trie_hash,
};
pub use {
    evm::backend::MemoryAccount,
    primitive_types::{H160, H256, U256},
};

pub type BlockNum = u64; // TODO: re-use existing one from sdk package

/// Blocks versions.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize, PartialOrd, Ord)]
pub enum BlockVersion {
    /// bogous version without transactions roots, ommers = H256::zero, and nonce as scalar.
    InitVersion,
    ///
    /// Version with fixed transactions root hashes, ommers and nonce values.
    /// All but difficulty/PoW part, should be compatible with ethereum light clients.
    ///
    VersionConsistentHashes,
}

construct_fixed_hash! {
    pub struct H64(8);
}

impl_fixed_hash_rlp! {
    H64, 8
}

impl BlockVersion {
    const BLOCK_VERSION_INIT: u64 = 0;
    const BLOCK_VERSION_CONSISTENT_HASH: u64 = 1;
    pub fn activate_spv_compatibility(&mut self) {
        // don't update if we on future versions
        if *self == BlockVersion::InitVersion {
            *self = BlockVersion::VersionConsistentHashes;
        }
    }
}
impl From<BlockVersion> for u64 {
    fn from(version: BlockVersion) -> u64 {
        match version {
            BlockVersion::InitVersion => BlockVersion::BLOCK_VERSION_INIT,
            BlockVersion::VersionConsistentHashes => BlockVersion::BLOCK_VERSION_CONSISTENT_HASH,
        }
    }
}

impl TryFrom<u64> for BlockVersion {
    type Error = &'static str;

    fn try_from(version: u64) -> Result<BlockVersion, Self::Error> {
        let version = match version {
            BlockVersion::BLOCK_VERSION_INIT => BlockVersion::InitVersion,
            BlockVersion::BLOCK_VERSION_CONSISTENT_HASH => BlockVersion::VersionConsistentHashes,
            _ => return Err("Specific blockversion incompatible"),
        };
        Ok(version)
    }
}

impl Default for BlockVersion {
    fn default() -> Self {
        BlockVersion::InitVersion
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

#[derive(Debug, Default, Clone, PartialEq, Eq, From, Into, AsRef, Serialize, Deserialize)]
pub struct Code(Vec<u8>);

impl Code {
    pub const fn empty() -> Self {
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
    pub block_hash: H256,
    pub log_index: usize,
    pub address: H160,
    pub data: Vec<u8>,
    pub topics: Vec<H256>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LogFilter {
    pub from_block: u64,
    pub to_block: u64,
    pub address: Vec<H160>,
    pub topics: Vec<LogFilterTopicEntry>, // None - mean any topic
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
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
    const LIMIT_ADDRESSES_SIZE: usize = 4;

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
        let bloom_addresses = self
            .address
            .iter()
            .map(|address| Bloom::from(Input::Raw(address.as_bytes())))
            .collect();

        if self.topics.is_empty() {
            return bloom_addresses;
        }

        let bloom_topics = self
            .topic_product()
            .map(|topics| {
                topics
                    .into_iter()
                    .flatten()
                    .fold(Bloom::default(), |bloom, topic| {
                        let result = bloom | Bloom::from(Input::Hash(topic.as_fixed_bytes()));
                        result
                    })
            })
            .take(Self::LIMIT_FILTER_ITEMS)
            .collect();

        // if user ask for too many addresses just query by logs.
        if bloom_addresses.is_empty() || bloom_addresses.len() > Self::LIMIT_ADDRESSES_SIZE {
            return bloom_topics;
        }

        // collect addresses and topics production.
        let mut result = Vec::new();
        for address in bloom_addresses {
            for topic in bloom_topics.iter() {
                result.push(*topic | address)
            }
        }
        result
    }

    pub fn is_log_match(&self, log: &Log) -> bool {
        if !self.address.is_empty() && self.address.iter().all(|address| log.address != *address) {
            return false;
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
    #[serde(deserialize_with = "crate::deserialize_utils::default_on_eof")]
    pub version: BlockVersion,
}

// TODO: Add transactions in block
impl BlockHeader {
    #[allow(clippy::too_many_arguments)]
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
        version: BlockVersion,
    ) -> BlockHeader {
        let transaction_receipts: Vec<_> = processed_transactions.collect();
        let transactions: Vec<H256> = transaction_receipts.iter().map(|(k, _)| *k).collect();

        let mut logs_bloom = Bloom::default();
        for (_, receipt) in &transaction_receipts {
            logs_bloom.accrue_bloom(&receipt.logs_bloom)
        }

        let (receipts_root, transactions_root) = match version {
            BlockVersion::InitVersion => (H256::zero(), H256::zero()),
            BlockVersion::VersionConsistentHashes => (
                transaction_roots::receipts_root(transaction_receipts.iter().map(|(_, tx)| tx)),
                transaction_roots::transactions_root(transaction_receipts.iter().map(|(_, tx)| tx)),
            ),
        };
        BlockHeader {
            parent_hash,
            state_root,
            native_chain_hash,
            transactions,
            transactions_root,
            receipts_root,
            logs_bloom,
            block_number,
            gas_limit,
            gas_used,
            timestamp,
            native_chain_slot,
            version,
        }
    }

    pub fn hash(&self) -> H256 {
        let mut stream = RlpStream::new();
        self.rlp_append(&mut stream);
        H256::from_slice(Keccak256::digest(stream.as_raw()).as_slice())
    }

    pub fn rlp_append_legacy(&self, s: &mut RlpStream) {
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

    pub fn rlp_append_newer(&self, s: &mut RlpStream) {
        const EMPTH_HASH: H256 = H256::zero();
        const ZERO_DIFFICULTY: U256 = U256::zero();
        const EXTRA_DATA: &[u8; 32] = b"Velas EVM compatibility layer.v2";
        let extra_data = H256::from_slice(EXTRA_DATA);
        let nonce = H64::from_low_u64_be(self.native_chain_slot);
        s.begin_list(15);
        s.append(&self.parent_hash);
        s.append(&empty_ommers_hash()); // ommers/unkles is impossible
        s.append(&H160::from(EMPTH_HASH)); // Beneficiar address is empty, because reward received in native chain
        s.append(&self.state_root);
        s.append(&self.transactions_root);
        s.append(&self.receipts_root);
        s.append(&self.logs_bloom);
        s.append(&ZERO_DIFFICULTY); // difficulty, is zero
        s.append(&U256::from(self.block_number));
        s.append(&U256::from(self.gas_limit));
        s.append(&U256::from(self.gas_used));
        s.append(&self.timestamp);
        s.append(&extra_data);
        s.append(&self.native_chain_hash); // mix hash is not available in PoS chains, using native chain hash.
        s.append(&nonce); // nonce like mix hash is not available in PoS, using native chain slot but as 8 bytes array.
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Block {
    pub header: BlockHeader,
    pub transactions: Vec<(crate::H256, TransactionReceipt)>,
}

impl Encodable for BlockHeader {
    fn rlp_append(&self, s: &mut RlpStream) {
        match self.version {
            BlockVersion::InitVersion => self.rlp_append_legacy(s),
            BlockVersion::VersionConsistentHashes => self.rlp_append_newer(s),
        }
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

mod transaction_roots {

    use {
        crate::{Log, TransactionReceipt, H256, U256},
        ethbloom::Bloom,
        rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream},
        triedb::{
            gc::{MapWithCounterCached, TrieCollection},
            FixedTrieMut,
        },
    };

    #[derive(Clone, Debug)]
    pub struct EthereumReceipt {
        pub gas_used: U256,
        pub log_bloom: Bloom,
        pub logs: Vec<Log>,
        pub status: u8,
    }

    impl<'a> From<&'a TransactionReceipt> for EthereumReceipt {
        fn from(receipt: &'a TransactionReceipt) -> Self {
            Self {
                gas_used: receipt.used_gas.into(),
                log_bloom: receipt.logs_bloom,
                logs: receipt.logs.clone(),
                status: u8::from(matches!(receipt.status, crate::ExitReason::Succeed(_))),
            }
        }
    }

    impl Encodable for EthereumReceipt {
        fn rlp_append(&self, s: &mut RlpStream) {
            s.begin_list(4);
            s.append(&self.status);
            s.append(&self.gas_used);
            s.append(&self.log_bloom);
            s.append_list(&self.logs);
        }
    }

    impl Decodable for EthereumReceipt {
        fn decode(rlp: &Rlp<'_>) -> Result<Self, DecoderError> {
            Ok(EthereumReceipt {
                gas_used: rlp.val_at(1)?,
                log_bloom: rlp.val_at(2)?,
                logs: rlp.list_at(3)?,
                status: rlp.val_at(0)?,
            })
        }
    }

    pub fn transactions_root<'a>(receipts: impl Iterator<Item = &'a TransactionReceipt>) -> H256 {
        fn no_childs(_: &[u8]) -> Vec<H256> {
            vec![]
        }
        let trie_c = TrieCollection::new(MapWithCounterCached::default());

        let mut root = trie_c.empty_guard(no_childs);
        for (i, receipt) in receipts.enumerate() {
            let mut trie = FixedTrieMut::<_, U256, _>::new(trie_c.trie_for(root.root));
            let transaction_in_receipt = &receipt.transaction;
            trie.insert(&U256::from(i), transaction_in_receipt);
            let trie = trie.to_trie();

            let patch = trie.into_patch();
            root = trie_c.apply_increase(patch, no_childs);
        }
        root.root
    }

    pub fn receipts_root<'a>(receipts: impl Iterator<Item = &'a TransactionReceipt>) -> H256 {
        fn no_childs(_: &[u8]) -> Vec<H256> {
            vec![]
        }
        let database = MapWithCounterCached::default();
        let trie_c = TrieCollection::new(database);
        let mut root = trie_c.empty_guard(no_childs);
        for (i, receipt) in receipts.enumerate() {
            let mut trie =
                FixedTrieMut::<_, U256, EthereumReceipt>::new(trie_c.trie_for(root.root));
            let ethereum_receipt: EthereumReceipt = receipt.into();
            trie.insert(&U256::from(i), &ethereum_receipt);

            let trie = trie.to_trie();
            let patch = trie.into_patch();
            root = trie_c.apply_increase(patch, no_childs);
        }

        root.root
    }

    #[cfg(test)]
    mod test {
        use super::*;

        #[test]
        fn test_crash_ethereum_receipt() {
            let receipt = EthereumReceipt {
                gas_used: 21000.into(),
                log_bloom: Default::default(),
                logs: vec![],
                status: 0x1,
            };
            let receipts = std::iter::from_fn(|| Some(receipt.clone())).take(129);

            fn no_childs(_: &[u8]) -> Vec<H256> {
                vec![]
            }
            let database = MapWithCounterCached::default();
            let trie_c = TrieCollection::new(database);
            let mut root = trie_c.empty_guard(no_childs);

            for (i, receipt) in receipts.enumerate() {
                let mut trie =
                    FixedTrieMut::<_, U256, EthereumReceipt>::new(trie_c.trie_for(root.root));
                println!("receipt: {:?}", i);
                // let ethereum_receipt: EthereumReceipt = receipt.into();
                trie.insert(&U256::from(i), &receipt);

                let trie = trie.to_trie();
                let patch = trie.into_patch();
                root = trie_c.apply_increase(patch, no_childs);
            }
        }
    }
}

pub fn empty_ommers_hash() -> H256 {
    let encoded = rlp::encode_list::<_, H256>(&[]).to_vec();
    let hash = H256::from_slice(Keccak256::digest(&encoded).as_slice());
    hash
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        crate::{Address, Gas},
        ethabi::ethereum_types,
        quickcheck::{Arbitrary, Gen},
        quickcheck_macros::quickcheck,
        std::str::FromStr,
    };

    // Ethereum header type for tests
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct Header {
        pub parent_hash: H256,
        pub ommers_hash: H256,
        pub beneficiary: Address,
        pub state_root: H256,
        pub transactions_root: H256,
        pub receipts_root: H256,
        pub logs_bloom: ethereum_types::Bloom,
        pub difficulty: U256,
        pub number: U256,
        pub gas_limit: Gas,
        pub gas_used: Gas,
        pub timestamp: u64,
        pub extra_data: Vec<u8>,
        pub mix_hash: H256,
        pub nonce: H64,
    }

    impl Encodable for Header {
        fn rlp_append(&self, s: &mut RlpStream) {
            s.begin_list(15);
            s.append(&self.parent_hash);
            s.append(&self.ommers_hash);
            s.append(&self.beneficiary);
            s.append(&self.state_root);
            s.append(&self.transactions_root);
            s.append(&self.receipts_root);
            s.append(&self.logs_bloom);
            s.append(&self.difficulty);
            s.append(&self.number);
            s.append(&self.gas_limit);
            s.append(&self.gas_used);
            s.append(&self.timestamp);
            s.append(&self.extra_data);
            s.append(&self.mix_hash);
            s.append(&self.nonce);
        }
    }

    impl Decodable for Header {
        fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
            Ok(Self {
                parent_hash: rlp.val_at(0)?,
                ommers_hash: rlp.val_at(1)?,
                beneficiary: rlp.val_at(2)?,
                state_root: rlp.val_at(3)?,
                transactions_root: rlp.val_at(4)?,
                receipts_root: rlp.val_at(5)?,
                logs_bloom: rlp.val_at(6)?,
                difficulty: rlp.val_at(7)?,
                number: rlp.val_at(8)?,
                gas_limit: rlp.val_at(9)?,
                gas_used: rlp.val_at(10)?,
                timestamp: rlp.val_at(11)?,
                extra_data: rlp.val_at(12)?,
                mix_hash: rlp.val_at(13)?,
                nonce: rlp.val_at(14)?,
            })
        }
    }

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
            address: vec![],
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
            address: vec![fixed_addr],
            topics: vec![
                LogFilterTopicEntry::One(fake_topic1),
                LogFilterTopicEntry::One(fake_topic2),
            ],
        };

        let log = Log {
            address: fixed_addr,
            topics: vec![topic1],
            data: vec![],
        };
        assert!(!log_entry_empty.is_log_match(&log))
    }

    #[test]
    fn test_is_log_match_empty_addr_topic() {
        use std::str::FromStr;
        let fixed_addr = H160::from_str("0x99f3f75da23bb250e4868c7889b8349f8bbfe72b").unwrap();
        let topic1 =
            H256::from_str("0xfb5a77ff5da352f242c9eb0481ce3b43d0289b0daae76d3c67046fc92fb215cc")
                .unwrap();
        let log_entry_empty1 = LogFilter {
            from_block: 0,
            to_block: 0,
            address: vec![],
            topics: vec![LogFilterTopicEntry::One(topic1)],
        };
        let log_entry_empty2 = LogFilter {
            from_block: 0,
            to_block: 0,
            address: vec![fixed_addr],
            topics: vec![], // None - mean any topic
        };

        let log = Log {
            address: fixed_addr,
            topics: vec![topic1],
            data: vec![],
        };
        assert!(log_entry_empty1.is_log_match(&log));
        assert!(log_entry_empty2.is_log_match(&log))
    }

    #[test]
    fn test_empty_ommers() {
        let empty_ommers =
            H256::from_str("1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347")
                .unwrap();
        assert!(empty_ommers_hash() == empty_ommers)
    }

    #[test]
    fn block_1_testnet_legacy_rlp() {
        let first_tx = crate::transactions::Transaction {
            nonce: 0xc.into(),
            gas_price: 0x1.into(),
            gas_limit: 0x5448.into(),
            value: U256::from_str("cb49b44ba602d800000").unwrap(),
            input: vec![
                0xb1, 0xd6, 0x92, 0x7a, 0x76, 0x2f, 0xea, 0xd9, 0x87, 0x56, 0xa1, 0x2b, 0x13, 0xb7,
                0x1c, 0x64, 0x45, 0xf8, 0x3a, 0xfa, 0x25, 0x0d, 0x47, 0xc9, 0xc2, 0x29, 0x76, 0x93,
                0x4a, 0x84, 0x02, 0xfc, 0xa1, 0x1b, 0x98, 0xe5,
            ],
            action: crate::transactions::TransactionAction::Call(
                H160::from_str("56454c41532d434841494e000000000053574150").unwrap(),
            ),
            signature: crate::transactions::TransactionSignature {
                v: 0x102,
                r: H256::from_str(
                    "649a29de0b5fce4e8063ae8a11138415bd82df7282618aebe0ec2d0d6c7cd174",
                )
                .unwrap(),
                s: H256::from_str(
                    "47d645e27d0d3d3b436cf7f209cabb8cae40c508ce372e3f7cf602cdfbb93b5c",
                )
                .unwrap(),
            },
        };
        let tx_hash = first_tx.signing_hash();
        let first_tx = crate::transactions::TransactionReceipt {
            transaction: crate::transactions::TransactionInReceipt::Signed(first_tx),
            block_number: 0x1,
            index: 0x1,
            logs: vec![],
            logs_bloom: ethbloom::Bloom::zero(),
            used_gas: 0x5448,
            status: crate::ExitReason::Succeed(crate::ExitSucceed::Returned),
        };

        let transactions = vec![(tx_hash, first_tx)];
        let block = BlockHeader::new(
            H256::from_str("0000000000000000000000000000000000000000000000000000000000000000")
                .unwrap(),
            0x11e1a300,
            H256::from_str("de51bcb676b5b88624f3b9f57e8e5dcf8683d1ce61fd2bcc9ba390155311391c")
                .unwrap(),
            0x1,
            0x5448,
            0x607493ea,
            0x0000000000000289,
            H256::from_str("3a64b9f3f6ef73ee021782c41b95d4c2c6ed04c6c47613d65cdc545fec4287b5")
                .unwrap(),
            transactions.iter(),
            BlockVersion::InitVersion,
        );
        assert_eq!(
            block.hash(),
            H256::from_str("99abf192da896d54e451601439d9e81b68f188f2289df2f8a5a61114469123db")
                .unwrap()
        );
    }

    #[test]
    fn block_1_testnet_newest_rlp_without_tx() {
        let transactions = vec![];
        let block = BlockHeader::new(
            H256::from_str("0000000000000000000000000000000000000000000000000000000000000000")
                .unwrap(),
            0x11e1a300,
            H256::from_str("de51bcb676b5b88624f3b9f57e8e5dcf8683d1ce61fd2bcc9ba390155311391c")
                .unwrap(),
            0x1,
            0x5448,
            0x607493ea,
            0x0000000000000289,
            H256::from_str("3a64b9f3f6ef73ee021782c41b95d4c2c6ed04c6c47613d65cdc545fec4287b5")
                .unwrap(),
            transactions.iter(),
            BlockVersion::VersionConsistentHashes,
        );

        let block_bytes = block.rlp_bytes();
        println!("debug {:x}", block_bytes);
        let rlp = Rlp::new(&block_bytes);
        let header: Header = rlp.as_val().unwrap();
        assert_eq!(
            Keccak256::digest(&rlp::encode(&header).to_vec()).as_slice(),
            block.hash().as_bytes()
        );

        assert_eq!(
            block.hash(),
            H256::from_str("81cb658d3064dabac80c1cc8a1832b39d2d8a1da6185146662eaa1b237a8e59d")
                .unwrap()
        );
    }

    #[test]
    fn block_1_testnet_newest_rlp_with_tx() {
        let first_tx = crate::transactions::Transaction {
            nonce: 0xc.into(),
            gas_price: 0x1.into(),
            gas_limit: 0x5448.into(),
            value: U256::from_str("cb49b44ba602d800000").unwrap(),
            input: vec![
                0xb1, 0xd6, 0x92, 0x7a, 0x76, 0x2f, 0xea, 0xd9, 0x87, 0x56, 0xa1, 0x2b, 0x13, 0xb7,
                0x1c, 0x64, 0x45, 0xf8, 0x3a, 0xfa, 0x25, 0x0d, 0x47, 0xc9, 0xc2, 0x29, 0x76, 0x93,
                0x4a, 0x84, 0x02, 0xfc, 0xa1, 0x1b, 0x98, 0xe5,
            ],
            action: crate::transactions::TransactionAction::Call(
                H160::from_str("56454c41532d434841494e000000000053574150").unwrap(),
            ),
            signature: crate::transactions::TransactionSignature {
                v: 0x102,
                r: H256::from_str(
                    "649a29de0b5fce4e8063ae8a11138415bd82df7282618aebe0ec2d0d6c7cd174",
                )
                .unwrap(),
                s: H256::from_str(
                    "47d645e27d0d3d3b436cf7f209cabb8cae40c508ce372e3f7cf602cdfbb93b5c",
                )
                .unwrap(),
            },
        };
        let tx_hash = first_tx.signing_hash();
        let first_tx = crate::transactions::TransactionReceipt {
            transaction: crate::transactions::TransactionInReceipt::Signed(first_tx),
            block_number: 0x1,
            index: 0x1,
            logs: vec![],
            logs_bloom: ethbloom::Bloom::zero(),
            used_gas: 0x5448,
            status: crate::ExitReason::Succeed(crate::ExitSucceed::Returned),
        };

        let transactions = vec![(tx_hash, first_tx)];
        let block = BlockHeader::new(
            H256::from_str("0000000000000000000000000000000000000000000000000000000000000000")
                .unwrap(),
            0x11e1a300,
            H256::from_str("de51bcb676b5b88624f3b9f57e8e5dcf8683d1ce61fd2bcc9ba390155311391c")
                .unwrap(),
            0x1,
            0x5448,
            0x607493ea,
            0x0000000000000289,
            H256::from_str("3a64b9f3f6ef73ee021782c41b95d4c2c6ed04c6c47613d65cdc545fec4287b5")
                .unwrap(),
            transactions.iter(),
            BlockVersion::VersionConsistentHashes,
        );

        let block_bytes = block.rlp_bytes();
        println!("debug {:x}", block_bytes);

        let rlp = Rlp::new(&block_bytes);
        let header: Header = rlp.as_val().unwrap();
        assert_eq!(
            Keccak256::digest(&rlp::encode(&header).to_vec()).as_slice(),
            block.hash().as_bytes()
        );

        assert_eq!(
            block.hash(),
            H256::from_str("f876809374f63d085da228d82576dc7be56e942b88d769c2174c27cb5249a1ec")
                .unwrap()
        );
    }
}
