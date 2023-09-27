#![allow(clippy::upper_case_acronyms)]

use {
    jsonrpc_core::BoxFuture,
    jsonrpc_derive::rpc,
    primitive_types::{H256, U256},
    serde::{Deserialize, Serialize},
    snafu::ResultExt,
    std::{collections::HashMap, fmt},
};

mod serialize;
use {
    self::error::EvmStateError,
    evm_state::{
        Address, Block, BlockHeader, ExitSucceed, Gas, LogFilterTopicEntry, LogWithLocation,
        TransactionInReceipt,
    },
};

pub mod error;
pub use self::{error::Error, serialize::*};

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(untagged)]
pub enum Either<T, U> {
    Left(T),
    Right(U),
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(untagged)]
pub enum RPCTopicFilter {
    Single(H256),
    Or(Vec<H256>),
}

impl RPCTopicFilter {
    #[allow(clippy::wrong_self_convention)]
    pub fn into_topics(value: Option<RPCTopicFilter>) -> LogFilterTopicEntry {
        match value {
            Some(RPCTopicFilter::Single(t)) => LogFilterTopicEntry::One(t),
            Some(RPCTopicFilter::Or(t)) => LogFilterTopicEntry::Or(t),
            None => LogFilterTopicEntry::Any,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct RPCLogFilter {
    pub from_block: Option<BlockId>,
    pub to_block: Option<BlockId>,
    pub address: Option<Either<Vec<Address>, Address>>,
    pub topics: Option<Vec<Option<RPCTopicFilter>>>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct RPCLog {
    pub removed: bool,
    pub log_index: Hex<usize>,
    pub transaction_index: Hex<usize>,
    pub transaction_hash: H256,
    pub block_hash: H256,
    pub block_number: U256,
    pub address: Address,
    pub data: Bytes,
    pub topics: Vec<H256>,
}
impl From<RPCLog> for evm_state::Log {
    fn from(rpc: RPCLog) -> evm_state::Log {
        evm_state::Log {
            data: rpc.data.0,
            topics: rpc.topics,
            address: rpc.address,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct RPCBlock {
    pub number: U256,
    pub hash: H256,
    pub parent_hash: H256,

    pub size: Hex<usize>,
    pub gas_limit: Gas,
    pub gas_used: Gas,
    pub timestamp: Hex<u64>,
    pub transactions: Either<Vec<H256>, Vec<RPCTransaction>>,
    pub is_finalized: bool,

    pub transactions_root: H256,
    pub state_root: H256,
    pub receipts_root: H256,
    #[serde(with = "serialize::hex_serde::padded")]
    pub nonce: u64,
    pub mix_hash: H256,

    pub sha3_uncles: H256,
    pub logs_bloom: ethbloom::Bloom, // H2048

    pub miner: Address,
    pub difficulty: U256,
    pub total_difficulty: U256,
    pub extra_data: Bytes,
    pub uncles: Vec<H256>,
}
impl Default for RPCBlock {
    fn default() -> Self {
        let empty_uncle: H256 =
            H256::from_hex("0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347")
                .unwrap();
        RPCBlock {
            number: U256::zero(),
            hash: H256::zero(),
            parent_hash: H256::repeat_byte(0xff),
            size: 0x100.into(),
            gas_limit: U256::one(), // avoid divide by zero on explorer, if it calculate percent used.
            gas_used: U256::zero(),
            timestamp: 0.into(),
            transactions: Either::Left(vec![]),
            nonce: 0,
            mix_hash: H256::zero(),
            logs_bloom: ethbloom::Bloom::zero(), // H2048
            transactions_root: H256::zero(),
            state_root: H256::zero(),
            receipts_root: H256::zero(),
            is_finalized: true,
            miner: Address::zero(),
            difficulty: U256::zero(),
            total_difficulty: U256::zero(),
            uncles: vec![],
            extra_data: b"Velas EVM compatibility layer...".to_vec().into(),
            sha3_uncles: empty_uncle,
        }
    }
}

impl RPCBlock {
    pub fn new_from_head(
        header: evm_state::BlockHeader,
        confirmed: bool,
        transactions: Either<Vec<H256>, Vec<RPCTransaction>>,
    ) -> Self {
        let empty_uncle = evm_state::empty_ommers_hash();
        let block_hash = header.hash();
        let extra_data = match header.version {
            evm_state::BlockVersion::InitVersion => {
                b"Velas EVM compatibility layer...".to_vec().into()
            }
            evm_state::BlockVersion::VersionConsistentHashes => {
                b"Velas EVM compatibility layer.v2".to_vec().into()
            }
        };
        RPCBlock {
            number: U256::from(header.block_number),
            hash: block_hash,
            parent_hash: header.parent_hash,
            gas_limit: header.gas_limit.into(),
            gas_used: header.gas_used.into(),
            timestamp: Hex(header.timestamp),
            transactions,
            nonce: header.native_chain_slot,
            mix_hash: header.native_chain_hash,
            logs_bloom: header.logs_bloom, // H2048
            transactions_root: header.transactions_root,
            state_root: header.state_root,
            receipts_root: header.receipts_root,
            extra_data,
            is_finalized: confirmed,
            size: 0x100.into(),
            miner: Address::zero(),
            difficulty: U256::zero(),
            total_difficulty: U256::zero(),
            sha3_uncles: empty_uncle,
            uncles: vec![],
        }
    }

    pub fn to_native_block(&self, version: evm_state::BlockVersion) -> evm_state::BlockHeader {
        evm_state::BlockHeader {
            state_root: self.state_root,
            transactions_root: self.transactions_root,
            receipts_root: self.receipts_root,
            native_chain_hash: self.mix_hash,
            native_chain_slot: self.nonce,
            parent_hash: self.parent_hash,
            transactions: vec![],
            logs_bloom: self.logs_bloom,
            block_number: self.number.as_u64(),
            gas_limit: self.gas_limit.as_u64(),
            gas_used: self.gas_used.as_u64(),
            timestamp: self.timestamp.0,
            version,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct RPCTransaction {
    pub from: Option<Address>,
    pub to: Option<Address>,
    pub creates: Option<Address>,
    pub gas: Option<Gas>,
    pub gas_price: Option<Gas>,
    pub value: Option<U256>,
    #[serde(alias = "data")]
    pub input: Option<Bytes>,
    pub nonce: Option<U256>,

    pub hash: Option<H256>,
    pub block_hash: Option<H256>,
    pub block_number: Option<U256>,
    pub transaction_index: Option<Hex<usize>>,
    #[serde(alias = "V")]
    pub v: Option<Hex<u64>>,
    #[serde(alias = "R")]
    pub r: Option<U256>,
    #[serde(alias = "S")]
    pub s: Option<U256>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct RPCReceipt {
    pub transaction_hash: H256,
    pub transaction_index: Hex<usize>,
    pub block_hash: H256,
    pub block_number: U256,
    pub cumulative_gas_used: Gas,
    pub gas_used: Gas,
    pub contract_address: Option<Address>,
    pub logs_bloom: ethbloom::Bloom, // H2048
    pub to: Option<Address>,
    pub from: Option<Address>,
    pub logs: Vec<RPCLog>,
    pub status: Hex<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<jsonrpc_core::Error>,
}
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct RPCTrace {
    pub gas: Gas,
    pub return_value: Bytes,
    pub struct_logs: Vec<RPCStep>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
#[serde(rename_all = "camelCase")]
pub struct RPCTraceConfig {
    #[serde(default)]
    pub disable_memory: bool,
    #[serde(default)]
    pub disable_stack: bool,
    #[serde(default)]
    pub disable_storage: bool,
    #[serde(default)]
    pub breakpoints: Option<RPCBreakpointConfig>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
#[serde(rename_all = "camelCase")]
pub struct RPCBreakpointConfig {
    pub source_map: HashMap<H256, RPCSourceMapConfig>,
    pub breakpoints: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct RPCSourceMapConfig {
    pub source_map: String,
    pub source_list: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct RPCBlockTrace {
    pub struct_logs: Vec<RPCStep>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct RPCStep {
    pub depth: usize,
    pub error: String,
    pub gas: Gas,
    pub gas_cost: Gas,
    pub op: u8,
    pub pc: usize,
    pub opcode_pc: usize,
    pub code_hash: H256,
    pub address: Address,
    pub breakpoint_index: Option<usize>,
    pub breakpoint: Option<String>,
    pub memory: Option<Vec<Bytes>>,
    pub stack: Option<Vec<U256>>,
    pub storage: Option<HashMap<U256, U256>>,
}

// #[derive(Serialize, Deserialize, Debug, Clone)]
// #[serde(rename_all = "camelCase")]
// pub struct RPCDump {
//     pub accounts: HashMap<Address, RPCDumpAccount>,
//     pub root: H256,
// }

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct RPCDumpAccountBasic {
    pub balance: U256,
    // pub code: Bytes,
    // pub code_hash: H256,
    pub nonce: U256,
    // pub root: H256,
    // pub storage: HashMap<U256, U256>,
}

#[derive(Eq, PartialEq, Serialize, Deserialize, Debug, Clone, Copy)]
#[serde(untagged)]
pub enum BlockId {
    Num(Hex<u64>),
    BlockHash {
        #[serde(rename = "blockHash")]
        block_hash: H256,
    },
    RelativeId(BlockRelId),
}

impl fmt::Display for BlockId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Num(n) => write!(f, "{}", n.format_hex()),
            Self::BlockHash { block_hash } => {
                write!(f, "{{ block_hash:{} }}", block_hash.format_hex())
            }
            Self::RelativeId(id) => write!(f, "{}", id),
        }
    }
}

#[derive(Eq, PartialEq, Serialize, Deserialize, Debug, Clone, Copy)]
#[serde(rename_all = "camelCase")]
pub enum BlockRelId {
    Latest,
    Pending,
    Earliest,
}

impl fmt::Display for BlockRelId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let str_id = match self {
            Self::Latest => "latest",
            Self::Pending => "pending",
            Self::Earliest => "earliest",
        };
        write!(f, "{}", str_id)
    }
}

impl Default for BlockId {
    fn default() -> Self {
        Self::RelativeId(BlockRelId::Latest)
    }
}

impl From<u64> for BlockId {
    fn from(b: u64) -> BlockId {
        BlockId::Num(Hex(b))
    }
}
pub mod trace {
    use super::*;

    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct Res {
        gas_used: U256,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "address")]
        contract: Option<Address>,
        #[serde(skip_serializing_if = "Option::is_none")]
        output: Option<Bytes>,
        #[serde(skip_serializing_if = "Option::is_none")]
        code: Option<Bytes>,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(tag = "type", content = "action")]
    #[serde(rename_all = "snake_case")]
    pub enum Action {
        Call {
            from: Address,
            to: Address,
            value: U256,
            gas: U256,
            input: Bytes,
            // #[serde(skip_serializing_if = "Option::is_none")]
            #[serde(rename = "callType")]
            call_type: CallScheme,
        },
        Create {
            #[serde(rename = "from")]
            caller: Address,
            value: U256,
            gas: U256,
            #[serde(rename = "init")]
            init_code: Bytes,
            #[serde(rename = "creationMethod")]
            creation_method: CreateScheme,
        },
        // TODO: Trace suicide?!
        // Suicide {
        //     address: Address,
        //     refund_address: Address,
        //     balance: U256,
        // },
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct Trace {
        #[serde(flatten)]
        pub action: Action,
        pub result: Res,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub error: Option<String>,
        pub subtraces: Hex<usize>,
        pub trace_address: Vec<usize>,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct TraceResultsWithTransactionHash {
        pub output: Bytes,
        pub trace: Vec<Trace>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub block_hash: Option<H256>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub block_number: Option<U256>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub transaction_hash: Option<H256>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub transaction_index: Option<Hex<usize>>,
    }

    #[derive(Debug, Clone, Copy, Serialize, Deserialize)]
    #[serde(rename_all = "lowercase")]
    pub enum CallScheme {
        Call,
        CallCode,
        DelegateCall,
        StaticCall,
    }

    #[derive(Debug, Clone, Copy, Serialize, Deserialize)]
    #[serde(rename_all = "lowercase")]
    pub enum CreateScheme {
        Create,
        Create2,
        Unimplemented,
    }

    impl From<evm_state::CallScheme> for CallScheme {
        fn from(scheme: evm_state::CallScheme) -> Self {
            match scheme {
                evm_state::CallScheme::Call => Self::Call,
                evm_state::CallScheme::CallCode => Self::CallCode,
                evm_state::CallScheme::DelegateCall => Self::DelegateCall,
                evm_state::CallScheme::StaticCall => Self::StaticCall,
            }
        }
    }
    impl From<evm_state::CreateScheme> for CreateScheme {
        fn from(scheme: evm_state::CreateScheme) -> Self {
            match scheme {
                evm_state::CreateScheme::Legacy { .. } => Self::Create,
                evm_state::CreateScheme::Create2 { .. } => Self::Create2,
                _ => Self::Unimplemented,
            }
        }
    }
    impl From<evm_state::executor::Trace> for Trace {
        fn from(trace: evm_state::executor::Trace) -> Self {
            let (result, error) = Self::result_from(trace.result);
            Self {
                action: trace.action.into(),
                result,
                error,
                subtraces: trace.subtraces.into(),
                trace_address: trace.trace_address,
            }
        }
    }
    impl From<evm_state::executor::Action> for Action {
        fn from(action: evm_state::executor::Action) -> Self {
            match action {
                evm_state::executor::Action::Call {
                    code,
                    input,
                    context,
                    gas,
                    call_type,
                } => Self::Call {
                    input: input.into(),
                    from: context.caller,
                    to: code,
                    gas,
                    value: context.apparent_value,
                    call_type: call_type.map(From::from).unwrap_or(CallScheme::Call),
                },
                evm_state::executor::Action::Create {
                    caller,
                    value,
                    gas,
                    init_code,
                    creation_method,
                } => Self::Create {
                    caller,
                    value,
                    gas,
                    init_code: init_code.into(),
                    creation_method: creation_method.into(),
                },
            }
        }
    }
    impl Trace {
        fn result_from(result: evm_state::executor::Res) -> (Res, Option<String>) {
            // TODO: Add rest errors panic!()/todo!(), and other keywords for better search.
            let error = match result.reason {
                evm_state::ExitReason::Succeed(_) => None,
                evm_state::ExitReason::Revert(_) => {
                    let reason = super::error::format_data(&Bytes(result.output.clone()));
                    Some(if reason.is_empty() {
                        String::from("Execution reverted")
                    } else {
                        format!("Execution reverted:{}", reason)
                    })
                }
                evm_state::ExitReason::Error(evm_state::ExitError::OutOfGas) => {
                    Some(String::from("Out of gas"))
                }
                evm_state::ExitReason::Error(evm_state::ExitError::InvalidJump) => {
                    Some(String::from("Invalid jump"))
                }
                evm_state::ExitReason::Error(evm_state::ExitError::StackUnderflow) => {
                    Some(String::from("Stack underflow"))
                }
                evm_state::ExitReason::Error(evm_state::ExitError::StackOverflow) => {
                    Some(String::from("Stack overflow"))
                }
                evm_state::ExitReason::Error(evm_state::ExitError::DesignatedInvalid) => {
                    Some(String::from("Invalid instruction"))
                }
                evm_state::ExitReason::Error(e) => Some(format!("Internal error: {:?}", e)),
                evm_state::ExitReason::Fatal(f) => Some(format!("Fatal error: {:?}", f)),
            };
            let (output, code) = if error.is_some() {
                (None, None)
            } else if result.contract.is_none() {
                // If contract, output = code
                (Some(result.output.into()), None)
            } else {
                (None, Some(result.output.into()))
            };
            (
                Res {
                    gas_used: result.gas_used,
                    contract: result.contract,
                    code,
                    output,
                },
                error,
            )
        }
    }

    #[derive(Debug, Default, Clone, Serialize, Deserialize)]
    pub struct TraceMeta {
        pub meta_keys: Option<Vec<String>>,
        pub transaction_hash: Option<H256>,
        pub transaction_index: Option<usize>,
        pub block_hash: Option<H256>,
        pub block_number: Option<U256>,
    }

    #[rpc]
    pub trait TraceERPC {
        type Metadata;

        #[rpc(meta, name = "trace_call")]
        fn trace_call(
            &self,
            meta: Self::Metadata,
            tx: RPCTransaction,
            traces: Vec<String>,
            block: Option<BlockId>,
            meta_info: Option<TraceMeta>,
        ) -> BoxFuture<Result<TraceResultsWithTransactionHash, Error>>;

        #[rpc(meta, name = "trace_callMany")]
        fn trace_call_many(
            &self,
            meta: Self::Metadata,
            tx_traces: Vec<(RPCTransaction, Vec<String>, Option<TraceMeta>)>,
            block: Option<BlockId>,
        ) -> BoxFuture<Result<Vec<TraceResultsWithTransactionHash>, Error>>;

        #[rpc(meta, name = "trace_replayTransaction")]
        fn trace_replay_transaction(
            &self,
            meta: Self::Metadata,
            tx_hash: H256,
            traces: Vec<String>,
            meta_info: Option<TraceMeta>,
        ) -> BoxFuture<Result<Option<TraceResultsWithTransactionHash>, Error>>;

        #[rpc(meta, name = "trace_replayBlockTransactions")]
        fn trace_replay_block(
            &self,
            meta: Self::Metadata,
            block: BlockId,
            traces: Vec<String>,
            meta_info: Option<TraceMeta>,
        ) -> BoxFuture<Result<Vec<TraceResultsWithTransactionHash>, Error>>;

        #[allow(clippy::too_many_arguments)]
        #[allow(clippy::type_complexity)]
        #[rpc(meta, name = "debug_recoverBlockHeader")]
        fn recover_block_header(
            &self,
            meta: Self::Metadata,
            txs: Vec<(RPCTransaction, Vec<String>)>,
            last_hashes: Vec<H256>,
            block_header: BlockHeader,
            state_root: H256,
            unsigned_tx_fix: bool,
            clear_logs_on_error: bool,
            accept_zero_gas_price_with_native_fee: bool,
            burn_gas_price: u64,
        ) -> BoxFuture<Result<(Block, Vec<H256>), Error>>;
    }
}

pub use {bridge::BridgeERPC, chain::ChainERPC, general::GeneralERPC, trace::TraceERPC};

pub mod general {
    use super::*;

    #[rpc]
    pub trait GeneralERPC {
        type Metadata;

        #[rpc(meta, name = "web3_clientVersion")]
        fn client_version(&self, meta: Self::Metadata) -> Result<String, Error>;

        #[rpc(meta, name = "web3_sha3")]
        fn sha3(&self, meta: Self::Metadata, bytes: Bytes) -> Result<H256, Error>;

        #[rpc(meta, name = "net_version")]
        fn network_id(&self, meta: Self::Metadata) -> Result<String, Error>;

        #[rpc(meta, name = "net_listening")]
        fn is_listening(&self, meta: Self::Metadata) -> Result<bool, Error>;

        #[rpc(meta, name = "net_peerCount")]
        fn peer_count(&self, meta: Self::Metadata) -> Result<Hex<usize>, Error>;

        #[rpc(meta, name = "eth_chainId")]
        fn chain_id(&self, meta: Self::Metadata) -> Result<Hex<u64>, Error>;

        #[rpc(meta, name = "eth_protocolVersion")]
        fn protocol_version(&self, meta: Self::Metadata) -> Result<String, Error>;

        #[rpc(meta, name = "eth_syncing")]
        fn is_syncing(&self, meta: Self::Metadata) -> Result<bool, Error>;

        #[rpc(meta, name = "eth_coinbase")]
        fn coinbase(&self, meta: Self::Metadata) -> Result<Address, Error>;

        #[rpc(meta, name = "eth_mining")]
        fn is_mining(&self, meta: Self::Metadata) -> Result<bool, Error>;

        #[rpc(meta, name = "eth_hashrate")]
        fn hashrate(&self, meta: Self::Metadata) -> Result<U256, Error>;

        #[rpc(meta, name = "eth_gasPrice")]
        fn gas_price(&self, meta: Self::Metadata) -> Result<Gas, Error>;
    }
}

pub mod chain {
    use super::*;

    #[rpc]
    pub trait ChainERPC {
        type Metadata;

        #[rpc(meta, name = "eth_blockNumber")]
        fn block_number(&self, meta: Self::Metadata) -> BoxFuture<Result<Hex<usize>, Error>>;

        #[rpc(meta, name = "eth_getBalance")]
        fn balance(
            &self,
            meta: Self::Metadata,
            address: Address,
            block: Option<BlockId>,
        ) -> BoxFuture<Result<U256, Error>>;

        #[rpc(meta, name = "eth_getStorageAt")]
        fn storage_at(
            &self,
            meta: Self::Metadata,
            address: Address,
            data: U256,
            block: Option<BlockId>,
        ) -> BoxFuture<Result<H256, Error>>;

        #[rpc(meta, name = "eth_getTransactionCount")]
        fn transaction_count(
            &self,
            meta: Self::Metadata,
            address: Address,
            block: Option<BlockId>,
        ) -> BoxFuture<Result<U256, Error>>;

        #[rpc(meta, name = "eth_getBlockTransactionCountByHash")]
        fn block_transaction_count_by_hash(
            &self,
            meta: Self::Metadata,
            block_hash: H256,
        ) -> BoxFuture<Result<Hex<usize>, Error>>;

        #[rpc(meta, name = "eth_getBlockTransactionCountByNumber")]
        fn block_transaction_count_by_number(
            &self,
            meta: Self::Metadata,
            block: BlockId,
        ) -> BoxFuture<Result<Hex<usize>, Error>>;

        #[rpc(meta, name = "eth_getCode")]
        fn code(
            &self,
            meta: Self::Metadata,
            address: Address,
            block: Option<BlockId>,
        ) -> BoxFuture<Result<Bytes, Error>>;

        #[rpc(meta, name = "eth_getBlockByHash")]
        fn block_by_hash(
            &self,
            meta: Self::Metadata,
            block_hash: H256,
            full: bool,
        ) -> BoxFuture<Result<Option<RPCBlock>, Error>>;

        #[rpc(meta, name = "eth_getBlockByNumber")]
        fn block_by_number(
            &self,
            meta: Self::Metadata,
            block: BlockId,
            full: bool,
        ) -> BoxFuture<Result<Option<RPCBlock>, Error>>;

        #[rpc(meta, name = "eth_getTransactionByHash")]
        fn transaction_by_hash(
            &self,
            meta: Self::Metadata,
            tx_hash: H256,
        ) -> BoxFuture<Result<Option<RPCTransaction>, Error>>;

        #[rpc(meta, name = "eth_getTransactionByBlockHashAndIndex")]
        fn transaction_by_block_hash_and_index(
            &self,
            meta: Self::Metadata,
            block_hash: H256,
            tx_id: Hex<usize>,
        ) -> BoxFuture<Result<Option<RPCTransaction>, Error>>;

        #[rpc(meta, name = "eth_getTransactionByBlockNumberAndIndex")]
        fn transaction_by_block_number_and_index(
            &self,
            meta: Self::Metadata,
            block: BlockId,
            tx_id: Hex<usize>,
        ) -> BoxFuture<Result<Option<RPCTransaction>, Error>>;

        #[rpc(meta, name = "eth_getTransactionReceipt")]
        fn transaction_receipt(
            &self,
            meta: Self::Metadata,
            tx_hash: H256,
        ) -> BoxFuture<Result<Option<RPCReceipt>, Error>>;

        #[rpc(meta, name = "eth_call")]
        fn call(
            &self,
            meta: Self::Metadata,
            tx: RPCTransaction,
            block: Option<BlockId>,
            meta_keys: Option<Vec<String>>,
        ) -> BoxFuture<Result<Bytes, Error>>;

        #[rpc(meta, name = "eth_estimateGas")]
        fn estimate_gas(
            &self,
            meta: Self::Metadata,
            tx: RPCTransaction,
            block: Option<BlockId>,
            meta_keys: Option<Vec<String>>,
        ) -> BoxFuture<Result<Gas, Error>>;

        #[rpc(meta, name = "eth_getLogs")]
        fn logs(
            &self,
            meta: Self::Metadata,
            log_filter: RPCLogFilter,
        ) -> BoxFuture<Result<Vec<RPCLog>, Error>>;

        #[rpc(meta, name = "eth_getUncleByBlockHashAndIndex")]
        fn uncle_by_block_hash_and_index(
            &self,
            meta: Self::Metadata,
            block_hash: H256,
            uncle_id: U256,
        ) -> Result<Option<RPCBlock>, Error>;

        #[rpc(meta, name = "eth_getUncleByBlockNumberAndIndex")]
        fn uncle_by_block_number_and_index(
            &self,
            meta: Self::Metadata,
            block: String,
            uncle_id: U256,
        ) -> Result<Option<RPCBlock>, Error>;

        #[rpc(meta, name = "eth_getUncleCountByBlockHash")]
        fn block_uncles_count_by_hash(
            &self,
            meta: Self::Metadata,
            block_hash: H256,
        ) -> Result<Hex<usize>, Error>;

        #[rpc(meta, name = "eth_getUncleCountByBlockNumber")]
        fn block_uncles_count_by_number(
            &self,
            meta: Self::Metadata,
            block: String,
        ) -> Result<Hex<usize>, Error>;
    }
}

pub mod bridge {
    use super::*;

    #[rpc]
    pub trait BridgeERPC {
        type Metadata;

        #[rpc(meta, name = "eth_accounts")]
        fn accounts(&self, meta: Self::Metadata) -> Result<Vec<Address>, Error>;

        #[rpc(meta, name = "eth_sign")]
        fn sign(&self, meta: Self::Metadata, address: Address, data: Bytes)
            -> Result<Bytes, Error>;

        #[rpc(meta, name = "eth_signTransaction")]
        fn sign_transaction(
            &self,
            meta: Self::Metadata,
            tx: RPCTransaction,
        ) -> BoxFuture<Result<Bytes, Error>>;

        #[rpc(meta, name = "eth_sendTransaction")]
        fn send_transaction(
            &self,
            meta: Self::Metadata,
            tx: RPCTransaction,
            meta_keys: Option<Vec<String>>,
        ) -> BoxFuture<Result<H256, Error>>;

        #[rpc(meta, name = "eth_sendRawTransaction")]
        fn send_raw_transaction(
            &self,
            meta: Self::Metadata,
            tx: Bytes,
            meta_keys: Option<Vec<String>>,
        ) -> BoxFuture<Result<H256, Error>>;

        #[rpc(meta, name = "eth_getCompilers")]
        fn compilers(&self, meta: Self::Metadata) -> Result<Vec<String>, Error>;
    }
}

// #[rpc]
// pub trait FilterRPC {
//     #[rpc(meta, name = "eth_newFilter")]
//     fn new_filter(&self, RPCLogFilter) -> Result<String, Error>;
//     #[rpc(meta, name = "eth_newBlockFilter")]
//     fn new_block_filter(&self) -> Result<String, Error>;
//     #[rpc(meta, name = "eth_newPendingTransactionFilter")]
//     fn new_pending_transaction_filter(&self) -> Result<String, Error>;
//     #[rpc(meta, name = "eth_uninstallFilter")]
//     fn uninstall_filter(&self, String) -> Result<bool, Error>;

//     #[rpc(meta, name = "eth_getFilterChanges")]
//     fn filter_changes(&self, String) -> Result<Either<Vec<String>, Vec<RPCLog>>, Error>;
//     #[rpc(meta, name = "eth_getFilterLogs")]
//     fn filter_logs(&self, String) -> Result<Vec<RPCLog>, Error>;
// }

// #[rpc]
// pub trait DebugRPC {
//     #[rpc(name = "debug_getBlockRlp")]
//     fn block_rlp(&self, usize) -> Result<Bytes, Error>;
//     #[rpc(name = "debug_traceTransaction")]
//     fn trace_transaction(&self, H256, Option<RPCTraceConfig>)
//                             -> Result<RPCTrace, Error>;
//     #[rpc(name = "debug_traceBlock")]
//     fn trace_block(&self, Bytes, Option<RPCTraceConfig>)
//                     -> Result<RPCBlockTrace, Error>;
//     #[rpc(name = "debug_traceBlockByNumber")]
//     fn trace_block_by_number(&self, usize, Option<RPCTraceConfig>)
//                                 -> Result<RPCBlockTrace, Error>;
//     #[rpc(name = "debug_traceBlockByHash")]
//     fn trace_block_by_hash(&self, H256, Option<RPCTraceConfig>)
//                             -> Result<RPCBlockTrace, Error>;
//     #[rpc(name = "debug_traceBlockFromFile")]
//     fn trace_block_from_file(&self, String, Option<RPCTraceConfig>)
//                                 -> Result<RPCBlockTrace, Error>;
//     #[rpc(name = "debug_dumpBlock")]
//     fn dump_block(&self, usize) -> Result<RPCDump, Error>;
// }

// pub fn rpc_loop<P: 'static + Patch + Send>(
//     state: Arc<Mutex<MinerState>>, addr: &SocketAddr, channel: Sender<bool>
// ) {
//     let rpc = serves::MinerEthereumRPC::<P>::new(state.clone(), channel);
//     let filter = serves::MinerFilterRPC::<P>::new(state.clone());
//     let debug = serves::MinerDebugRPC::<P>::new(state);

//     let mut io = IoHandler::default();

//     io.extend_with(rpc.to_delegate());
//     io.extend_with(filter.to_delegate());
//     io.extend_with(debug.to_delegate());

//     let server = ServerBuilder::new(io)
//         .cors(DomainsValidation::AllowOnly(vec![
//             AccessControlAllowOrigin::Any,
//             AccessControlAllowOrigin::Null,
//         ]))
//         .start_http(addr)
//         .expect("Expect to build HTTP RPC server");

//     server.wait();
// }

impl RPCTransaction {
    pub fn new_from_receipt(
        receipt: evm_state::transactions::TransactionReceipt,
        tx_hash: H256,
        block_hash: H256,
        _chain_id: u64,
    ) -> Result<Self, crate::Error> {
        Ok(RPCTransaction {
            transaction_index: Some((receipt.index as usize).into()),
            block_hash: Some(block_hash),
            block_number: Some(receipt.block_number.into()),
            hash: Some(tx_hash),
            ..RPCTransaction::from_transaction(receipt.transaction)?
        })
    }

    pub fn from_transaction(tx: evm_state::TransactionInReceipt) -> Result<Self, crate::Error> {
        let (hash, to, creates, from, gas_limit, gas_price, input, value, nonce, v, r, s) = match tx
        {
            TransactionInReceipt::Signed(tx) => {
                let hash = tx.tx_id_hash();
                let from = tx.caller().with_context(|_| EvmStateError)?;
                let gas_limit = tx.gas_limit;
                let gas_price = tx.gas_price;
                let input = tx.input;
                let value = tx.value;
                let nonce = tx.nonce;
                let (to, creates) = match tx.action {
                    evm_state::transactions::TransactionAction::Call(address) => {
                        (Some(address), None)
                    }
                    evm_state::transactions::TransactionAction::Create => (
                        None,
                        Some(
                            evm_state::transactions::TransactionAction::Create.address(from, nonce),
                        ),
                    ),
                };
                (
                    hash,
                    to,
                    creates,
                    from,
                    gas_limit,
                    gas_price,
                    input,
                    value,
                    nonce,
                    tx.signature.v,
                    tx.signature.r.as_bytes().into(),
                    tx.signature.s.as_bytes().into(),
                )
            }
            TransactionInReceipt::Unsigned(tx) => {
                let hash = tx.tx_id_hash();
                let from = tx.caller;
                let gas_limit = tx.unsigned_tx.gas_limit;
                let gas_price = tx.unsigned_tx.gas_price;
                let input = tx.unsigned_tx.input;
                let value = tx.unsigned_tx.value;
                let nonce = tx.unsigned_tx.nonce;
                let (to, creates) = match tx.unsigned_tx.action {
                    evm_state::transactions::TransactionAction::Call(address) => {
                        (Some(address), None)
                    }
                    evm_state::transactions::TransactionAction::Create => (
                        None,
                        Some(
                            evm_state::transactions::TransactionAction::Create.address(from, nonce),
                        ),
                    ),
                };
                let addr = U256::from_big_endian(tx.caller.as_bytes());
                let v = tx.chain_id;

                (
                    hash,
                    to,
                    creates,
                    from,
                    gas_limit,
                    gas_price,
                    input,
                    value,
                    nonce,
                    v,
                    addr,
                    U256::from(0x1),
                )
            }
        };
        Ok(RPCTransaction {
            from: Some(from),
            to,
            creates,
            gas: Some(gas_limit),
            gas_price: Some(gas_price),
            value: Some(value),
            input: Some(input.into()),
            nonce: Some(nonce),
            hash: Some(hash),
            transaction_index: None,
            block_hash: None,
            block_number: None,
            v: Some(Hex(v)),
            r: Some(r),
            s: Some(s),
        })
    }
}

impl RPCReceipt {
    pub fn new_from_receipt(
        receipt: evm_state::transactions::TransactionReceipt,
        tx_hash: H256,
        block_hash: H256,
        exit_data: Option<Vec<u8>>,
    ) -> Result<Self, crate::Error> {
        let (from, to, contract_address) = match receipt.transaction {
            TransactionInReceipt::Signed(tx) => {
                let from = tx.caller().with_context(|_| EvmStateError)?;
                let nonce = tx.nonce;
                let (to, creates) = match tx.action {
                    evm_state::transactions::TransactionAction::Call(address) => {
                        (Some(address), None)
                    }
                    evm_state::transactions::TransactionAction::Create => (
                        None,
                        Some(
                            evm_state::transactions::TransactionAction::Create.address(from, nonce),
                        ),
                    ),
                };
                (from, to, creates)
            }
            TransactionInReceipt::Unsigned(tx) => {
                let from = tx.caller;
                let nonce = tx.unsigned_tx.nonce;
                let (to, creates) = match tx.unsigned_tx.action {
                    evm_state::transactions::TransactionAction::Call(address) => {
                        (Some(address), None)
                    }
                    evm_state::transactions::TransactionAction::Create => (
                        None,
                        Some(
                            evm_state::transactions::TransactionAction::Create.address(from, nonce),
                        ),
                    ),
                };

                (from, to, creates)
            }
        };

        let tx_index: Hex<_> = (receipt.index as usize).into();
        let block_number = U256::from(receipt.block_number);

        let logs = receipt
            .logs
            .into_iter()
            .enumerate()
            .map(|(id, log)| RPCLog {
                removed: false,
                log_index: Hex(id),
                transaction_hash: tx_hash,
                transaction_index: tx_index,
                block_hash,
                block_number,
                data: log.data.into(),
                topics: log.topics,
                address: log.address,
            })
            .collect();

        let (status, error) =
            match handle_evm_exit_reason(receipt.status, exit_data.unwrap_or_default()) {
                // todo use data
                Ok(_) => (1, None),
                Err(e) => (0, Some(e.into())),
            };

        Ok(RPCReceipt {
            from: from.into(),
            to,
            contract_address,
            gas_used: receipt.used_gas.into(),
            cumulative_gas_used: receipt.used_gas.into(),
            transaction_hash: tx_hash,
            transaction_index: tx_index,
            block_hash,
            block_number,
            logs_bloom: receipt.logs_bloom,
            logs,
            status: Hex(status),
            error,
        })
    }
}

impl From<LogWithLocation> for RPCLog {
    fn from(log: LogWithLocation) -> Self {
        RPCLog {
            removed: false,
            transaction_hash: log.transaction_hash,
            transaction_index: (log.transaction_id as usize).into(),
            block_number: log.block_num.into(),
            block_hash: log.block_hash,
            log_index: Hex(log.log_index),
            address: log.address,
            topics: log.topics,
            data: Bytes(log.data),
        }
    }
}

pub fn handle_evm_exit_reason(
    reason: evm_state::ExitReason,
    data: Vec<u8>,
) -> Result<(ExitSucceed, Vec<u8>), Error> {
    match reason {
        evm_state::ExitReason::Error(error) => Err(Error::CallError {
            data: data.into(),
            error,
        }),
        evm_state::ExitReason::Revert(error) => Err(Error::CallRevert {
            data: data.into(),
            error,
        }),
        evm_state::ExitReason::Fatal(error) => Err(Error::CallFatal { error }),
        evm_state::ExitReason::Succeed(s) => Ok((s, data)),
    }
}
#[cfg(test)]
mod test {

    use super::*;

    #[test]
    fn test_block_id() {
        println!(
            "{}",
            serde_json::to_string(&BlockId::Num(Hex(1234))).unwrap()
        );
        println!(
            "{}",
            serde_json::to_string(&BlockId::RelativeId(BlockRelId::Latest)).unwrap()
        );
        println!(
            "{}",
            serde_json::to_string(&BlockId::RelativeId(BlockRelId::Pending)).unwrap()
        );
        println!(
            "{}",
            serde_json::to_string(&BlockId::RelativeId(BlockRelId::Earliest)).unwrap()
        );
        println!(
            "{}",
            serde_json::to_string(&BlockId::BlockHash {
                block_hash: H256::repeat_byte(0xde)
            })
            .unwrap()
        );

        let block: BlockId = serde_json::from_str("\"0x123\"").unwrap();
        assert!(matches!(block, BlockId::Num(Hex(0x123u64))));
        let block: BlockId = serde_json::from_str("\"latest\"").unwrap();
        assert!(matches!(block, BlockId::RelativeId(BlockRelId::Latest)));
        let block: BlockId = serde_json::from_str("\"pending\"").unwrap();
        assert!(matches!(block, BlockId::RelativeId(BlockRelId::Pending)));
        let block: BlockId = serde_json::from_str("\"earliest\"").unwrap();
        assert!(matches!(block, BlockId::RelativeId(BlockRelId::Earliest)));
        let block : BlockId = serde_json::from_str("{\"blockHash\":\"0xdededededededededededededededededededededededededededededededede\"}").unwrap();
        assert!(
            matches!(block, BlockId::BlockHash{block_hash} if block_hash == H256::repeat_byte(0xde))
        );
    }

    #[test]
    fn format_block_id() {
        assert_eq!(BlockRelId::Pending.to_string(), "pending");
        assert_eq!(BlockRelId::Latest.to_string(), "latest");
        assert_eq!(BlockRelId::Earliest.to_string(), "earliest");

        assert_eq!(
            BlockId::RelativeId(BlockRelId::Pending).to_string(),
            "pending"
        );
        assert_eq!(
            BlockId::RelativeId(BlockRelId::Latest).to_string(),
            "latest"
        );
        assert_eq!(
            BlockId::RelativeId(BlockRelId::Earliest).to_string(),
            "earliest"
        );

        assert_eq!(BlockId::Num(0xab.into()).to_string(), "0xab");
        assert_eq!(
            BlockId::BlockHash {
                block_hash: H256::repeat_byte(0xde)
            }
            .to_string(),
            r"{ block_hash:0xdededededededededededededededededededededededededededededededede }"
        );
    }
}
