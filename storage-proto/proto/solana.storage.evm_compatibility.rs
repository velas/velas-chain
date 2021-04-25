#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EvmBlockHeader {
    #[prost(bytes, tag = "1")]
    pub parent_hash: std::vec::Vec<u8>,
    #[prost(bytes, tag = "2")]
    pub state_root: std::vec::Vec<u8>,
    #[prost(bytes, tag = "3")]
    pub native_chain_hash: std::vec::Vec<u8>,
    #[prost(bytes, repeated, tag = "4")]
    pub transactions: ::std::vec::Vec<std::vec::Vec<u8>>,
    #[prost(bytes, tag = "5")]
    pub transactions_root: std::vec::Vec<u8>,
    #[prost(bytes, tag = "6")]
    pub receipts_root: std::vec::Vec<u8>,
    #[prost(bytes, tag = "7")]
    pub logs_bloom: std::vec::Vec<u8>,
    #[prost(uint64, tag = "8")]
    pub block_number: u64,
    #[prost(uint64, tag = "9")]
    pub gas_limit: u64,
    #[prost(uint64, tag = "10")]
    pub gas_used: u64,
    #[prost(uint64, tag = "11")]
    pub timestamp: u64,
    #[prost(uint64, tag = "12")]
    pub native_chain_slot: u64,
}
/// Unsigned and signed transaction are encoded in rlp format, because there is
/// no reason to keep their fields.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Transaction {
    #[prost(bytes, tag = "1")]
    pub rlp_encoded_body: std::vec::Vec<u8>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct UnsignedTransactionWithCaller {
    #[prost(bytes, tag = "1")]
    pub rlp_encoded_body: std::vec::Vec<u8>,
    #[prost(bytes, tag = "2")]
    pub caller: std::vec::Vec<u8>,
    #[prost(uint64, tag = "3")]
    pub chain_id: u64,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TransactionInReceipt {
    #[prost(oneof = "transaction_in_receipt::Transaction", tags = "1, 2")]
    pub transaction: ::std::option::Option<transaction_in_receipt::Transaction>,
}
pub mod transaction_in_receipt {
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Transaction {
        #[prost(message, tag = "1")]
        Unsigned(super::UnsignedTransactionWithCaller),
        #[prost(message, tag = "2")]
        Signed(super::Transaction),
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TransactionReceipt {
    #[prost(message, optional, tag = "1")]
    pub transaction: ::std::option::Option<TransactionInReceipt>,
    #[prost(message, optional, tag = "2")]
    pub status: ::std::option::Option<ExitReason>,
    #[prost(uint64, tag = "3")]
    pub block_number: u64,
    #[prost(uint64, tag = "4")]
    pub index: u64,
    #[prost(uint64, tag = "5")]
    pub used_gas: u64,
    #[prost(bytes, tag = "6")]
    pub logs_bloom: std::vec::Vec<u8>,
    #[prost(message, repeated, tag = "7")]
    pub logs: ::std::vec::Vec<Log>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Log {
    #[prost(bytes, tag = "1")]
    pub address: std::vec::Vec<u8>,
    #[prost(bytes, repeated, tag = "2")]
    pub topics: ::std::vec::Vec<std::vec::Vec<u8>>,
    #[prost(bytes, tag = "3")]
    pub data: std::vec::Vec<u8>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ExitReason {
    #[prost(enumeration = "exit_reason::ExitVariant", tag = "1")]
    pub variant: i32,
    #[prost(bool, tag = "2")]
    pub fatal: bool,
    #[prost(string, tag = "3")]
    pub other: std::string::String,
}
pub mod exit_reason {
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
    #[repr(i32)]
    pub enum ExitVariant {
        /// Succeed
        Stopped = 0,
        Returned = 1,
        Suicided = 2,
        /// Revert
        Reverted = 3,
        /// Fatal
        NotSupported = 4,
        UnhandledInterrupt = 5,
        OtherFatal = 6,
        /// Error or Error as Fatal
        StackUnderflow = 7,
        StackOverflow = 8,
        InvalidJump = 9,
        InvalidRange = 10,
        DesignatedInvalid = 11,
        CallTooDeep = 12,
        CreateCollision = 13,
        CreateContractLimit = 14,
        OutOfOffset = 15,
        OutOfGas = 16,
        OutOfFund = 17,
        PcUnderflow = 18,
        CreateEmpty = 19,
        Other = 20,
    }
}
