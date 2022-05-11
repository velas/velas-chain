#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EvmBlockHeader {
    #[prost(bytes = "vec", tag = "1")]
    pub parent_hash: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub state_root: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    pub native_chain_hash: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", repeated, tag = "4")]
    pub transactions: ::prost::alloc::vec::Vec<::prost::alloc::vec::Vec<u8>>,
    #[prost(bytes = "vec", tag = "5")]
    pub transactions_root: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", tag = "6")]
    pub receipts_root: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", tag = "7")]
    pub logs_bloom: ::prost::alloc::vec::Vec<u8>,
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
    #[prost(uint64, tag = "13")]
    pub version: u64,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ReceiptWithHash {
    #[prost(bytes = "vec", tag = "1")]
    pub hash: ::prost::alloc::vec::Vec<u8>,
    #[prost(message, optional, tag = "2")]
    pub transaction: ::core::option::Option<TransactionReceipt>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EvmFullBlock {
    #[prost(message, optional, tag = "1")]
    pub header: ::core::option::Option<EvmBlockHeader>,
    #[prost(message, repeated, tag = "2")]
    pub transactions: ::prost::alloc::vec::Vec<ReceiptWithHash>,
}
/// Unsigned and signed transaction are encoded in rlp format, because there is
/// no reason to keep their fields.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Transaction {
    #[prost(bytes = "vec", tag = "1")]
    pub rlp_encoded_body: ::prost::alloc::vec::Vec<u8>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct UnsignedTransactionWithCaller {
    #[prost(bytes = "vec", tag = "1")]
    pub rlp_encoded_body: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub caller: ::prost::alloc::vec::Vec<u8>,
    #[prost(uint64, tag = "3")]
    pub chain_id: u64,
    #[prost(bool, tag = "4")]
    pub signed_compatible: bool,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TransactionInReceipt {
    #[prost(oneof = "transaction_in_receipt::Transaction", tags = "1, 2")]
    pub transaction: ::core::option::Option<transaction_in_receipt::Transaction>,
}
/// Nested message and enum types in `TransactionInReceipt`.
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
    pub transaction: ::core::option::Option<TransactionInReceipt>,
    #[prost(message, optional, tag = "2")]
    pub status: ::core::option::Option<ExitReason>,
    #[prost(uint64, tag = "3")]
    pub block_number: u64,
    #[prost(uint64, tag = "4")]
    pub index: u64,
    #[prost(uint64, tag = "5")]
    pub used_gas: u64,
    #[prost(bytes = "vec", tag = "6")]
    pub logs_bloom: ::prost::alloc::vec::Vec<u8>,
    #[prost(message, repeated, tag = "7")]
    pub logs: ::prost::alloc::vec::Vec<Log>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Log {
    #[prost(bytes = "vec", tag = "1")]
    pub address: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", repeated, tag = "2")]
    pub topics: ::prost::alloc::vec::Vec<::prost::alloc::vec::Vec<u8>>,
    #[prost(bytes = "vec", tag = "3")]
    pub data: ::prost::alloc::vec::Vec<u8>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ExitReason {
    #[prost(enumeration = "exit_reason::ExitVariant", tag = "1")]
    pub variant: i32,
    #[prost(bool, tag = "2")]
    pub fatal: bool,
    #[prost(string, tag = "3")]
    pub other: ::prost::alloc::string::String,
}
/// Nested message and enum types in `ExitReason`.
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
        InvalidCode = 21,
    }
}
