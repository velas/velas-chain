#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TransactionByAddr {
    #[prost(message, repeated, tag = "1")]
    pub tx_by_addrs: ::std::vec::Vec<TransactionByAddrInfo>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TransactionByAddrInfo {
    #[prost(bytes, tag = "1")]
    pub signature: std::vec::Vec<u8>,
    #[prost(message, optional, tag = "2")]
    pub err: ::std::option::Option<TransactionError>,
    #[prost(uint32, tag = "3")]
    pub index: u32,
    #[prost(message, optional, tag = "4")]
    pub memo: ::std::option::Option<Memo>,
    #[prost(message, optional, tag = "5")]
    pub block_time: ::std::option::Option<UnixTimestamp>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Memo {
    #[prost(string, tag = "1")]
    pub memo: std::string::String,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TransactionError {
    #[prost(enumeration = "TransactionErrorType", tag = "1")]
    pub transaction_error: i32,
    #[prost(message, optional, tag = "2")]
    pub instruction_error: ::std::option::Option<InstructionError>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct InstructionError {
    #[prost(uint32, tag = "1")]
    pub index: u32,
    #[prost(enumeration = "InstructionErrorType", tag = "2")]
    pub error: i32,
    #[prost(message, optional, tag = "3")]
    pub custom: ::std::option::Option<CustomError>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct UnixTimestamp {
    #[prost(int64, tag = "1")]
    pub timestamp: i64,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CustomError {
    #[prost(uint32, tag = "1")]
    pub custom: u32,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum TransactionErrorType {
    AccountInUse = 0,
    AccountLoadedTwice = 1,
    AccountNotFound = 2,
    ProgramAccountNotFound = 3,
    InsufficientFundsForFee = 4,
    InvalidAccountForFee = 5,
    DuplicateSignature = 6,
    BlockhashNotFound = 7,
    InstructionError = 8,
    CallChainTooDeep = 9,
    MissingSignatureForFee = 10,
    InvalidAccountIndex = 11,
    SignatureFailure = 12,
    InvalidProgramForExecution = 13,
    SanitizeFailure = 14,
    ClusterMaintenance = 15,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum InstructionErrorType {
    GenericError = 0,
    InvalidArgument = 1,
    InvalidInstructionData = 2,
    InvalidAccountData = 3,
    AccountDataTooSmall = 4,
    InsufficientFunds = 5,
    IncorrectProgramId = 6,
    MissingRequiredSignature = 7,
    AccountAlreadyInitialized = 8,
    UninitializedAccount = 9,
    UnbalancedInstruction = 10,
    ModifiedProgramId = 11,
    ExternalAccountLamportSpend = 12,
    ExternalAccountDataModified = 13,
    ReadonlyLamportChange = 14,
    ReadonlyDataModified = 15,
    DuplicateAccountIndex = 16,
    ExecutableModified = 17,
    RentEpochModified = 18,
    NotEnoughAccountKeys = 19,
    AccountDataSizeChanged = 20,
    AccountNotExecutable = 21,
    AccountBorrowFailed = 22,
    AccountBorrowOutstanding = 23,
    DuplicateAccountOutOfSync = 24,
    Custom = 25,
    InvalidError = 26,
    ExecutableDataModified = 27,
    ExecutableLamportChange = 28,
    ExecutableAccountNotRentExempt = 29,
    UnsupportedProgramId = 30,
    CallDepth = 31,
    MissingAccount = 32,
    ReentrancyNotAllowed = 33,
    MaxSeedLengthExceeded = 34,
    InvalidSeeds = 35,
    InvalidRealloc = 36,
    ComputationalBudgetExceeded = 37,
    PrivilegeEscalation = 38,
    ProgramEnvironmentSetupFailure = 39,
    ProgramFailedToComplete = 40,
    ProgramFailedToCompile = 41,
    Immutable = 42,
    IncorrectAuthority = 43,
    BorshIoError = 44,
    AccountNotRentExempt = 45,
    InvalidAccountOwner = 46,
}
