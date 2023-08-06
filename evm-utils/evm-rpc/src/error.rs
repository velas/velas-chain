use {
    crate::{BlockId, Bytes},
    ethabi::StateMutability,
    evm_state::{ExitError, ExitFatal, ExitRevert, U256},
    jsonrpc_core::Error as JRpcError,
    rlp::DecoderError,
    rustc_hex::FromHexError,
    serde_json::json,
    snafu::Snafu,
    std::num::ParseIntError,
};

#[derive(Debug, Snafu)]
#[snafu(context(suffix(false)))]
#[snafu(visibility(pub))]
pub enum Error {
    #[snafu(display("Failed to decode Hex({})", input_data))]
    #[snafu(context(suffix(Error)))]
    HexError {
        input_data: String,
        source: FromHexError,
    },

    #[snafu(display("Invalid hex prefix in Hex({})", input_data))]
    InvalidHexPrefix { input_data: String },

    #[snafu(display(
        "ServerError(-32005): Invalid blocks range {}..{}, maximum_allowed_batch={:?}",
        starting,
        ending,
        batch_size
    ))]
    InvalidBlocksRange {
        starting: u64,
        ending: u64,
        batch_size: Option<u64>,
    },
    #[snafu(display("Tokio runtime error: {}", details))]
    #[snafu(context(suffix(Error)))]
    RuntimeError { details: String },

    #[snafu(display("Failed to decode Rlp struct {} ({})", struct_name, input_data))]
    #[snafu(context(suffix(Error)))]
    RlpError {
        struct_name: String,
        input_data: String,
        source: DecoderError,
    },

    #[snafu(display("Failed to parse integer({})", input_data))]
    #[snafu(context(suffix(Error)))]
    IntError {
        input_data: String,
        source: ParseIntError,
    },

    #[snafu(display("Failed to parse BigInt({})", input_data))]
    #[snafu(context(suffix(Error)))]
    BigIntError {
        input_data: String,
        source: uint::FromHexError,
    },

    #[snafu(display("Failed to cast BigInt({}) to short int.", input_data))]
    BigIntTrimFailed { input_data: String, error: String },

    #[snafu(display("Failed to find block {:?}", block))]
    BlockNotFound { block: BlockId },

    #[snafu(display("Validator node didn't support archive history"))]
    ArchiveNotSupported,

    #[snafu(display("Failed to find archive state for block {}", block))]
    StateNotFoundForBlock { block: BlockId },

    #[snafu(display("Failed to process native chain request: {}", source))]
    #[snafu(context(suffix(Error)))]
    ProxyRpcError { source: JRpcError },

    #[snafu(display("Method needs to be redirected to node"))]
    ProxyRequest,

    #[snafu(display("Failed to execute request, rpc return error: {}", source))]
    #[snafu(context(suffix(Error)))]
    NativeRpcError {
        details: String,
        source: anyhow::Error,
        verbose: bool,
    },

    #[snafu(display("Error in evm processing layer: {}", source))]
    #[snafu(context(suffix(Error)))]
    EvmStateError { source: evm_state::error::Error },

    #[snafu(display("Method unimplemented"))]
    Unimplemented {},
    #[snafu(display("ServerError(-32005)"))]
    #[snafu(context(suffix(Error)))]
    ServerError {},

    #[snafu(display("Wrong EVM chain id, expected={}, but tx={:?}", chain_id, tx_chain_id))]
    WrongChainId {
        chain_id: u64,
        tx_chain_id: Option<u64>,
    },

    #[snafu(display("Secret key for account not found, account: {:?}", account))]
    KeyNotFound { account: evm_state::H160 },
    #[snafu(display("execution error: {}", format_data_with_error(data, error)))]
    #[snafu(context(suffix(Error)))]
    CallError { data: Bytes, error: ExitError },
    #[snafu(display("execution reverted: {}", format_data(data)))]
    CallRevert { data: Bytes, error: ExitRevert },
    #[snafu(display("Fatal evm error: {:?}", error))]
    CallFatal { error: ExitFatal },
    #[snafu(display("Gas price too low, need={}", need))]
    GasPriceTooLow { need: U256 },
    #[snafu(display("Transaction was removed from mempool"))]
    TransactionRemoved {},
    #[snafu(display("Failed to import transaction into mempool: {}", details))]
    MempoolImport { details: String },
    #[snafu(display("Invalid rpc params"))]
    InvalidParams {},
    // InvalidParams {},
    // UnsupportedTrieQuery,
    // NotFound,
    // UnknownSourceMapJump
}

fn format_data_with_error<T: std::fmt::Debug>(data: &Bytes, error: &T) -> String {
    format!("{:?}:{}", error, format_data(data))
}

pub(crate) fn format_data(data: &Bytes) -> String {
    #[allow(deprecated)]
    let func_decl = ethabi::Function {
        name: "Error".to_string(),
        inputs: vec![ethabi::Param {
            name: "string".to_string(),
            kind: ethabi::ParamType::String,
            internal_type: None,
        }],
        outputs: vec![],
        constant: Some(false),
        state_mutability: StateMutability::Pure,
    };
    if data.0.len() > 4 {
        let hash = &data.0[0..4];
        // check that function hash is taken from "Error" function name
        if *hash == [0x08, 0xc3, 0x79, 0xa0] {
            if let Ok(input) = func_decl.decode_input(&data.0[4..]) {
                if let Some(ethabi::Token::String(s)) = input.get(0) {
                    // on success decode return error from reason string.
                    return s.clone();
                }
            }
        }
    }
    // if anything fail, return error from VM
    String::new()
}

pub fn internal_error_with_details<T: ToString, U: ToString>(
    code: i64,
    message: &T,
    data: &U,
) -> JRpcError {
    JRpcError {
        code: jsonrpc_core::ErrorCode::ServerError(code),
        message: message.to_string(),
        data: serde_json::Value::String(data.to_string()).into(),
    }
}

pub fn internal_error<T: ToString>(code: i64, message: &T) -> JRpcError {
    JRpcError {
        code: jsonrpc_core::ErrorCode::ServerError(code),
        message: message.to_string(),
        data: None,
    }
}
const EVM_STATE_RPC_ERROR: i64 = 1002;
const NATIVE_RPC_ERROR: i64 = 1003;

const BLOCK_NOT_FOUND_RPC_ERROR: i64 = 2001;
const STATE_NOT_FOUND_RPC_ERROR: i64 = 2002;
const KEY_NOT_FOUND_RPC_ERROR: i64 = 2003;
const FATAL_EVM_ERROR: i64 = 2004;
const GAS_PRICE_TOO_LOW: i64 = 2005;
const TRANSACTION_REPLACED: i64 = 2006;
const ARCHIVE_NOT_SUPPORTED_ERROR: i64 = 2007;
const MEMPOOL_IMPORT: i64 = 2008;

const EVM_EXECUTION_ERROR: i64 = 3; // from geth docs
const ERROR_EVM_BASE_SUBCODE: i64 = 100; //reserved place for evm errors range: 100 - 200
const ERROR_EVM_BASE_SUBRANGE: i64 = 100;
const SERVER_ERROR: i64 = -32005;

impl From<Error> for JRpcError {
    fn from(err: Error) -> Self {
        match &err {
            Error::HexError { source, .. } => {
                Self::invalid_params_with_details(err.to_string(), source)
            }
            Error::InvalidHexPrefix { .. } => Self::invalid_params(err.to_string()),
            Error::RlpError { source, .. } => {
                Self::invalid_params_with_details(err.to_string(), source)
            }
            Error::IntError { source, .. } => {
                Self::invalid_params_with_details(err.to_string(), source)
            }
            Error::BigIntError { source, .. } => {
                Self::invalid_params_with_details(err.to_string(), source)
            }
            Error::BigIntTrimFailed { error, .. } => {
                Self::invalid_params_with_details(err.to_string(), error)
            }
            Error::ProxyRpcError { source } => source.clone(),
            Error::ProxyRequest => Self::method_not_found(),
            Error::WrongChainId { .. } => Self::invalid_params(err.to_string()),
            // NOTE: add context information of the error
            Error::InvalidParams {} => Self::invalid_params(err.to_string()),
            Error::EvmStateError { source } => {
                internal_error_with_details(EVM_STATE_RPC_ERROR, &err, &source)
            }
            Error::NativeRpcError {
                source: _source,
                details,
                verbose,
            } => {
                if *verbose {
                    // in verbose mode, print full details in message, and ignore original message.
                    internal_error_with_details(NATIVE_RPC_ERROR, &details, &"")
                } else {
                    internal_error_with_details(NATIVE_RPC_ERROR, &err, &details)
                }
            }
            Error::BlockNotFound { .. } => internal_error(BLOCK_NOT_FOUND_RPC_ERROR, &err),
            Error::ArchiveNotSupported => internal_error(ARCHIVE_NOT_SUPPORTED_ERROR, &err),
            Error::StateNotFoundForBlock { .. } => internal_error(STATE_NOT_FOUND_RPC_ERROR, &err),
            Error::KeyNotFound { .. } => internal_error(KEY_NOT_FOUND_RPC_ERROR, &err),
            Error::Unimplemented {} => {
                let mut error = Self::invalid_request();
                error.message = err.to_string();
                error
            }
            Error::CallFatal { error: _ } => internal_error(FATAL_EVM_ERROR, &err),
            Error::CallError { data, error } => {
                let error_code = match error {
                    ExitError::CallTooDeep => 1,
                    ExitError::CreateCollision => 2,
                    ExitError::CreateContractLimit => 3,
                    ExitError::CreateEmpty => 4,
                    ExitError::DesignatedInvalid => 5,
                    ExitError::InvalidJump => 6,
                    ExitError::InvalidRange => 7,
                    ExitError::OutOfFund => 8,
                    ExitError::OutOfGas => 9,
                    ExitError::OutOfOffset => 10,
                    ExitError::PCUnderflow => 11,
                    ExitError::StackOverflow => 12,
                    ExitError::StackUnderflow => 13,
                    ExitError::Other(_) => 14,
                    ExitError::InvalidCode(_) => 15,
                };
                let error_code = ERROR_EVM_BASE_SUBCODE + error_code;
                assert!(error_code < ERROR_EVM_BASE_SUBCODE + ERROR_EVM_BASE_SUBRANGE);
                internal_error_with_details(
                    EVM_EXECUTION_ERROR,
                    &err,
                    &json! {
                        [
                        {
                            "code": error_code,
                            "original_result": data,
                            "debug_message": format!("{:?}", error)
                        }
                        ]
                    },
                )
            }
            Error::CallRevert { data, error: _ } => {
                internal_error_with_details(EVM_EXECUTION_ERROR, &err, &data)
            }
            Error::ServerError {} => internal_error(SERVER_ERROR, &err),
            Error::InvalidBlocksRange { .. } => internal_error(SERVER_ERROR, &err),
            Error::RuntimeError { .. } => internal_error(SERVER_ERROR, &err),
            Error::GasPriceTooLow { .. } => internal_error(GAS_PRICE_TOO_LOW, &err),
            Error::TransactionRemoved {} => internal_error(TRANSACTION_REPLACED, &err),
            Error::MempoolImport { .. } => internal_error(MEMPOOL_IMPORT, &err),
        }
    }
}

pub fn into_native_error<E>(e: E, verbose: bool) -> Error
where
    E: Into<anyhow::Error> + std::fmt::Debug,
{
    let details = format!("{:?}", e);
    Error::NativeRpcError {
        source: e.into(),
        details,
        verbose,
    }
}

#[cfg(test)]
mod test {

    use {super::*, std::str::FromStr};
    #[test]
    fn test_decode_revert() {
        let bytes = Bytes::from_str("0x08c379a00000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000d4552525f4e4f545f424f554e4400000000000000000000000000000000000000").unwrap();
        let result = format_data(&bytes);
        assert_eq!(&result, "ERR_NOT_BOUND");
    }

    #[test]
    fn test_decode_revert_invalid_length() {
        let bytes = Bytes::from_str("0x08c379a00000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000d4552525f4e4f545f424f554e4400000000000000000000000000000000000000").unwrap();
        let result = format_data(&Bytes(bytes.0[0..3].to_vec()));
        assert_eq!(&result, "");
        let result = format_data(&Bytes(bytes.0[0..4].to_vec()));
        assert_eq!(&result, "");
        let result = format_data(&Bytes(bytes.0[0..5].to_vec()));
        assert_eq!(&result, "");
    }
}
