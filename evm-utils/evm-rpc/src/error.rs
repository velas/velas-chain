use std::num::ParseIntError;

use evm_state::{ExitError, ExitFatal, ExitRevert, H256};
use jsonrpc_core::Error as JRpcError;
use rlp::DecoderError;
use rustc_hex::FromHexError;
use serde_json::json;
use snafu::Snafu;

use crate::Bytes;

#[derive(Debug, Snafu)]
#[snafu(visibility = "pub")]
pub enum Error {
    #[snafu(display("Failed to decode Hex({})", input_data))]
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
    RuntimeError { details: String },

    #[snafu(display("Failed to decode Rlp struct {} ({})", struct_name, input_data))]
    RlpError {
        struct_name: String,
        input_data: String,
        source: DecoderError,
    },

    #[snafu(display("Failed to parse integer({})", input_data))]
    IntError {
        input_data: String,
        source: ParseIntError,
    },

    #[snafu(display("Failed to parse BigInt({})", input_data))]
    BigIntError {
        input_data: String,
        source: uint::FromHexError,
    },

    #[snafu(display("Failed to cast BigInt({}) to short int.", input_data))]
    BigIntTrimFailed { input_data: String, error: String },

    #[snafu(display("Failed to find block {}", block))]
    BlockNotFound { block: evm_state::BlockNum },

    #[snafu(display("Failed to find state for block {}", block))]
    StateNotFoundForBlock { block: String },

    #[snafu(display("Failed to find state root {}", state))]
    StateRootNotFound { state: H256 },

    #[snafu(display("Failed to process native chain request: {}", source))]
    ProxyRpcError { source: JRpcError },

    #[snafu(display("Failed to execute request, rpc return error: {}", source))]
    NativeRpcError {
        details: String,
        source: anyhow::Error,
        verbose: bool,
    },

    #[snafu(display("Error in evm processing layer"))]
    EvmStateError { source: evm_state::error::Error },

    #[snafu(display("Method unimplemented"))]
    Unimplemented {},
    #[snafu(display("ServerError(-32005)"))]
    ServerError {},

    #[snafu(display("Wrong EVM chain id, expected={}, but tx={:?}", chain_id, tx_chain_id))]
    WrongChainId {
        chain_id: u64,
        tx_chain_id: Option<u64>,
    },

    #[snafu(display("Secret key for account not found, account: {:?}", account))]
    KeyNotFound { account: evm_state::H160 },
    #[snafu(display("execution error: {}", format_data_with_error(data, error)))]
    CallError { data: Bytes, error: ExitError },
    #[snafu(display("execution reverted: {}", format_data(data)))]
    CallRevert { data: Bytes, error: ExitRevert },
    #[snafu(display("Fatal evm error: {:?}", error))]
    CallFatal { error: ExitFatal },
    // InvalidParams {},
    // UnsupportedTrieQuery,
    // NotFound,
    // CallError,
    // UnknownSourceMapJump
}

fn format_data_with_error<T: std::fmt::Debug>(data: &Bytes, error: &T) -> String {
    format!("{:?}:{}", error, format_data(data))
}

pub(crate) fn format_data(data: &Bytes) -> String {
    let func_decl = ethabi::Function {
        name: "Error".to_string(),
        inputs: vec![ethabi::Param {
            name: "string".to_string(),
            kind: ethabi::ParamType::String,
        }],
        outputs: vec![],
        constant: false,
    };
    if data.0.len() > 4 {
        let hash = &data.0[0..4];
        // check that function hash is taken from "Error" function name
        if dbg!(*hash == [0x08, 0xc3, 0x79, 0xa0]) {
            if let Ok(input) = dbg!(func_decl.decode_input(&data.0[4..])) {
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
            Error::WrongChainId { .. } => Self::invalid_params(err.to_string()),
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
            Error::StateNotFoundForBlock { .. } => internal_error(STATE_NOT_FOUND_RPC_ERROR, &err),
            Error::StateRootNotFound { .. } => internal_error(STATE_NOT_FOUND_RPC_ERROR, &err),
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
        }
    }
}

pub trait IntoNativeRpcError<T> {
    fn into_native_error(self, verbose: bool) -> Result<T, Error>;
}

impl<T, Err> IntoNativeRpcError<T> for Result<T, Err>
where
    anyhow::Error: From<Err>,
    Err: std::fmt::Debug,
{
    fn into_native_error(self, verbose: bool) -> Result<T, Error> {
        match self {
            Ok(ok) => Ok(ok),
            Err(e) => {
                let details = format!("{:?}", e);
                Err(Error::NativeRpcError {
                    source: anyhow::Error::from(e),
                    details,
                    verbose,
                })
            }
        }
    }
}

#[cfg(test)]
mod test {

    use std::str::FromStr;

    use super::*;
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
