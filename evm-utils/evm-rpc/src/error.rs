use std::num::ParseIntError;

use jsonrpc_core::Error as JRpcError;
use rlp::DecoderError;
use rustc_hex::FromHexError;
use snafu::Snafu;

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

    #[snafu(display("Wrong EVM chain id, expected={}, but tx={:?}", chain_id, tx_chain_id))]
    WrongChainId {
        chain_id: u64,
        tx_chain_id: Option<u64>,
    },

    #[snafu(display("Secret key for account not found, account: {:?}", account))]
    KeyNotFound { account: evm_state::H160 },
    // InvalidParams {},
    // UnsupportedTrieQuery,
    // NotFound,
    // CallError,
    // UnknownSourceMapJump
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
            Error::KeyNotFound { .. } => internal_error(KEY_NOT_FOUND_RPC_ERROR, &err),
            Error::Unimplemented {} => {
                let mut error = Self::invalid_request();
                error.message = err.to_string();
                error
            }
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
