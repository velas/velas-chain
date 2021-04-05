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
    BlockNotFound { block: evm_state::Slot },

    #[snafu(display("Failed to process native chain request: {}", source))]
    ProxyRpcError { source: JRpcError },

    #[snafu(display("Failed to execute request, rpc return error: {}", source))]
    NativeRpcError { source: anyhow::Error },

    #[snafu(display("Error in evm processing layer"))]
    EvmStateError { source: evm_state::error::Error },

    #[snafu(display("Method unimplemented"))]
    Unimplemented {},

    #[snafu(display("Wrong EVM chain id, expected={}, but tx={:?}", chain_id, tx_chain_id))]
    WrongChainId {
        chain_id: u64,
        tx_chain_id: Option<u64>,
    },
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
            Error::NativeRpcError { source } => {
                internal_error_with_details(NATIVE_RPC_ERROR, &err, &source)
            }
            Error::BlockNotFound { .. } => internal_error(BLOCK_NOT_FOUND_RPC_ERROR, &err),
            Error::Unimplemented {} => {
                let mut error = Self::invalid_request();
                error.message = err.to_string();
                error
            }
        }
    }
}
