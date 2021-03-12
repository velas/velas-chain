use std::num::ParseIntError;

use jsonrpc_core::Error as JRpcError;
use primitive_types::U256;
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

    #[snafu(display("Failed to process native chain request"))]
    NativeRpcError { source: JRpcError },

    #[snafu(display("Failed to execute request, rpc return error"))]
    ProxyRpcError { source: anyhow::Error },

    #[snafu(display("Error in evm processing layer"))]
    EvmStateError { source: evm_state::error::Error },

    #[snafu(display("Method unimplemented"))]
    Unimplemented {},

    #[snafu(display("Wrong EVM chain id, expected={}, but tx={:?}", chain_id, tx_chain_id))]
    WrongChainId {
        chain_id: U256,
        tx_chain_id: Option<U256>,
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
const NATIVE_RPC_ERROR: i64 = 1001;
const EVM_STATE_RPC_ERROR: i64 = 1002;
const PROXY_RPC_ERROR: i64 = 1003;

const BLOCK_NOT_FOUND_RPC_ERROR: i64 = 2001;

impl Into<JRpcError> for Error {
    fn into(self) -> JRpcError {
        match &self {
            Self::HexError { source, .. } => {
                JRpcError::invalid_params_with_details(self.to_string(), source)
            }
            Self::InvalidHexPrefix { .. } => JRpcError::invalid_params(self.to_string()),
            Self::RlpError { source, .. } => {
                JRpcError::invalid_params_with_details(self.to_string(), source)
            }
            Self::IntError { source, .. } => {
                JRpcError::invalid_params_with_details(self.to_string(), source)
            }
            Self::BigIntError { source, .. } => {
                JRpcError::invalid_params_with_details(self.to_string(), source)
            }
            Self::BigIntTrimFailed { error, .. } => {
                JRpcError::invalid_params_with_details(self.to_string(), error)
            }
            Self::NativeRpcError { source } => {
                internal_error_with_details(NATIVE_RPC_ERROR, &self, &source)
            }
            Self::WrongChainId { .. } => JRpcError::invalid_params(self.to_string()),
            Self::EvmStateError { source } => {
                internal_error_with_details(EVM_STATE_RPC_ERROR, &self, &source)
            }
            Self::ProxyRpcError { source } => {
                internal_error_with_details(PROXY_RPC_ERROR, &self, &source)
            }
            Self::BlockNotFound { .. } => internal_error(BLOCK_NOT_FOUND_RPC_ERROR, &self),
            Self::Unimplemented {} => {
                let mut error = JRpcError::invalid_request();
                error.message = self.to_string();
                error
            }
        }
    }
}
