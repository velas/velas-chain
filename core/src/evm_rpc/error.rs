use jsonrpc_core;
use secp256k1;
// use sputnikvm::errors::PreExecutionError;
use hex::FromHexError;
use rlp::DecoderError;
use std::num::ParseIntError;

#[derive(Debug)]
pub enum Error {
    InvalidParams,
    HexError,
    IntError,
    UnsupportedTrieQuery,
    ECDSAError,
    NotFound,
    RlpError,
    CallError,
    UnknownSourceMapJump,
}

// impl From<PreExecutionError> for Error {
//     fn from(val: PreExecutionError) -> Error {
//         Error::CallError
//     }
// }

impl From<DecoderError> for Error {
    fn from(_val: DecoderError) -> Error {
        Error::RlpError
    }
}

impl From<FromHexError> for Error {
    fn from(_val: FromHexError) -> Error {
        Error::HexError
    }
}

impl From<ParseIntError> for Error {
    fn from(_val: ParseIntError) -> Error {
        Error::IntError
    }
}

impl From<secp256k1::Error> for Error {
    fn from(_val: secp256k1::Error) -> Error {
        Error::ECDSAError
    }
}

impl Into<jsonrpc_core::Error> for Error {
    fn into(self) -> jsonrpc_core::Error {
        jsonrpc_core::Error::invalid_request()
    }
}
