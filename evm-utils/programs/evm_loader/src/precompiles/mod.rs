use hex::FromHexError;
use snafu::{ensure, ResultExt, Snafu};
use std::cell::RefCell;
use std::{collections::HashMap, str::FromStr};

use ethabi::{Function, Param, ParamType, Token};
use evm_state::{Context, ExitError, ExitSucceed};
use once_cell::sync::Lazy;
use primitive_types::H160;

use solana_sdk::{keyed_account::KeyedAccount, pubkey::Pubkey};

mod builtins;
use builtins::BUILTINS_MAP;

use crate::account_structure::AccountStructure;

/// Exit result, if succeed, returns `ExitSucceed` - info about execution, Vec<u8> - output data, u64 - gas cost
type CallResult = Result<(ExitSucceed, Vec<u8>, u64), ExitError>;

#[derive(Debug, Snafu)]
enum PrecompileErrors {
    #[snafu(display("Cannot parse function {} abi = {}", name, source))]
    FailedToParse { name: String, source: ethabi::Error },

    #[snafu(display("Cannot parse function input {} error = {}", arg_type, source))]
    FailedToParseInput {
        arg_type: String,
        source: FromHexError,
    },
    #[snafu(display(
        "Input len lesser than 4 bytes, expected to be function hash, input_len = {}",
        input_len
    ))]
    InputToShort { input_len: usize },
    #[snafu(display("Function hash, not equal, expected = {}, got = {}", expected, got))]
    MismatchFunctionHash { expected: String, got: String },
    #[snafu(display(
        "Received different params count, expected = {}, got = {}",
        expected,
        got
    ))]
    ParamsCountMismatch { expected: usize, got: usize },

    #[snafu(display(
        "Function received unexpected input, expected = {}, got = {}",
        expected,
        got
    ))]
    UnexpectedInput { expected: String, got: String },
    #[snafu(display("Failed to find account, account_pk = {}", public_key))]
    AccountNotFound { public_key: Pubkey },

    #[snafu(display(
        "No enough tokens, on EVM state account, to credit request = {}",
        lamports
    ))]
    InsufficientFunds { lamports: u64 },

    #[snafu(display("Native chain Instruction error source = {}", source))]
    NativeChainInstructionError {
        source: solana_sdk::instruction::InstructionError,
    },
}

impl From<PrecompileErrors> for ExitError {
    fn from(rhs: PrecompileErrors) -> Self {
        ExitError::Other(rhs.to_string().into())
    }
}

fn entrypoint_static(
    accounts: AccountStructure,
    address: H160,
    function_abi_input: &[u8],
    gas_left: Option<u64>,
    cx: &Context,
) -> Option<CallResult> {
    let result =
        BUILTINS_MAP
            .get(&address)?
            .parse_and_eval(accounts, function_abi_input, gas_left, cx);
    Some(result)
}

#[cfg(test)]
mod test {
    use primitive_types::U256;

    use crate::scope::evm::lamports_to_gwei;

    use super::builtins::BUILTINS_MAP;
    use super::*;

    #[test]
    fn check_num_builtins() {
        assert_eq!(BUILTINS_MAP.len(), 1);
    }

    #[test]
    fn call_transfer_to_native_failed_incorrect_addr() {
        let addr = H160::from_str("56454c41532d434841494e000000000053574150").unwrap();
        let input =
            hex::decode("b1d6927a1111111111111111111111111111111111111111111111111111111111111111") // func_hash + 0x111..111 in bytes32
                .unwrap();
        let cx = Context {
            address: H160::from_str("56454c41532d434841494e000000000053574150").unwrap(),
            caller: H160::from_str("56454c41532d434841494e000000000053574150").unwrap(),
            apparent_value: U256::from(1),
        };
        AccountStructure::testing(0, |structure| {
            assert_eq!(
                dbg!(entrypoint_static(structure, addr, &input, None, &cx).unwrap()),
                Err(ExitError::Other("Failed to find account, account_pk = 29d2S7vB453rNYFdR5Ycwt7y9haRT5fwVwL9zTmBhfV2".into())) // equal to 0x111..111 in base58
            );
        })
    }

    #[test]
    fn call_transfer_to_native_real() {
        let addr = H160::from_str("56454c41532d434841494e000000000053574150").unwrap();

        let cx = Context {
            address: H160::from_str("56454c41532d434841494e000000000053574150").unwrap(),
            caller: H160::from_str("56454c41532d434841494e000000000053574150").unwrap(),
            apparent_value: lamports_to_gwei(1),
        };
        AccountStructure::testing(0, |accounts: AccountStructure| {
            let user = accounts.user().unwrap();
            let input = hex::decode(format!(
                "b1d6927a{}",
                hex::encode(user.unsigned_key().to_bytes())
            ))
            .unwrap();
            let lamports_before = user.lamports().unwrap();
            assert!(matches!(
                dbg!(entrypoint_static(accounts, addr, &input, None, &cx)),
                Some(Ok((ExitSucceed::Returned, _, 0)))
            ));

            let lamports_after = user.lamports().unwrap();
            assert_eq!(lamports_before + 1, lamports_after)
        })
    }
}
