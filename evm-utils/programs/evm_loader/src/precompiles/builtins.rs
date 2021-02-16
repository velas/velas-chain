use snafu::{ensure, ResultExt, Snafu};
use std::{borrow::BorrowMut, cell::RefCell};
use std::{collections::HashMap, str::FromStr};

use ethabi::{Function, Param, ParamType, Token};
use evm_state::{Context, ExitError, ExitSucceed};
use once_cell::sync::Lazy;
use primitive_types::H160;

use super::*;
use crate::account_structure::AccountStructure;
use crate::scope::evm::gweis_to_lamports;
use solana_sdk::{keyed_account::KeyedAccount, pubkey::Pubkey};

// Currently only static is allowed (but it can be closure).
type BuiltinImplementation =
    &'static (dyn Fn(AccountStructure, Vec<Token>, Option<u64>, &Context) -> CallResult + Sync);

#[derive(Clone)]
pub struct Builtin {
    // TODO: Replace by real function hash calculation
    function_hash: Vec<u8>,
    address: H160,
    abi: Function,
    implementation: BuiltinImplementation,
}

impl Builtin {
    pub fn new(
        function_hash: Vec<u8>,
        address: H160,
        abi: Function,
        implementation: BuiltinImplementation,
    ) -> Self {
        assert_eq!(function_hash.len(), 4);
        Self {
            function_hash,
            address,
            abi,
            implementation,
        }
    }
    fn parse_abi(schema: &Function, input: &[u8]) -> Result<Vec<Token>, ExitError> {
        Ok(schema.decode_input(input).with_context(|| FailedToParse {
            name: schema.name.clone(),
        })?)
    }

    pub fn parse_and_eval(
        &self,
        accounts: AccountStructure,
        function_abi_input: &[u8],
        gas_limit: Option<u64>,
        cx: &Context,
    ) -> CallResult {
        ensure!(
            function_abi_input.len() >= 4,
            InputToShort {
                input_len: function_abi_input.len()
            }
        );
        let (hash, input) = function_abi_input.split_at(4);

        ensure!(
            hash == self.function_hash,
            MismatchFunctionHash {
                expected: hex::encode(&self.function_hash),
                got: hex::encode(hash)
            }
        );

        let tokens = Self::parse_abi(&self.abi, input)?;

        ensure!(
            tokens.len() == self.abi.inputs.len(),
            ParamsCountMismatch {
                expected: self.abi.inputs.len(),
                got: tokens.len()
            }
        );

        (*self.implementation)(accounts, tokens, gas_limit, cx)
    }
}

//
// Builtins collection.
//

pub static BUILTINS_MAP: Lazy<HashMap<H160, Builtin>> = Lazy::new(|| {
    let mut builtins = HashMap::new();

    assert!(builtins
        .insert(ETH_TO_SOL.address, ETH_TO_SOL.clone())
        .is_none());
    builtins
});

//
// Builtins declaration below
//

static ETH_TO_SOL: Lazy<Builtin> = Lazy::new(|| {
    let abi = Function {
        name: String::from("transferToNative"),
        inputs: vec![Param {
            name: String::from("native_recipient"),
            kind: ParamType::FixedBytes(32),
        }],
        outputs: vec![],
        constant: false,
    };
    // TODO: Implement some procedural macro to render this in more
    let address = H160::from_str(concat!(
        "56454c41532d434841494e", // 'VELAS-CHAIN'
        "0000000000",             // just spaces
        "53574150",               // 'SWAP'
    ))
    .expect("Serialization of static data should be determenistic and never fail.");

    // TOOD: Modify gas left.
    fn implementation(
        accounts: AccountStructure,
        inputs: Vec<Token>,
        gas_left: Option<u64>,
        cx: &Context,
    ) -> CallResult {
        // EVM should ensure that user has enough tokens, before calling this precompile.
        ensure!(
            inputs.len() == 1,
            ParamsCountMismatch {
                expected: 1 as usize,
                got: inputs.len()
            }
        );

        let bytes = match &inputs[0] {
            Token::FixedBytes(bytes) if bytes.len() == 32 => bytes,
            t => {
                return UnexpectedInput {
                    expected: String::from("bytes32"),
                    got: t.to_string(),
                }
                .fail()
                .map_err(Into::into)
            }
        };
        let pk = Pubkey::new(&bytes);
        let user = if let Some(account) = accounts.find_user(&pk) {
            account
        } else {
            return AccountNotFound { public_key: pk }
                .fail()
                .map_err(Into::into);
        };

        // TODO: return change back
        let (lamports, change) = gweis_to_lamports(cx.apparent_value);

        let mut evm_account = accounts
            .evm
            .try_account_ref_mut()
            .with_context(|| NativeChainInstructionError {})?;

        let mut user_account = user
            .try_account_ref_mut()
            .with_context(|| NativeChainInstructionError {})?;

        if lamports > evm_account.lamports {
            return InsufficientFunds { lamports }.fail().map_err(Into::into);
        }

        evm_account.lamports -= lamports;
        user_account.lamports += lamports;
        Ok((ExitSucceed::Returned, vec![], 0))
    };

    Builtin::new(vec![0xb1, 0xd6, 0x92, 0x7a], address, abi, &implementation)
});
