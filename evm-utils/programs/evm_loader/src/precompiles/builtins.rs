use snafu::{ensure, ResultExt};
use std::{collections::HashMap, marker::PhantomData, str::FromStr};

use ethabi::{Function, Param, ParamType, Token};
use evm_state::ExitSucceed;
use once_cell::sync::Lazy;
use primitive_types::H160;

use super::abi_parse::ParseTokens;
use super::errors::*;
use super::{CallResult, PrecompileContext, PrecompileOk, Result};
use crate::scope::evm::gweis_to_lamports;
use solana_sdk::pubkey::Pubkey;

pub trait BuiltinFunction<Inputs> {
    fn call(&self, inputs: Inputs, cx: PrecompileContext<'_>) -> Result<PrecompileOk>;
}

impl<F, Inputs> BuiltinFunction<Inputs> for F
where
    F: Fn(Inputs, PrecompileContext<'_>) -> Result<PrecompileOk>,
{
    fn call(&self, inputs: Inputs, cx: PrecompileContext<'_>) -> Result<PrecompileOk> {
        (*self)(inputs, cx)
    }
}

#[derive(Clone)]
pub struct Builtin<F, I> {
    // TODO: Replace by real function hash calculation
    function_hash: [u8; 4],
    pub abi: Function,
    implementation: F,
    pd: PhantomData<I>,
}

impl<F, I> Builtin<F, I>
where
    F: BuiltinFunction<I>,
    I: ParseTokens,
{
    pub fn new(function_hash: [u8; 4], abi: Function, implementation: F) -> Self {
        Self {
            function_hash,
            abi,
            implementation,
            pd: PhantomData,
        }
    }

    fn check_args(&self, tokens: &[Token]) -> Result<()> {
        ensure!(
            tokens.len() == self.abi.inputs.len(),
            ParamsCountMismatch {
                expected: self.abi.inputs.len(),
                got: tokens.len()
            }
        );
        Ok(())
    }

    pub fn parse_abi(&self, function_abi_input: &[u8]) -> Result<I> {
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

        self.abi
            .decode_input(input)
            .with_context(|| FailedToParse {
                name: self.abi.name.clone(),
            })
            .and_then(|tokens| self.check_args(&tokens).map(|_| tokens))
            .and_then(I::parse)
    }

    pub fn eval(&self, function_abi_input: &[u8], cx: PrecompileContext) -> Result<PrecompileOk> {
        let params = self.parse_abi(function_abi_input)?;

        self.implementation.call(params, cx)
    }
}

//
// Builtins collection.
//

// Currently only static is allowed (but it can be closure).
type BuiltinEval = &'static (dyn Fn(&[u8], PrecompileContext) -> CallResult + Sync);

pub static BUILTINS_MAP: Lazy<HashMap<H160, BuiltinEval>> = Lazy::new(|| {
    let mut builtins = HashMap::new();

    let eth_to_sol: BuiltinEval =
        &|function_abi_input, cx| (*ETH_TO_SOL_CODE).eval(function_abi_input, cx);
    assert!(builtins.insert(*ETH_TO_SOL_ADDR, eth_to_sol).is_none());
    builtins
});

//
// Builtins declaration below
//

// TODO: Implement some procedural macro to render this in more
pub static ETH_TO_SOL_ADDR: Lazy<H160> = Lazy::new(|| {
    H160::from_str(concat!(
        "56454c41532d434841494e", // 'VELAS-CHAIN'
        "0000000000",             // just spaces
        "53574150",               // 'SWAP'
    ))
    .expect("Serialization of static data should be determenistic and never fail.")
});

type EthToSolImp = fn(Pubkey, PrecompileContext) -> Result<PrecompileOk>;

pub static ETH_TO_SOL_CODE: Lazy<Builtin<EthToSolImp, Pubkey>> = Lazy::new(|| {
    let abi = Function {
        name: String::from("transferToNative"),
        inputs: vec![Param {
            name: String::from("native_recipient"),
            kind: ParamType::FixedBytes(32),
        }],
        outputs: vec![],
        constant: false,
    };

    // TOOD: Modify gas left.
    fn implementation(pubkey: Pubkey, cx: PrecompileContext) -> Result<PrecompileOk> {
        // EVM should ensure that user has enough tokens, before calling this precompile.

        let user = if let Some(account) = cx.accounts.find_user(&pubkey) {
            account
        } else {
            return AccountNotFound { public_key: pubkey }.fail();
        };

        // TODO: return change back
        let (lamports, _change) = gweis_to_lamports(cx.evm_context.apparent_value);

        let mut evm_account = cx
            .accounts
            .evm
            .try_account_ref_mut()
            .with_context(|| NativeChainInstructionError {})?;

        let mut user_account = user
            .try_account_ref_mut()
            .with_context(|| NativeChainInstructionError {})?;

        if lamports > evm_account.lamports {
            return InsufficientFunds { lamports }.fail();
        }

        evm_account.lamports -= lamports;
        user_account.lamports += lamports;
        Ok(PrecompileOk::new(ExitSucceed::Returned, vec![], 0))
    };

    Builtin::new([0xb1, 0xd6, 0x92, 0x7a], abi, implementation)
});
