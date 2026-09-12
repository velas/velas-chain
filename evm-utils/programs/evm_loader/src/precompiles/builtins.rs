use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use snafu::{ensure, ResultExt};
use std::{marker::PhantomData, str::FromStr};

use ethabi::{Function, Param, ParamType, StateMutability, Token};
use evm_state::{executor::PrecompileOutput, CallScheme, ExitSucceed};
use once_cell::sync::Lazy;
use primitive_types::H160;

use super::abi_parse::ParseTokens;
use super::{errors::*, CallResult};
use super::{NativeContext, Result};
use crate::scope::evm::gweis_to_lamports;
use crate::AccountStructure;
use solana_sdk::account::{ReadableAccount, WritableAccount};
use solana_sdk::pubkey::Pubkey;

pub trait NativeFunction<Inputs> {
    type PromiseType;
    fn call(
        &self,
        inputs: Inputs,
        cx: NativeContext<'_, '_>,
    ) -> Result<(PrecompileOutput, u64, Vec<Self::PromiseType>)>;
    fn process_promise(
        &self,
        accounts: AccountStructure<'_>,
        promise: Self::PromiseType,
    ) -> Result<()>;
}

pub struct PromiseFunc<F, U, Inputs, Promise>
where
    F: Fn(Inputs, NativeContext<'_, '_>) -> Result<(PrecompileOutput, u64, Vec<Promise>)>,
    U: Fn(AccountStructure<'_>, Promise) -> Result<()>,
{
    implementation: F,
    promise_impl: U,
    _pd: PhantomData<(Promise, Inputs)>,
}

impl<F, U, Inputs, Promise> PromiseFunc<F, U, Inputs, Promise>
where
    F: Fn(Inputs, NativeContext<'_, '_>) -> Result<(PrecompileOutput, u64, Vec<Promise>)>,
    U: Fn(AccountStructure<'_>, Promise) -> Result<()>,
{
    pub fn new(implementation: F, promise_impl: U) -> Self {
        Self {
            implementation,
            promise_impl,
            _pd: PhantomData,
        }
    }
}

impl<F, U, Inputs, Promise> NativeFunction<Inputs> for PromiseFunc<F, U, Inputs, Promise>
where
    F: Fn(Inputs, NativeContext<'_, '_>) -> Result<(PrecompileOutput, u64, Vec<Promise>)>,
    U: Fn(AccountStructure<'_>, Promise) -> Result<()>,
{
    type PromiseType = Promise;
    fn call(
        &self,
        inputs: Inputs,
        cx: NativeContext<'_, '_>,
    ) -> Result<(PrecompileOutput, u64, Vec<Promise>)> {
        (self.implementation)(inputs, cx)
    }

    fn process_promise(&self, accounts: AccountStructure<'_>, promise: Promise) -> Result<()> {
        (self.promise_impl)(accounts, promise)
    }
}

#[derive(Clone)]
pub struct NativeContract<F, I> {
    // TODO: Replace by real function hash calculation
    function_hash: [u8; 4],
    pub abi: Function,
    implementation: F,
    pd: PhantomData<I>,
}

impl<F, I> NativeContract<F, I>
where
    F: NativeFunction<I>,
    I: ParseTokens,
    F::PromiseType: Serialize + DeserializeOwned,
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
    pub fn decode_promise(&self, data: &[u8]) -> Result<F::PromiseType> {
        bincode::deserialize(data).map_err(|e| LogSerialize { error: e }.build())
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
                expected: hex::encode(self.function_hash),
                got: hex::encode(hash)
            }
        );

        self.abi
            .decode_input(input)
            .with_context(|_| FailedToParse {
                name: self.abi.name.clone(),
            })
            .and_then(|tokens| self.check_args(&tokens).map(|_| tokens))
            .and_then(I::parse)
    }

    pub fn eval(&self, function_abi_input: &[u8], cx: NativeContext) -> CallResult {
        let params = self.parse_abi(function_abi_input)?;

        self.implementation
            .call(params, cx)
            .and_then(|(o, g, promise)| {
                let result: Result<Vec<Vec<_>>, _> = promise
                    .into_iter()
                    .map(|promise| bincode::serialize(&promise))
                    .collect();
                let result = result.map_err(|e| LogSerialize { error: e }.build())?;
                let logs = result.into_iter().map(|e| (Vec::new(), e)).collect(); // empty topic

                Ok((o, g, logs))
            })
    }

    pub fn process_promise(&self, accounts: AccountStructure, data: Vec<u8>) -> Result<()> {
        let promise = self.decode_promise(&data)?;

        self.implementation.process_promise(accounts, promise)
    }
}

//
// NativeContracts declaration below
//
// 0x56454c41532d434841494e000000000053574150 for better search
// TODO: Implement some procedural macro to render this in more
pub static ETH_TO_VLX_ADDR: Lazy<H160> = Lazy::new(|| {
    H160::from_str(concat!(
        "56454c41532d434841494e", // 'VELAS-CHAIN'
        "0000000000",             // just spaces
        "53574150",               // 'SWAP'
    ))
    .expect("Serialization of static data should be determenistic and never fail.")
});

type EthToVlxImp = PromiseFunc<
    fn(Pubkey, NativeContext) -> Result<(PrecompileOutput, u64, Vec<EthToVlxResult>)>,
    fn(AccountStructure, EthToVlxResult) -> Result<()>,
    Pubkey,
    EthToVlxResult,
>;

#[derive(Serialize, Deserialize, Debug)]
pub struct EthToVlxResult {
    pubkey: Pubkey,
    amount: u64,
}

pub static ETH_TO_VLX_CODE: Lazy<NativeContract<EthToVlxImp, Pubkey>> = Lazy::new(|| {
    #[allow(deprecated)]
    let abi = Function {
        name: String::from("transferToNative"),
        inputs: vec![Param {
            name: String::from("native_recipient"),
            kind: ParamType::FixedBytes(32),
            internal_type: Some(String::from("NativeAddress")),
        }],
        outputs: vec![],
        constant: Some(false),
        state_mutability: StateMutability::Payable,
    };

    // TOOD: Modify gas left.
    fn implementation(
        pubkey: Pubkey,
        cx: NativeContext,
    ) -> Result<(PrecompileOutput, u64, Vec<EthToVlxResult>)> {
        // EVM should ensure that user has enough tokens, before calling this precompile.

        log::trace!("Precompile ETH_TO_VLX");

        if !matches!(
            cx.precompile_context.call_scheme,
            None | Some(CallScheme::Call)
        ) || cx.precompile_context.evm_context.address != *ETH_TO_VLX_ADDR
        // if transfer to other address
        {
            log::trace!(
                "Invalid call type = {:?}",
                cx.precompile_context.call_scheme
            );
            return InvalidCallScheme {
                scheme: cx.precompile_context.call_scheme,
            }
            .fail();
        }

        // TODO: return change back
        let (lamports, _change) =
            gweis_to_lamports(cx.precompile_context.evm_context.apparent_value);
        // TODO: remove native context in handle after majority update
        if cx.keep_old_errors {
            let user = if let Some(account) = cx.accounts.find_user(&pubkey) {
                account
            } else {
                log::trace!("Account not found pk = {}", pubkey);
                return AccountNotFound { public_key: pubkey }.fail();
            };

            let evm_account = cx
                .accounts
                .evm
                .try_account_ref_mut()
                .with_context(|_| NativeChainInstructionError {})?;

            let _user_account = user
                .try_account_ref_mut()
                .with_context(|_| NativeChainInstructionError {})?;

            if lamports > evm_account.lamports() {
                return InsufficientFunds { lamports }.fail();
            }
        }

        Ok((
            PrecompileOutput {
                exit_status: ExitSucceed::Returned,
                output: vec![],
            },
            0,
            vec![
                // Vec::new(), // Only support empty topics for now
                EthToVlxResult {
                    pubkey,
                    amount: lamports,
                },
            ],
        ))
    }

    fn handle_promise(accounts: AccountStructure, promise: EthToVlxResult) -> Result<()> {
        log::trace!("Promise handle ETH_TO_VLX {:?}", promise);
        let lamports = promise.amount;
        let pubkey = promise.pubkey;
        let user = if let Some(account) = accounts.find_user(&pubkey) {
            account
        } else {
            log::trace!("Account not found pk = {}", pubkey);
            return AccountNotFound { public_key: pubkey }.fail();
        };
        let mut evm_account = accounts
            .evm
            .try_account_ref_mut()
            .with_context(|_| NativeChainInstructionError {})?;

        let mut user_account = user
            .try_account_ref_mut()
            .with_context(|_| NativeChainInstructionError {})?;

        if lamports > evm_account.lamports() {
            return InsufficientFunds { lamports }.fail();
        }
        let evm_account_lamports = evm_account.lamports().saturating_sub(lamports);
        let user_account_lamports = user_account.lamports().saturating_add(lamports);
        evm_account.set_lamports(evm_account_lamports);
        user_account.set_lamports(user_account_lamports);
        Ok(())
    }

    NativeContract::new(
        [0xb1, 0xd6, 0x92, 0x7a],
        abi,
        PromiseFunc::new(implementation, handle_promise),
    )
});
