use evm_state::{
    executor::{LogEntry, OwnedPrecompile, PrecompileFailure, PrecompileOutput},
    CallScheme, Context, ExitError, Log, H256,
};
use once_cell::sync::Lazy;
use primitive_types::H160;
use std::collections::{BTreeMap, HashMap};

mod abi_parse;
mod builtins;
mod compatibility;
mod errors;
pub use abi_parse::*;
pub use builtins::{ETH_TO_VLX_ADDR, ETH_TO_VLX_CODE};
pub use compatibility::extend_precompile_map;
pub use errors::PrecompileErrors;

use crate::account_structure::AccountStructure;
use solana_sdk::keyed_account::KeyedAccount;

pub type Result<T, Err = PrecompileErrors> = std::result::Result<T, Err>;
type CallResult = Result<(PrecompileOutput, u64, LogEntry)>;

pub struct NativeContext<'a, 'b> {
    accounts: AccountStructure<'a>,
    keep_old_errors: bool,
    precompile_context: PrecompileContext<'b>,
}

impl<'a, 'b> NativeContext<'a, 'b> {
    fn new(
        keep_old_errors: bool,
        accounts: AccountStructure<'a>,
        gas_limit: Option<u64>,
        evm_context: &'b Context,
        call_scheme: Option<CallScheme>,
    ) -> Self {
        Self {
            keep_old_errors,
            accounts,
            precompile_context: PrecompileContext::new(gas_limit, evm_context, call_scheme),
        }
    }
}

pub struct PrecompileContext<'b> {
    #[allow(unused)]
    gas_limit: Option<u64>,
    evm_context: &'b Context,
    call_scheme: Option<CallScheme>,
}
impl<'b> PrecompileContext<'b> {
    fn new(
        gas_limit: Option<u64>,
        evm_context: &'b Context,
        call_scheme: Option<CallScheme>,
    ) -> Self {
        Self {
            gas_limit,
            evm_context,
            call_scheme,
        }
    }
}

// Currently only static is allowed (but it can be closure).
type BuiltinEval =
    &'static (dyn for<'a, 'c> Fn(&'a [u8], PrecompileContext<'c>) -> CallResult + Sync);

type NativeBuiltinEval =
    &'static (dyn for<'a, 'b, 'c> Fn(&'a [u8], NativeContext<'b, 'c>) -> CallResult + Sync);

type NativePromiseHandler =
    &'static (dyn for<'a, 'b, 'c> Fn(AccountStructure, Vec<H256>, Vec<u8>) -> Result<()> + Sync);

pub static NATIVE_CONTRACTS: Lazy<HashMap<H160, (NativeBuiltinEval, NativePromiseHandler)>> =
    Lazy::new(|| {
        let mut native_contracts = HashMap::new();

        let eth_to_sol: NativeBuiltinEval =
            &|function_abi_input, cx| (*ETH_TO_VLX_CODE).eval(function_abi_input, cx);

        let handle_log: NativePromiseHandler = &|accounts, _topics: Vec<H256>, data| {
            (*ETH_TO_VLX_CODE).process_promise(accounts, data)
        };
        assert!(native_contracts
            .insert(*ETH_TO_VLX_ADDR, (eth_to_sol, handle_log))
            .is_none());
        native_contracts
    });

pub static PRECOMPILES_MAP: Lazy<HashMap<H160, BuiltinEval>> = Lazy::new(|| {
    let mut precompiles = HashMap::new();
    extend_precompile_map(&mut precompiles);
    precompiles
});

// Simulation does not have access to real account structure, so only process immutable entrypoints
pub fn simulation_entrypoint<'a>(
    activate_precompile: bool,
    evm_account: &'a KeyedAccount,
    users_accounts: &'a [KeyedAccount],
) -> OwnedPrecompile<'a> {
    let accounts = AccountStructure::new(evm_account, users_accounts);
    entrypoint(accounts, activate_precompile, true)
}

pub fn entrypoint(
    accounts: AccountStructure,
    activate_precompile: bool,
    keep_old_errors: bool,
) -> OwnedPrecompile {
    let mut map = BTreeMap::new();
    if activate_precompile {
        map.extend(PRECOMPILES_MAP.iter().map(|(k, method)| {
            (
                *k,
                Box::new(
                    move |function_abi_input: &[u8],
                          gas_left,
                          call_scheme,
                          cx: &Context,
                          _is_static| {
                        let cx = PrecompileContext::new(gas_left, cx, call_scheme);
                        method(function_abi_input, cx).map_err(|err| {
                            let exit_err: ExitError = Into::into(err);
                            PrecompileFailure::Error {
                                exit_status: exit_err,
                            }
                        })
                    },
                )
                    as Box<
                        dyn for<'a, 'b> Fn(
                            &'a [u8],
                            Option<u64>,
                            Option<CallScheme>,
                            &'b Context,
                            bool,
                        ) -> Result<
                            (PrecompileOutput, u64, LogEntry),
                            PrecompileFailure,
                        >,
                    >,
            )
        }));
    }
    map.extend(NATIVE_CONTRACTS.iter().map(|(k, (method, _))| {
        (
            *k,
            Box::new(
                move |function_abi_input: &[u8],
                      gas_left,
                      call_scheme,
                      cx: &Context,
                      _is_static| {
                    let cx =
                        NativeContext::new(keep_old_errors, accounts, gas_left, cx, call_scheme);
                    method(function_abi_input, cx).map_err(|err| {
                        let exit_err: ExitError = Into::into(err);
                        PrecompileFailure::Error {
                            exit_status: exit_err,
                        }
                    })
                },
            )
                as Box<
                    dyn for<'a, 'b> Fn(
                        &[u8],
                        Option<u64>,
                        Option<CallScheme>,
                        &Context,
                        bool,
                    ) -> Result<
                        (PrecompileOutput, u64, LogEntry),
                        PrecompileFailure,
                    >,
                >,
        )
    }));
    OwnedPrecompile { precompiles: map }
}

pub fn filter_native_logs(accounts: AccountStructure<'_>, logs: &mut Vec<Log>) -> Result<()> {
    let tmp_logs = std::mem::take(logs);
    for log in tmp_logs {
        if let Some(c) = NATIVE_CONTRACTS.get(&log.address) {
            let handle_promise = c.1;
            (*handle_promise)(accounts, log.topics, log.data)?
        } else {
            logs.push(log)
        }
    }
    Ok(())
}

#[cfg(test)]
mod test {
    use hex_literal::hex;
    use primitive_types::U256;

    use crate::scope::evm::lamports_to_gwei;

    use super::*;
    use evm_state::{ExitError, ExitSucceed};
    use std::str::FromStr;

    #[test]
    fn check_num_builtins() {
        assert_eq!(NATIVE_CONTRACTS.len(), 1);
    }
    #[test]
    fn check_num_precompiles() {
        assert_eq!(PRECOMPILES_MAP.len(), 4);
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
        AccountStructure::testing(0, |accounts| {
            let precompiles = entrypoint(accounts, false, true);
            assert_eq!(
                dbg!(precompiles.precompiles.get(&addr).unwrap()(&input, None, None, &cx, false).unwrap_err()),
                PrecompileFailure::Error { exit_status: ExitError::Other("Failed to find account, account_pk = 29d2S7vB453rNYFdR5Ycwt7y9haRT5fwVwL9zTmBhfV2".into()) } // equal to 0x111..111 in base58
            );
        })
    }

    fn log_entry_to_logs(address: H160, entries: LogEntry) -> Vec<Log> {
        let mut logs = Vec::new();
        for (topics, data) in entries {
            logs.push(Log {
                address,
                topics,
                data,
            })
        }
        logs
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
            let precompiles = entrypoint(accounts, false, false);
            let user = accounts.first().unwrap();
            let input = hex::decode(format!(
                "b1d6927a{}",
                hex::encode(user.unsigned_key().to_bytes())
            ))
            .unwrap();
            let lamports_before = user.lamports().unwrap();
            let precompile_output = dbg!(precompiles.precompiles.get(&addr).unwrap()(
                &input, None, None, &cx, false
            ));
            assert!(matches!(
                precompile_output,
                Ok((
                    PrecompileOutput {
                        exit_status: ExitSucceed::Returned,
                        ..
                    },
                    0,
                    _
                ))
            ));
            let mut logs = log_entry_to_logs(addr, precompile_output.unwrap().2);
            assert!(!logs.is_empty());
            filter_native_logs(accounts, &mut logs).unwrap();
            assert!(logs.is_empty());

            let lamports_after = user.lamports().unwrap();
            assert_eq!(lamports_before + 1, lamports_after)
        })
    }

    #[test]
    fn call_to_sha256() {
        let addr = H160::from_str("0000000000000000000000000000000000000002").unwrap();

        let cx = Context {
            address: H160::from_str("0000000000000000000000000000000000000002").unwrap(),
            caller: H160::from_str("0000000000000000000000000000000000000002").unwrap(),
            apparent_value: lamports_to_gwei(1),
        };
        AccountStructure::testing(0, |accounts: AccountStructure| {
            let precompiles = entrypoint(accounts, true, false);
            let input = [0u8; 0];
            let result =
                precompiles.precompiles.get(&addr).unwrap()(&input, None, None, &cx, false)
                    .unwrap();
            println!("{}", hex::encode(&result.0.output));
            assert_eq!(
                result,
                (
                    PrecompileOutput {
                        exit_status: ExitSucceed::Returned,
                        output: hex!(
                            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                        )
                        .to_vec(),
                    },
                    60,
                    vec![]
                )
            );
        })
    }

    #[test]
    fn call_to_identity() {
        let addr = H160::from_str("0000000000000000000000000000000000000004").unwrap();

        let cx = Context {
            address: H160::from_str("0000000000000000000000000000000000000004").unwrap(),
            caller: H160::from_str("0000000000000000000000000000000000000004").unwrap(),
            apparent_value: lamports_to_gwei(1),
        };
        AccountStructure::testing(0, |accounts: AccountStructure| {
            let precompiles = entrypoint(accounts, true, false);
            let input = [1, 2, 3, 4];
            let result =
                precompiles.precompiles.get(&addr).unwrap()(&input, None, None, &cx, false)
                    .unwrap();
            println!("{}", hex::encode(&result.0.output));
            assert_eq!(
                result,
                (
                    PrecompileOutput {
                        exit_status: ExitSucceed::Returned,
                        output: input.to_vec(),
                    },
                    15,
                    vec![]
                )
            );
        })
    }

    #[test]
    fn call_to_identity_disabled() {
        let addr = H160::from_str("0000000000000000000000000000000000000004").unwrap();
        AccountStructure::testing(0, |accounts: AccountStructure| {
            let precompiles = entrypoint(accounts, false, false);
            assert!(precompiles.precompiles.get(&addr).is_none());
        })
    }

    #[test]
    fn call_to_ripemd160() {
        let addr = H160::from_str("0000000000000000000000000000000000000003").unwrap();

        let cx = Context {
            address: H160::from_str("0000000000000000000000000000000000000003").unwrap(),
            caller: H160::from_str("0000000000000000000000000000000000000003").unwrap(),
            apparent_value: lamports_to_gwei(1),
        };
        AccountStructure::testing(0, |accounts: AccountStructure| {
            let precompiles = entrypoint(accounts, true, false);
            let input = [0u8; 0];
            let result =
                precompiles.precompiles.get(&addr).unwrap()(&input, None, None, &cx, false)
                    .unwrap();
            println!("{}", hex::encode(&result.0.output));
            assert_eq!(
                result,
                (
                    PrecompileOutput {
                        exit_status: ExitSucceed::Returned,
                        output: hex!(
                            "0000000000000000000000009c1185a5c5e9fc54612808977ee8f548b2258d31"
                        )
                        .to_vec(),
                    },
                    60,
                    vec![]
                )
            );
        })
    }

    #[test]
    fn call_to_ecrecover() {
        let addr = H160::from_str("0000000000000000000000000000000000000001").unwrap();

        let cx = Context {
            address: H160::from_str("0000000000000000000000000000000000000001").unwrap(),
            caller: H160::from_str("0000000000000000000000000000000000000001").unwrap(),
            apparent_value: lamports_to_gwei(1),
        };
        AccountStructure::testing(0, |accounts: AccountStructure| {
            let precompiles = entrypoint(accounts, true, false);
            let input = hex!("47173285a8d7341e5e972fc677286384f802f8ef42a5ec5f03bbfa254cb01fad000000000000000000000000000000000000000000000000000000000000001a650acf9d3f5f0a2c799776a1254355d5f4061762a237396a99a0e0e3fc2bcd6729514a0dacb2e623ac4abd157cb18163ff942280db4d5caad66ddf941ba12e03");

            let result =
                precompiles.precompiles.get(&addr).unwrap()(&input, None, None, &cx, false)
                    .unwrap();
            println!("{}", hex::encode(&result.0.output));
            assert_eq!(
                result,
                (
                    PrecompileOutput {
                        exit_status: ExitSucceed::Returned,
                        output: vec![],
                    },
                    108,
                    vec![]
                )
            );
        });
        AccountStructure::testing(0, |accounts: AccountStructure| {
            let precompiles = entrypoint(accounts, true, false);
            let input = hex!("47173285a8d7341e5e972fc677286384f802f8ef42a5ec5f03bbfa254cb01fad000000000000000000000000000000000000000000000000000000000000001b650acf9d3f5f0a2c799776a1254355d5f4061762a237396a99a0e0e3fc2bcd6729514a0dacb2e623ac4abd157cb18163ff942280db4d5caad66ddf941ba12e03");

            let result =
                precompiles.precompiles.get(&addr).unwrap()(&input, None, None, &cx, false)
                    .unwrap();
            println!("{}", hex::encode(&result.0.output));
            assert_eq!(
                result,
                (
                    PrecompileOutput {
                        exit_status: ExitSucceed::Returned,
                        output: hex!(
                            "000000000000000000000000c08b5542d177ac6686946920409741463a15dddb"
                        )
                        .to_vec(),
                    },
                    108,
                    vec![]
                )
            );
        });
    }
}
