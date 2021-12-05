use evm_state::{Context, ExitSucceed};

use once_cell::sync::Lazy;
use primitive_types::H160;
use solana_sdk::keyed_account::KeyedAccount;
use std::cell::RefCell;
use std::collections::HashMap;

mod abi_parse;
mod builtins;
mod compatibility;
mod errors;
pub use abi_parse::*;
pub use builtins::{ETH_TO_VLX_ADDR, ETH_TO_VLX_CODE};
pub use compatibility::extend_precompile_map;
pub use errors::PrecompileErrors;

use crate::account_structure::AccountStructure;

pub type Result<T, Err = PrecompileErrors> = std::result::Result<T, Err>;
type CallResult = Result<PrecompileOk>;

/// If precompile succeed, returns `ExitSucceed` - info about execution, Vec<u8> - output data, u64 - gas cost
pub struct PrecompileOk {
    reason: ExitSucceed,
    bytes: Vec<u8>,
    gas_used: u64,
}

impl PrecompileOk {
    pub fn new(reason: ExitSucceed, bytes: Vec<u8>, gas_used: u64) -> PrecompileOk {
        Self {
            reason,
            bytes,
            gas_used,
        }
    }
}

impl From<PrecompileOk> for (ExitSucceed, Vec<u8>, u64) {
    fn from(ok: PrecompileOk) -> Self {
        (ok.reason, ok.bytes, ok.gas_used)
    }
}

pub struct PrecompileContext<'a> {
    accounts: AccountStructure<'a>,
    #[allow(unused)]
    gas_limit: Option<u64>,
    evm_context: &'a Context,
}
impl<'a> PrecompileContext<'a> {
    fn new(
        accounts: AccountStructure<'a>,
        gas_limit: Option<u64>,
        evm_context: &'a Context,
    ) -> Self {
        Self {
            accounts,
            gas_limit,
            evm_context,
        }
    }
}

// Currently only static is allowed (but it can be closure).
type BuiltinEval = &'static (dyn Fn(&[u8], PrecompileContext) -> CallResult + Sync);
pub static NATIVE_CONTRACTS: Lazy<HashMap<H160, BuiltinEval>> = Lazy::new(|| {
    let mut native_contracts = HashMap::new();

    let eth_to_sol: BuiltinEval =
        &|function_abi_input, cx| (*ETH_TO_VLX_CODE).eval(function_abi_input, cx);
    assert!(native_contracts
        .insert(*ETH_TO_VLX_ADDR, eth_to_sol)
        .is_none());
    native_contracts
});

pub static PRECOMPILES_MAP: Lazy<HashMap<H160, BuiltinEval>> = Lazy::new(|| {
    let mut precompiles = HashMap::new();
    extend_precompile_map(&mut precompiles);
    precompiles
});

fn entrypoint_static(
    address: H160,
    function_abi_input: &[u8],
    cx: PrecompileContext,
    activate_precompile: bool,
) -> Option<evm_state::PrecompileCallResult> {
    log::trace!("Searching for precompile(builtin) = {}", address);
    let mut method = NATIVE_CONTRACTS.get(&address);
    if method.is_none() && activate_precompile {
        method = PRECOMPILES_MAP.get(&address);
    }
    let method = method?;
    log::trace!("Precompile found");
    let result = method(function_abi_input, cx)
        .map(Into::into)
        .map_err(Into::into);

    log::trace!("Precompile Executed = {:?}", result);
    Some(result)
}

// Simulation does not have access to real account structure, so only process immutable entrypoints
pub fn simulation_entrypoint<'a>(
    activate_precompile: bool,
    evm_state_balance: u64,
    users_accounts: &'a [KeyedAccount],
) -> impl FnMut(H160, &[u8], Option<u64>, &Context) -> Option<evm_state::PrecompileCallResult> + 'a
{
    move |address, function_abi_input, gas_left, cx| {
        let evm_account = RefCell::new(crate::create_state_account(evm_state_balance));
        let evm_keyed_account = KeyedAccount::new(&solana_sdk::evm_state::ID, false, &evm_account);

        let accounts = AccountStructure::new(&evm_keyed_account, users_accounts);
        entrypoint_static(
            address,
            function_abi_input,
            PrecompileContext::new(accounts, gas_left, cx),
            activate_precompile,
        )
    }
}

pub(crate) fn entrypoint(
    accounts: AccountStructure,
    activate_precompile: bool,
) -> impl FnMut(H160, &[u8], Option<u64>, &Context) -> Option<evm_state::PrecompileCallResult> + '_
{
    move |address, function_abi_input, gas_left, cx| {
        entrypoint_static(
            address,
            function_abi_input,
            PrecompileContext::new(accounts, gas_left, cx),
            activate_precompile,
        )
    }
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
        assert_eq!(PRECOMPILES_MAP.len(), 9);
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
            assert_eq!(
                dbg!(entrypoint_static(addr, &input, PrecompileContext::new(accounts, None, &cx), false).unwrap()),
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
            let user = accounts.first().unwrap();
            let input = hex::decode(format!(
                "b1d6927a{}",
                hex::encode(user.unsigned_key().to_bytes())
            ))
            .unwrap();
            let lamports_before = user.lamports().unwrap();
            assert!(matches!(
                dbg!(entrypoint_static(
                    addr,
                    &input,
                    PrecompileContext::new(accounts, None, &cx),
                    false
                )),
                Some(Ok((ExitSucceed::Returned, _, 0)))
            ));

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
            let input = [0u8; 0];
            let result = entrypoint_static(
                addr,
                &input,
                PrecompileContext::new(accounts, None, &cx),
                true,
            );
            let result = result.unwrap().unwrap();
            println!("{}", hex::encode(&result.1));
            assert_eq!(
                result,
                (
                    ExitSucceed::Returned,
                    hex!("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
                        .to_vec(),
                    60
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
            let input = [1, 2, 3, 4];
            let result = entrypoint_static(
                addr,
                &input,
                PrecompileContext::new(accounts, None, &cx),
                true,
            );
            let result = result.unwrap().unwrap();
            println!("{}", hex::encode(&result.1));

            #[cfg(not(feature = "pricefix"))]
            assert_eq!(result, (ExitSucceed::Returned, input.to_vec(), 15));

            #[cfg(feature = "pricefix")]
            assert_eq!(result, (ExitSucceed::Returned, input.to_vec(), 18));
        })
    }

    #[test]
    fn call_to_identity_disabled() {
        let addr = H160::from_str("0000000000000000000000000000000000000004").unwrap();

        let cx = Context {
            address: H160::from_str("0000000000000000000000000000000000000004").unwrap(),
            caller: H160::from_str("0000000000000000000000000000000000000004").unwrap(),
            apparent_value: lamports_to_gwei(1),
        };

        AccountStructure::testing(0, |accounts: AccountStructure| {
            let input = [1, 2, 3, 4];
            let result = entrypoint_static(
                addr,
                &input,
                PrecompileContext::new(accounts, None, &cx),
                false,
            );
            assert!(result.is_none());
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
            let input = [0u8; 0];
            let result = entrypoint_static(
                addr,
                &input,
                PrecompileContext::new(accounts, None, &cx),
                true,
            );
            let result = result.unwrap().unwrap();
            println!("{}", hex::encode(&result.1));

            #[cfg(not(feature = "pricefix"))]
            assert_eq!(
                result,
                (
                    ExitSucceed::Returned,
                    hex!("0000000000000000000000009c1185a5c5e9fc54612808977ee8f548b2258d31")
                        .to_vec(),
                    60
                )
            );

            #[cfg(feature = "pricefix")]
            assert_eq!(
                result,
                (
                    ExitSucceed::Returned,
                    hex!("0000000000000000000000009c1185a5c5e9fc54612808977ee8f548b2258d31")
                        .to_vec(),
                    600
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
            let input = hex!("47173285a8d7341e5e972fc677286384f802f8ef42a5ec5f03bbfa254cb01fad000000000000000000000000000000000000000000000000000000000000001a650acf9d3f5f0a2c799776a1254355d5f4061762a237396a99a0e0e3fc2bcd6729514a0dacb2e623ac4abd157cb18163ff942280db4d5caad66ddf941ba12e03");

            let result = entrypoint_static(
                addr,
                &input,
                PrecompileContext::new(accounts, None, &cx),
                true,
            );
            let result = result.unwrap().unwrap();
            println!("{}", hex::encode(&result.1));

            #[cfg(not(feature = "pricefix"))]
            assert_eq!(result, (ExitSucceed::Returned, vec![], 108));

            #[cfg(feature = "pricefix")]
            assert_eq!(result, (ExitSucceed::Returned, vec![], 3000));
        });

        AccountStructure::testing(0, |accounts: AccountStructure| {
            let input = hex!("47173285a8d7341e5e972fc677286384f802f8ef42a5ec5f03bbfa254cb01fad000000000000000000000000000000000000000000000000000000000000001b650acf9d3f5f0a2c799776a1254355d5f4061762a237396a99a0e0e3fc2bcd6729514a0dacb2e623ac4abd157cb18163ff942280db4d5caad66ddf941ba12e03");

            let result = entrypoint_static(
                addr,
                &input,
                PrecompileContext::new(accounts, None, &cx),
                true,
            );
            let result = result.unwrap().unwrap();
            println!("{}", hex::encode(&result.1));

            #[cfg(not(feature = "pricefix"))]
            assert_eq!(
                result,
                (
                    ExitSucceed::Returned,
                    hex!("000000000000000000000000c08b5542d177ac6686946920409741463a15dddb")
                        .to_vec(),
                    108
                )
            );

            #[cfg(feature = "pricefix")]
            assert_eq!(
                result,
                (
                    ExitSucceed::Returned,
                    hex!("000000000000000000000000c08b5542d177ac6686946920409741463a15dddb")
                        .to_vec(),
                    3000
                )
            );
        });
    }

    #[test]
    fn call_modexp() {
        let addr = H160::from_str("0000000000000000000000000000000000000005").unwrap();

        let cx = Context {
            address: H160::from_str("0000000000000000000000000000000000000005").unwrap(),
            caller: H160::from_str("0000000000000000000000000000000000000005").unwrap(),
            apparent_value: lamports_to_gwei(1),
        };

        // // test for potential exp len overflow
        // // this test is slow
        // AccountStructure::testing(0, |accounts| {
        //     let input = hex!(
        //         "
        //         00000000000000000000000000000000000000000000000000000000000000ff
        //         2a1e530000000000000000000000000000000000000000000000000000000000
        //         0000000000000000000000000000000000000000000000000000000000000000
        //         "
        //     );

        //     let expected = hex!("0000000000000000000000000000000000000000000000000000000000000000");

        //     let result = entrypoint_static(
        //         addr,
        //         &input,
        //         PrecompileContext::new(accounts, None, &cx),
        //         true,
        //     );

        //     let (_result, output, _) = result.unwrap().unwrap();

        //     assert_eq!(output, expected);
        // });

        // fermat's little theorem example.
        AccountStructure::testing(0, |accounts| {
            let input = hex!(
                "
                0000000000000000000000000000000000000000000000000000000000000001
                0000000000000000000000000000000000000000000000000000000000000020
                0000000000000000000000000000000000000000000000000000000000000020
                03
                fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2e
                fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f
                "
            );

            let expected = hex!("0000000000000000000000000000000000000000000000000000000000000001");

            let result = entrypoint_static(
                addr,
                &input,
                PrecompileContext::new(accounts, None, &cx),
                true,
            );

            let (_result, output, price) = result.unwrap().unwrap();

            assert_eq!(output, expected);
            assert_eq!(price, 13_056);
        });

        // second example from EIP: zero base.
        AccountStructure::testing(0, |accounts| {
            let input = hex!(
                "
                0000000000000000000000000000000000000000000000000000000000000000
                0000000000000000000000000000000000000000000000000000000000000020
                0000000000000000000000000000000000000000000000000000000000000020
                fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2e
                fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f"
            );

            let expected = hex!("0000000000000000000000000000000000000000000000000000000000000000");

            let result = entrypoint_static(
                addr,
                &input,
                PrecompileContext::new(accounts, None, &cx),
                true,
            );

            let (_result, output, price) = result.unwrap().unwrap();

            assert_eq!(output, expected);
            assert_eq!(price, 13056);
        });

        // another example from EIP: zero-padding
        AccountStructure::testing(0, |accounts| {
            let input = hex!(
                "
                0000000000000000000000000000000000000000000000000000000000000001
                0000000000000000000000000000000000000000000000000000000000000002
                0000000000000000000000000000000000000000000000000000000000000020
                03
                ffff
                80"
            );

            let expected = hex!("3b01b01ac41f2d6e917c6d6a221ce793802469026d9ab7578fa2e79e4da6aaab");

            let result = entrypoint_static(
                addr,
                &input,
                PrecompileContext::new(accounts, None, &cx),
                true,
            );

            let (_result, output, price) = result.unwrap().unwrap();

            assert_eq!(output, expected);
            assert_eq!(price, 768);
        });

        // zero-length modulus.
        AccountStructure::testing(0, |accounts| {
            let input = hex!(
                "
                0000000000000000000000000000000000000000000000000000000000000001
                0000000000000000000000000000000000000000000000000000000000000002
                0000000000000000000000000000000000000000000000000000000000000000
                03
                ffff"
            );

            let result = entrypoint_static(
                addr,
                &input,
                PrecompileContext::new(accounts, None, &cx),
                true,
            );

            let (_result, output, price) = result.unwrap().unwrap();

            assert_eq!(output.len(), 0); // shouldn't have written any output.
            assert_eq!(price, 0);
        });
    }

    // This test is slow
    #[ignore]
    #[test]
    fn modexp_price_overflows() {
        let addr = H160::from_str("0000000000000000000000000000000000000005").unwrap();

        let cx = Context {
            address: H160::from_str("0000000000000000000000000000000000000005").unwrap(),
            caller: H160::from_str("0000000000000000000000000000000000000005").unwrap(),
            apparent_value: lamports_to_gwei(1),
        };

        AccountStructure::testing(0, |accounts| {
            let input = hex!(
                "
                0000000000000000000000000000000000000000000000000000000000000001
                000000000000000000000000000000000000000000000000000000003b27bafd
                00000000000000000000000000000000000000000000000000000000503c8ac3
                "
            );

            let result = entrypoint_static(
                addr,
                &input,
                PrecompileContext::new(accounts, None, &cx),
                true,
            );

            let (_result, _output, price) = result.unwrap().unwrap();

            assert_eq!(price, u64::max_value());
        });

        AccountStructure::testing(0, |accounts| {
            let input = hex!(
                "
                00000000000000000000000000000000000000000000000000000000000000ff
                2a1e530000000000000000000000000000000000000000000000000000000000
                0000000000000000000000000000000000000000000000000000000000000000
                "
            );

            let result = entrypoint_static(
                addr,
                &input,
                PrecompileContext::new(accounts, None, &cx),
                true,
            );

            let (_result, _output, price) = result.unwrap().unwrap();

            assert_eq!(price, u64::max_value());
        });
    }

    #[test]
    fn call_bn_128_add() {
        let addr = H160::from_str("0000000000000000000000000000000000000006").unwrap();

        let cx = Context {
            address: H160::from_str("0000000000000000000000000000000000000006").unwrap(),
            caller: H160::from_str("0000000000000000000000000000000000000006").unwrap(),
            apparent_value: U256::from(1),
        };

        // zero-points additions
        AccountStructure::testing(0, |accounts| {
            let input = hex!(
                "
                0000000000000000000000000000000000000000000000000000000000000000
                0000000000000000000000000000000000000000000000000000000000000000
                0000000000000000000000000000000000000000000000000000000000000000
                0000000000000000000000000000000000000000000000000000000000000000
                "
            );

            let result = entrypoint_static(
                addr,
                &input,
                PrecompileContext::new(accounts, None, &cx),
                true,
            );

            let (_result, output, price) = result.unwrap().unwrap();

            let expected = hex!(
                "
                0000000000000000000000000000000000000000000000000000000000000000
                0000000000000000000000000000000000000000000000000000000000000000
                "
            );

            assert_eq!(output, expected);
            assert_eq!(price, 150);
        });

        // no input, should not fail
        AccountStructure::testing(0, |accounts| {
            let input = [0u8; 0];

            let expected = hex!(
                "
                0000000000000000000000000000000000000000000000000000000000000000
                0000000000000000000000000000000000000000000000000000000000000000
                "
            );

            let result = entrypoint_static(
                addr,
                &input,
                PrecompileContext::new(accounts, None, &cx),
                true,
            );

            let (_result, output, _) = result.unwrap().unwrap();

            assert_eq!(output, expected);
        });

        // should fail - point not on curve
        AccountStructure::testing(0, |accounts| {
            let input = hex!(
                "
                1111111111111111111111111111111111111111111111111111111111111111
                1111111111111111111111111111111111111111111111111111111111111111
                1111111111111111111111111111111111111111111111111111111111111111
                1111111111111111111111111111111111111111111111111111111111111111
                "
            );

            let result = entrypoint_static(
                addr,
                &input,
                PrecompileContext::new(accounts, None, &cx),
                true,
            );

            let result = result.unwrap();

            assert!(result.is_err())
        });
    }

    #[test]
    fn call_bn_128_mul() {
        let addr = H160::from_str("0000000000000000000000000000000000000007").unwrap();

        let cx = Context {
            address: H160::from_str("0000000000000000000000000000000000000007").unwrap(),
            caller: H160::from_str("0000000000000000000000000000000000000007").unwrap(),
            apparent_value: U256::from(1),
        };

        // zero-point multiplication
        AccountStructure::testing(0, |accounts| {
            let input = hex!(
                "
                0000000000000000000000000000000000000000000000000000000000000000
                0000000000000000000000000000000000000000000000000000000000000000
                0200000000000000000000000000000000000000000000000000000000000000
                "
            );

            let expected = hex!(
                "
                0000000000000000000000000000000000000000000000000000000000000000
                0000000000000000000000000000000000000000000000000000000000000000
                "
            );

            let result = entrypoint_static(
                addr,
                &input,
                PrecompileContext::new(accounts, None, &cx),
                true,
            );

            let (_result, output, price) = result.unwrap().unwrap();

            assert_eq!(output, expected);
            assert_eq!(price, 6000);
        });

        // should fail - point not on curve
        AccountStructure::testing(0, |accounts| {
            let input = hex!(
                "
                1111111111111111111111111111111111111111111111111111111111111111
                1111111111111111111111111111111111111111111111111111111111111111
                0f00000000000000000000000000000000000000000000000000000000000000
                "
            );

            let result = entrypoint_static(
                addr,
                &input,
                PrecompileContext::new(accounts, None, &cx),
                true,
            );

            let result = result.unwrap();

            assert!(result.is_err())
        });
    }

    #[test]
    fn call_bn_128_pairing() {
        let addr = H160::from_str("0000000000000000000000000000000000000008").unwrap();

        let cx = Context {
            address: H160::from_str("0000000000000000000000000000000000000008").unwrap(),
            caller: H160::from_str("0000000000000000000000000000000000000008").unwrap(),
            apparent_value: U256::from(1),
        };

        // should not fail, because empty input is a valid input of 0 elements
        AccountStructure::testing(0, |accounts| {
            let input = [0u8; 0];

            let expected = hex!("0000000000000000000000000000000000000000000000000000000000000001");

            let result = entrypoint_static(
                addr,
                &input,
                PrecompileContext::new(accounts, None, &cx),
                true,
            );

            let (_result, output, price) = result.unwrap().unwrap();

            assert_eq!(output, expected);
            assert_eq!(price, 45_000);
        });

        // should fail - point not on curve
        AccountStructure::testing(0, |accounts| {
            let input = hex!(
                "
                1111111111111111111111111111111111111111111111111111111111111111
                1111111111111111111111111111111111111111111111111111111111111111
                1111111111111111111111111111111111111111111111111111111111111111
                1111111111111111111111111111111111111111111111111111111111111111
                1111111111111111111111111111111111111111111111111111111111111111
                1111111111111111111111111111111111111111111111111111111111111111
                "
            );

            let result = entrypoint_static(
                addr,
                &input,
                PrecompileContext::new(accounts, None, &cx),
                true,
            );

            let result = result.unwrap();

            assert!(result.is_err());
        });

        // should fail - input length is invalid
        AccountStructure::testing(0, |accounts| {
            let input = hex!(
                "
                1111111111111111111111111111111111111111111111111111111111111111
                1111111111111111111111111111111111111111111111111111111111111111
                111111111111111111111111111111
                "
            );

            let result = entrypoint_static(
                addr,
                &input,
                PrecompileContext::new(accounts, None, &cx),
                true,
            );

            let result = result.unwrap();

            assert!(result.is_err());
        });
    }

    #[test]
    fn call_blake2f() {
        let addr = H160::from_str("0000000000000000000000000000000000000009").unwrap();

        let cx = Context {
            address: H160::from_str("0000000000000000000000000000000000000009").unwrap(),
            caller: H160::from_str("0000000000000000000000000000000000000009").unwrap(),
            apparent_value: U256::from(1),
        };

        // Test vector 4 and expected output from https://github.com/ethereum/EIPs/blob/master/EIPS/eip-152.md#test-vector-4
        AccountStructure::testing(0, |accounts| {
            let input = hex!(
                "
                0000000048c9bdf267e6096a3ba7ca8485ae67bb2bf894fe72f36e3cf1361d5f
                3af54fa5d182e6ad7f520e511f6c3e2b8c68059b6bbd41fbabd9831f79217e13
                19cde05b61626300000000000000000000000000000000000000000000000000
                0000000000000000000000000000000000000000000000000000000000000000
                0000000000000000000000000000000000000000000000000000000000000000
                0000000000000000000000000000000000000000000000000000000000000000
                000000000300000000000000000000000000000001
                "
            );

            let expected = hex!(
                "
                08c9bcf367e6096a3ba7ca8485ae67bb2bf894fe72f36e3cf1361d5f3af54fa5
                d282e6ad7f520e511f6c3e2b8c68059b9442be0454267ce079217e1319cde05b
                "
            );

            let result = entrypoint_static(
                addr,
                &input,
                PrecompileContext::new(accounts, None, &cx),
                true,
            );

            let (_result, output, price) = result.unwrap().unwrap();

            assert_eq!(output, expected);
            assert_eq!(price, 0);
        });

        // Test vector 5 and expected output from https://github.com/ethereum/EIPs/blob/master/EIPS/eip-152.md#test-vector-5
        AccountStructure::testing(0, |accounts| {
            let input = hex!(
                "
                0000000c48c9bdf267e6096a3ba7ca8485ae67bb2bf894fe72f36e3cf1361d5f
                3af54fa5d182e6ad7f520e511f6c3e2b8c68059b6bbd41fbabd9831f79217e13
                19cde05b61626300000000000000000000000000000000000000000000000000
                0000000000000000000000000000000000000000000000000000000000000000
                0000000000000000000000000000000000000000000000000000000000000000
                0000000000000000000000000000000000000000000000000000000000000000
                000000000300000000000000000000000000000001
                "
            );

            let expected = hex!(
                "
                ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1
                7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923
                "
            );

            let result = entrypoint_static(
                addr,
                &input,
                PrecompileContext::new(accounts, None, &cx),
                true,
            );

            let (_result, output, price) = result.unwrap().unwrap();

            assert_eq!(output, expected);
            assert_eq!(price, 12);
        });

        // Test vector 6 and expected output from https://github.com/ethereum/EIPs/blob/master/EIPS/eip-152.md#test-vector-6
        AccountStructure::testing(0, |accounts| {
            let input = hex!(
                "
                0000000c48c9bdf267e6096a3ba7ca8485ae67bb2bf894fe72f36e3cf1361d5f
                3af54fa5d182e6ad7f520e511f6c3e2b8c68059b6bbd41fbabd9831f79217e13
                19cde05b61626300000000000000000000000000000000000000000000000000
                0000000000000000000000000000000000000000000000000000000000000000
                0000000000000000000000000000000000000000000000000000000000000000
                0000000000000000000000000000000000000000000000000000000000000000
                000000000300000000000000000000000000000000
                "
            );

            let expected = hex!(
                "
                75ab69d3190a562c51aef8d88f1c2775876944407270c42c9844252c26d28752
                98743e7f6d5ea2f2d3e8d226039cd31b4e426ac4f2d3d666a610c2116fde4735
                "
            );

            let result = entrypoint_static(
                addr,
                &input,
                PrecompileContext::new(accounts, None, &cx),
                true,
            );

            let (_result, output, price) = result.unwrap().unwrap();

            assert_eq!(output, expected);
            assert_eq!(price, 12);
        });

        // Test vector 7 and expected output from https://github.com/ethereum/EIPs/blob/master/EIPS/eip-152.md#test-vector-7
        AccountStructure::testing(0, |accounts| {
            let input = hex!(
                "
                0000000148c9bdf267e6096a3ba7ca8485ae67bb2bf894fe72f36e3cf1361d5f
                3af54fa5d182e6ad7f520e511f6c3e2b8c68059b6bbd41fbabd9831f79217e13
                19cde05b61626300000000000000000000000000000000000000000000000000
                0000000000000000000000000000000000000000000000000000000000000000
                0000000000000000000000000000000000000000000000000000000000000000
                0000000000000000000000000000000000000000000000000000000000000000
                000000000300000000000000000000000000000001
                "
            );

            let expected = hex!(
                "
                b63a380cb2897d521994a85234ee2c181b5f844d2c624c002677e9703449d2fb
                a551b3a8333bcdf5f2f7e08993d53923de3d64fcc68c034e717b9293fed7a421
                "
            );

            let result = entrypoint_static(
                addr,
                &input,
                PrecompileContext::new(accounts, None, &cx),
                true,
            );

            let (_result, output, price) = result.unwrap().unwrap();

            assert_eq!(output, expected);
            assert_eq!(price, 1);
        });
    }
}
