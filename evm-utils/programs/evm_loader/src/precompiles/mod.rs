use evm_state::{Context, ExitSucceed};
use primitive_types::H160;

mod abi_parse;
mod builtins;
mod errors;
pub use abi_parse::*;
use builtins::BUILTINS_MAP;
pub use builtins::{ETH_TO_SOL_ADDR, ETH_TO_SOL_CODE};
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

fn entrypoint_static(
    address: H160,
    function_abi_input: &[u8],
    cx: PrecompileContext,
) -> Option<evm_state::PrecompileCallResult> {
    let method = BUILTINS_MAP.get(&address)?;
    let result = method(function_abi_input, cx)
        .map(Into::into)
        .map_err(Into::into);
    Some(result)
}

pub(crate) fn entrypoint(
    accounts: AccountStructure,
) -> impl FnMut(H160, &[u8], Option<u64>, &Context) -> Option<evm_state::PrecompileCallResult> + '_
{
    move |address, function_abi_input, gas_left, cx| {
        entrypoint_static(
            address,
            function_abi_input,
            PrecompileContext::new(accounts, gas_left, cx),
        )
    }
}

#[cfg(test)]
mod test {
    use primitive_types::U256;

    use crate::scope::evm::lamports_to_gwei;

    use super::builtins::BUILTINS_MAP;
    use super::*;
    use evm_state::{ExitError, ExitSucceed};
    use std::str::FromStr;

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
        AccountStructure::testing(0, |accounts| {
            assert_eq!(
                dbg!(entrypoint_static(addr, &input, PrecompileContext::new(accounts, None, &cx)).unwrap()),
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
                dbg!(entrypoint_static(
                    addr,
                    &input,
                    PrecompileContext::new(accounts, None, &cx)
                )),
                Some(Ok((ExitSucceed::Returned, _, 0)))
            ));

            let lamports_after = user.lamports().unwrap();
            assert_eq!(lamports_before + 1, lamports_after)
        })
    }
}
