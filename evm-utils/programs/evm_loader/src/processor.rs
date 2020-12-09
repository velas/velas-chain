use super::instructions::{Deposit, EvmInstruction};
use super::scope::*;
use evm::TransactionAction;
use log::*;

use evm::EvmState;
use evm::StaticExecutor;
use solana_sdk::instruction::InstructionError;
use solana_sdk::pubkey::Pubkey;
use solana_sdk::{
    account::KeyedAccount,
    program_utils::limited_deserialize,
    sysvar::{rent::Rent, Sysvar},
};

/// Return the next AccountInfo or a NotEnoughAccountKeys error
pub fn next_account_info<'a, 'b, I: Iterator<Item = &'a KeyedAccount<'b>>>(
    iter: &mut I,
) -> Result<I::Item, InstructionError> {
    iter.next().ok_or(InstructionError::NotEnoughAccountKeys)
}

/// Ensure that first account is program itself, and it's locked for writes.
fn check_evm_account<'a, 'b>(
    program_id: &Pubkey,
    keyed_accounts: &'a [KeyedAccount<'b>],
) -> Result<&'a [KeyedAccount<'b>], InstructionError> {
    let first = keyed_accounts
        .first()
        .ok_or(InstructionError::NotEnoughAccountKeys)?;

    if first.unsigned_key() != program_id || !first.is_writable() {
        error!("First account is not evm, or not writable");
        return Err(InstructionError::MissingAccount);
    }

    let keyed_accounts = &keyed_accounts[1..];
    Ok(keyed_accounts)
}

#[derive(Default, Debug, Clone)]
pub struct EvmProcessor {}

impl EvmProcessor {
    pub fn process_initialize_deposit(
        accounts: &[KeyedAccount],
        pubkey: Pubkey,
    ) -> Result<(), InstructionError> {
        let account_info_iter = &mut accounts.iter();
        let deposit_info = next_account_info(account_info_iter)?;
        let rent_account = next_account_info(account_info_iter)?;
        let deposit_info_len = deposit_info.data_len()?;
        let rent = &Rent::from_account(&*rent_account.try_account_ref()?)
            .ok_or(InstructionError::InvalidArgument)?;

        let mut deposit: Deposit =
            limited_deserialize(&deposit_info.try_account_ref()?.data).unwrap_or_default();
        if deposit.is_initialized {
            return Err(InstructionError::AccountAlreadyInitialized);
        }

        if !rent.is_exempt(deposit_info.lamports()?, deposit_info_len) {
            return Err(InstructionError::ExecutableAccountNotRentExempt);
        }

        deposit.deposit_authority = Option::Some(pubkey);
        deposit.is_initialized = true;
        deposit.locked_lamports = 0;

        bincode::serialize_into(&mut *deposit_info.try_account_ref_mut()?.data, &deposit)
            .map_err(|_| InstructionError::InvalidArgument)?;

        Ok(())
    }

    pub fn process_instruction(
        &self,
        program_id: &Pubkey,
        keyed_accounts: &[KeyedAccount],
        data: &[u8],
        executor: Option<&mut StaticExecutor<EvmState>>,
    ) -> Result<(), InstructionError> {
        let executor = executor.expect("Evm execution from crossprogram is not allowed.");
        let evm_executor = executor.rent_executor();

        let keyed_accounts = check_evm_account(program_id, keyed_accounts)?;

        let ix = limited_deserialize(data)?;
        debug!("Run evm exec with ix = {:?}.", ix);
        match ix {
            EvmInstruction::EvmTransaction { evm_tx } => {
                // TODO: Handle gas price
                // TODO: Handle nonce
                // TODO: validate tx signature

                let before_gas = evm_executor.used_gas();
                let result = match evm_tx.action {
                    TransactionAction::Call(addr) => {
                        let caller = evm_tx
                            .caller()
                            .map_err(|_| InstructionError::InvalidArgument)?;
                        debug!(
                            "TransactionAction::Call caller  = {}, to = {}.",
                            caller, addr
                        );
                        evm_executor.transact_call(
                            caller,
                            addr,
                            evm_tx.value,
                            evm_tx.input.clone(),
                            evm_tx.gas_limit.as_usize(),
                        )
                    }
                    TransactionAction::Create => {
                        let caller = evm_tx
                            .caller()
                            .map_err(|_| InstructionError::InvalidArgument)?;
                        let addr = evm_tx.address();
                        debug!(
                            "TransactionAction::Create caller  = {}, to = {:?}.",
                            caller, addr
                        );
                        (
                            evm_executor.transact_create(
                                caller,
                                evm_tx.value,
                                evm_tx.input.clone(),
                                evm_tx.gas_limit.as_usize(),
                            ),
                            vec![],
                        )
                    }
                };

                let used_gas = evm_executor.used_gas() - before_gas;
                executor.register_tx_receipt(evm_state::TransactionReceipt::new(
                    evm_tx,
                    used_gas.into(),
                    result.clone(),
                ));
                // TODO: Map evm errors on solana.
                debug!("Exit status = {:?}", result);
            }
            EvmInstruction::CreateDepositAccount { pubkey } => {
                Self::process_initialize_deposit(&keyed_accounts, pubkey)?
            }
            EvmInstruction::SwapNativeToEther {
                lamports,
                ether_address,
            } => {
                let accounts_iter = &mut keyed_accounts.iter();
                let signer_account = next_account_info(accounts_iter)?;
                let authority_account = next_account_info(accounts_iter)?;
                let gweis = evm::lamports_to_gwei(lamports);
                debug!(
                    "Sending lamports to Gwei tokens from={},to={}",
                    authority_account.unsigned_key(),
                    ether_address
                );

                if keyed_accounts.is_empty() {
                    error!("Not enough accounts");
                    return Err(InstructionError::InvalidArgument);
                }

                if lamports == 0 {
                    return Ok(());
                }

                let mut deposit: Deposit =
                    limited_deserialize(&authority_account.account.borrow().data)
                        .unwrap_or_default();

                if signer_account.signer_key().is_none()
                    || deposit.get_owner()? != *signer_account.signer_key().unwrap()
                {
                    debug!("SwapNativeToEther: from must sign");
                    return Err(InstructionError::MissingRequiredSignature);
                }

                let mut real_lamports = authority_account.lamports()?;
                if deposit.locked_lamports >= real_lamports {
                    debug!(
                        "SwapNativeToEther: insufficient unlocked lamports ({}, locked {})",
                        authority_account.lamports()?,
                        deposit.locked_lamports
                    );
                    return Err(InstructionError::InsufficientFunds);
                }
                real_lamports -= deposit.locked_lamports;
                if lamports > real_lamports {
                    debug!(
                        "SwapNativeToEther: insufficient lamports ({}, need {})",
                        real_lamports, lamports
                    );
                    return Err(InstructionError::InsufficientFunds);
                }
                deposit.locked_lamports += lamports;
                evm_executor.deposit(ether_address, gweis);
                bincode::serialize_into(
                    &mut *authority_account.try_account_ref_mut()?.data,
                    &deposit,
                )
                .map_err(|_| InstructionError::InvalidArgument)?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use evm_state::transactions::{TransactionAction, TransactionSignature};
    use primitive_types::{H160, H256, U256};
    use solana_sdk::account::KeyedAccount;
    use solana_sdk::native_loader;
    use solana_sdk::program_utils::limited_deserialize;

    use std::cell::RefCell;
    use std::sync::RwLock;

    fn dummy_eth_tx() -> evm_state::transactions::Transaction {
        evm_state::transactions::Transaction {
            nonce: U256::zero(),
            gas_price: U256::zero(),
            gas_limit: U256::zero(),
            action: TransactionAction::Call(H160::zero()),
            value: U256::zero(),
            signature: TransactionSignature {
                v: 0,
                r: H256::zero(),
                s: H256::zero(),
            },
            input: vec![],
        }
    }

    #[test]
    fn serialize_deserialize_eth_ix() {
        let tx = dummy_eth_tx();
        let sol_ix = EvmInstruction::EvmTransaction { evm_tx: tx };
        let ser = bincode::serialize(&sol_ix).unwrap();
        assert_eq!(sol_ix, limited_deserialize(&ser).unwrap());
    }

    const SECRET_KEY_DUMMY: [u8; 32] = [1; 32];

    #[test]
    fn execute_tx() {
        let mut executor = evm_state::StaticExecutor::with_config(
            evm_state::EvmState::default(),
            evm_state::Config::istanbul(),
            10000000,
        );
        let mut executor = Some(&mut executor);
        let processor = EvmProcessor::default();
        // pub fn new(key: &'a Pubkey, is_signer: bool, account: &'a RefCell<Account>) -> Self {
        //     Self {
        //         is_signer,
        //         is_writable: true,
        //         key,
        //         account,
        //     }
        // }
        let evm_account = RefCell::new(native_loader::create_loadable_account("Evm Processor"));

        let evm_keyed_account = KeyedAccount::new(&crate::ID, false, &evm_account);
        let keyed_accounts = [evm_keyed_account];
        let secret_key = evm::SecretKey::from_slice(&SECRET_KEY_DUMMY).unwrap();
        let tx_create = evm::UnsignedTransaction {
            nonce: 0.into(),
            gas_price: 1.into(),
            gas_limit: 300000.into(),
            action: TransactionAction::Create,
            value: 0.into(),
            input: hex::decode(evm_state::HELLO_WORLD_CODE).unwrap().to_vec(),
        };
        let tx_create = tx_create.sign(&secret_key, None);

        assert!(processor
            .process_instruction(
                &crate::ID,
                &keyed_accounts,
                &bincode::serialize(&EvmInstruction::EvmTransaction {
                    evm_tx: tx_create.clone()
                })
                .unwrap(),
                executor.as_deref_mut()
            )
            .is_ok());
        println!("cx = {:?}", executor);
        // cx.evm_executor.borrow_mut().deconstruct();
        let tx_address = tx_create.address().unwrap();
        let tx_call = evm::UnsignedTransaction {
            nonce: 0.into(),
            gas_price: 1.into(),
            gas_limit: 300000.into(),
            action: TransactionAction::Call(tx_address),
            value: 0.into(),
            input: hex::decode(evm_state::HELLO_WORLD_ABI).unwrap().to_vec(),
        };

        let tx_call = tx_call.sign(&secret_key, None);
        assert!(processor
            .process_instruction(
                &crate::ID,
                &keyed_accounts,
                &bincode::serialize(&EvmInstruction::EvmTransaction { evm_tx: tx_call }).unwrap(),
                executor.as_deref_mut()
            )
            .is_ok());
        println!("cx = {:?}", executor);
    }

    #[test]
    fn execute_tx_with_state_apply() {
        use evm_state::Backend;
        let state = RwLock::new(evm_state::EvmState::default());
        let processor = EvmProcessor::default();
        let evm_account = RefCell::new(native_loader::create_loadable_account("Evm Processor"));

        let evm_keyed_account = KeyedAccount::new(&crate::ID, false, &evm_account);
        let keyed_accounts = [evm_keyed_account];

        let secret_key = evm::SecretKey::from_slice(&SECRET_KEY_DUMMY).unwrap();
        let tx_create = evm::UnsignedTransaction {
            nonce: 0.into(),
            gas_price: 1.into(),
            gas_limit: 300000.into(),
            action: TransactionAction::Create,
            value: 0.into(),
            input: hex::decode(evm_state::HELLO_WORLD_CODE).unwrap().to_vec(),
        };

        let tx_create = tx_create.sign(&secret_key, None);

        let caller_address = tx_create.caller().unwrap();
        let tx_address = tx_create.address().unwrap();

        assert_eq!(state.read().unwrap().basic(caller_address).nonce, 0.into());
        assert_eq!(state.read().unwrap().basic(tx_address).nonce, 0.into());
        {
            let mut locked = state.write().unwrap();
            let mut executor_orig = evm_state::StaticExecutor::with_config(
                locked.clone(),
                evm_state::Config::istanbul(),
                10000000,
            );
            let mut executor = Some(&mut executor_orig);
            assert!(processor
                .process_instruction(
                    &crate::ID,
                    &keyed_accounts,
                    &bincode::serialize(&EvmInstruction::EvmTransaction {
                        evm_tx: tx_create.clone()
                    })
                    .unwrap(),
                    executor.as_deref_mut()
                )
                .is_ok());
            println!("cx = {:?}", executor);

            let patch = executor_orig.deconstruct();

            locked.apply(patch);
        }

        // cx.evm_executor.borrow_mut().deconstruct();

        assert_eq!(state.read().unwrap().basic(caller_address).nonce, 1.into());
        assert_eq!(state.read().unwrap().basic(tx_address).nonce, 1.into());

        let tx_call = evm::UnsignedTransaction {
            nonce: 1.into(),
            gas_price: 1.into(),
            gas_limit: 300000.into(),
            action: TransactionAction::Call(tx_address),
            value: 0.into(),
            input: hex::decode(evm_state::HELLO_WORLD_ABI).unwrap().to_vec(),
        };

        let tx_call = tx_call.sign(&secret_key, None);
        {
            let mut locked = state.write().unwrap();
            let mut executor_orig = evm_state::StaticExecutor::with_config(
                locked.clone(),
                evm_state::Config::istanbul(),
                10000000,
            );
            let mut executor = Some(&mut executor_orig);

            assert!(processor
                .process_instruction(
                    &crate::ID,
                    &keyed_accounts,
                    &bincode::serialize(&EvmInstruction::EvmTransaction { evm_tx: tx_call })
                        .unwrap(),
                    executor.as_deref_mut()
                )
                .is_ok());
            println!("cx = {:?}", executor);

            let patch = executor_orig.deconstruct();

            locked.apply(patch);
        }

        // TODO: Assert that tx executed successfull.
        panic!();
        // assert!(process_instruction(&crate::ID, &[], tx_call, &mut cx).is_ok());
    }
}
