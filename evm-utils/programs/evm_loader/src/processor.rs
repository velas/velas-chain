use super::instructions::{Deposit, EvmInstruction};
use super::scope::*;
use log::*;

use evm::Executor;
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
        executor: Option<&mut Executor>,
    ) -> Result<(), InstructionError> {
        let executor = executor.expect("Evm execution from crossprogram is not allowed.");

        let keyed_accounts = check_evm_account(program_id, keyed_accounts)?;

        let ix = limited_deserialize(data)?;
        debug!("Run evm exec with ix = {:?}.", ix);
        match ix {
            EvmInstruction::EvmTransaction { evm_tx } => {
                // TODO: Handle gas price
                // TODO: Handle nonce
                // TODO: validate tx signature
                let result = executor
                    .transaction_execute(evm_tx)
                    .map_err(|_| InstructionError::InvalidArgument)?;
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
                executor.with_executor(|e| e.deposit(ether_address, gweis));
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
    use assert_matches::assert_matches;
    use evm_state::transactions::{TransactionAction, TransactionSignature};
    use evm_state::{ExitReason, ExitSucceed};
    use primitive_types::{H160, H256, U256};
    use solana_sdk::account::{Account, KeyedAccount};
    use solana_sdk::native_loader;
    use solana_sdk::program_utils::limited_deserialize;

    use std::sync::RwLock;
    use std::{cell::RefCell, collections::BTreeMap};

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
        let mut executor = evm_state::Executor::with_config(
            evm_state::EvmState::default(),
            evm_state::Config::istanbul(),
            10000000,
        );
        let mut executor = Some(&mut executor);
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
        let tx_address = tx_create.address().unwrap();
        let tx_call = evm::UnsignedTransaction {
            nonce: 0.into(),
            gas_price: 1.into(),
            gas_limit: 300000.into(),
            action: TransactionAction::Call(tx_address),
            value: 0.into(),
            input: hex::decode(evm_state::HELLO_WORLD_ABI).unwrap().to_vec(),
        };

        let tx_hash = tx_call.signing_hash(None);
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
        assert!(executor
            .as_deref_mut()
            .unwrap()
            .get_tx_receipt_by_hash(tx_hash)
            .is_some())
    }

    #[test]
    fn execute_tx_with_state_apply() {
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
            let mut executor_orig = evm_state::Executor::with_config(
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

            locked.swap_commit(patch);
        }

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

        let tx_hash = tx_call.signing_hash(None);
        let tx_call = tx_call.sign(&secret_key, None);
        {
            let mut locked = state.write().unwrap();
            let mut executor_orig = evm_state::Executor::with_config(
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

            locked.swap_commit(patch);
        }

        let receipt = state
            .read()
            .unwrap()
            .get_tx_receipt_by_hash(tx_hash)
            .unwrap()
            .clone();
        assert_matches!(receipt.status, ExitReason::Succeed(ExitSucceed::Returned));
        // TODO: Assert that tx executed with result.
    }

    fn all_ixs() -> Vec<solana_sdk::instruction::Instruction> {
        let secret_key = evm::SecretKey::from_slice(&SECRET_KEY_DUMMY).unwrap();
        let dummy_address = evm::addr_from_public_key(&evm::PublicKey::from_secret_key(
            &evm::SECP256K1,
            &secret_key,
        ));

        let tx_call = evm::UnsignedTransaction {
            nonce: 1.into(),
            gas_price: 1.into(),
            gas_limit: 300000.into(),
            action: TransactionAction::Call(dummy_address),
            value: 0.into(),
            input: hex::decode(evm_state::HELLO_WORLD_ABI).unwrap().to_vec(),
        };
        let tx_call = tx_call.sign(&secret_key, None);

        let signer = solana::Address::new_rand();
        let authority = solana::Address::new_rand();
        vec![
            crate::create_deposit_account(&signer, &authority),
            crate::transfer_native_to_eth(&signer, &authority, 1, dummy_address),
            crate::send_raw_tx(&signer, tx_call),
        ]
    }

    fn account_by_key(pubkey: solana::Address) -> solana_sdk::account::Account {
        match &pubkey {
            id if id == &crate::ID => native_loader::create_loadable_account("Evm Processor"),
            id if id == &solana_sdk::sysvar::rent::id() => solana_sdk::account::Account {
                lamports: 10,
                owner: native_loader::id(),
                data: bincode::serialize(&Rent::default()).unwrap(),
                executable: false,
                rent_epoch: 0,
            },
            _rest => solana_sdk::account::Account {
                lamports: 20000000,
                owner: native_loader::id(),
                data: vec![0u8; Deposit::LEN],
                executable: false,
                rent_epoch: 0,
            },
        }
    }

    #[test]
    fn each_solana_tx_should_contain_writeable_evm_state() {
        simple_logger::SimpleLogger::new().init().unwrap();
        let mut executor = evm_state::Executor::with_config(
            evm_state::EvmState::default(),
            evm_state::Config::istanbul(),
            10000000,
        );
        let mut executor = Some(&mut executor);
        let processor = EvmProcessor::default();

        let mut dummy_accounts = BTreeMap::new();

        for ix in all_ixs() {
            // insert new accounts, if some missing
            for acc in &ix.accounts {
                dummy_accounts
                    .entry(acc.pubkey)
                    .or_insert_with(|| RefCell::new(account_by_key(acc.pubkey)));
            }

            let data: EvmInstruction = limited_deserialize(&ix.data).unwrap();
            println!("Executing = {:?}", data);
            let mut keyed_accounts: Vec<_> = ix
                .accounts
                .iter()
                .map(|k| {
                    if k.is_writable {
                        KeyedAccount::new(&k.pubkey, k.is_signer, &dummy_accounts[&k.pubkey])
                    } else {
                        KeyedAccount::new_readonly(
                            &k.pubkey,
                            k.is_signer,
                            &dummy_accounts[&k.pubkey],
                        )
                    }
                })
                .collect();

            println!("Keyed accounts = {:?}", keyed_accounts);
            processor
                .process_instruction(
                    &crate::ID,
                    &keyed_accounts,
                    &bincode::serialize(&data).unwrap(),
                    executor.as_deref_mut(),
                )
                .unwrap();
            keyed_accounts.remove(0);

            let err = processor
                .process_instruction(
                    &crate::ID,
                    &keyed_accounts,
                    &bincode::serialize(&data).unwrap(),
                    executor.as_deref_mut(),
                )
                .unwrap_err();
            match err {
                InstructionError::NotEnoughAccountKeys | InstructionError::MissingAccount => {}
                rest => panic!("Unexpected result = {:?}", rest),
            }
        }
    }
}
