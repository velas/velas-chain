use super::account_structure::AccountStructure;
use super::instructions::{EvmBigTransaction, EvmInstruction};
use super::precompiles;
use super::scope::*;
use log::*;

use evm::{Executor, ExitReason};
use solana_sdk::instruction::InstructionError;
use solana_sdk::pubkey::Pubkey;
use solana_sdk::{keyed_account::KeyedAccount, program_utils::limited_deserialize};

use super::tx_chunks::TxChunks;

/// Return the next AccountInfo or a NotEnoughAccountKeys error
pub fn next_account_info<'a, 'b, I: Iterator<Item = &'a KeyedAccount<'b>>>(
    iter: &mut I,
) -> Result<I::Item, InstructionError> {
    iter.next().ok_or(InstructionError::NotEnoughAccountKeys)
}

#[derive(Default, Debug, Clone)]
pub struct EvmProcessor {}

impl EvmProcessor {
    pub fn process_instruction(
        &self,
        _program_id: &Pubkey,
        keyed_accounts: &[KeyedAccount],
        data: &[u8],
        executor: Option<&mut Executor>,
    ) -> Result<(), InstructionError> {
        let executor = executor.expect("Evm execution from crossprogram is not allowed.");

        let (evm_state_account, keyed_accounts) = Self::check_evm_account(keyed_accounts)?;

        let accounts = AccountStructure::new(evm_state_account, keyed_accounts);

        let ix = limited_deserialize(data)?;
        debug!("Run evm exec with ix = {:?}.", ix);
        match ix {
            EvmInstruction::EvmTransaction { evm_tx } => {
                // TODO: Handle gas price in EVM Bridge
                let result = executor
                    .transaction_execute(evm_tx, precompiles::entrypoint(accounts))
                    .map_err(|e| {
                        error!("Exec tx error: {:?}", e);
                        InstructionError::InvalidArgument
                    })?;
                debug!("Exit status = {:?}", result);
                if matches!(result.0, ExitReason::Fatal(_) | ExitReason::Error(_)) {
                    return Err(InstructionError::InvalidError);
                }
            }
            EvmInstruction::FreeOwnership {} => {
                let mut user = accounts
                    .user()
                    .ok_or_else(|| {
                        error!("Not enough accounts");
                        InstructionError::InvalidArgument
                    })?
                    .try_account_ref_mut()?;

                if user.owner != crate::ID {
                    return Err(InstructionError::InvalidError);
                }
                user.owner = solana_sdk::system_program::id();
            }
            EvmInstruction::SwapNativeToEther {
                lamports,
                ether_address,
            } => self.process_swap_to_native(executor, accounts, lamports, ether_address)?,
            EvmInstruction::EvmBigTransaction(big_tx) => {
                self.process_big_tx(executor, accounts, big_tx)?;
            }
        }
        Ok(())
    }

    fn process_swap_to_native(
        &self,
        executor: &mut Executor,
        accounts: AccountStructure,
        lamports: u64,
        evm_address: evm::Address,
    ) -> Result<(), InstructionError> {
        let gweis = evm::lamports_to_gwei(lamports);
        let user = accounts.user().ok_or_else(|| {
            error!("Not enough accounts");
            InstructionError::InvalidArgument
        })?;
        debug!(
            "Sending lamports to Gwei tokens from={},to={}",
            user.unsigned_key(),
            evm_address
        );

        if lamports == 0 {
            return Ok(());
        }

        if user.signer_key().is_none() {
            debug!("SwapNativeToEther: from must sign");
            return Err(InstructionError::MissingRequiredSignature);
        }

        let mut user_account = user.try_account_ref_mut()?;
        if lamports > user_account.lamports {
            debug!(
                "SwapNativeToEther: insufficient lamports ({}, need {})",
                user_account.lamports, lamports
            );
            return Err(InstructionError::InsufficientFunds);
        }

        user_account.lamports -= lamports;
        accounts.evm.try_account_ref_mut()?.lamports += lamports;
        executor.with_executor(|e| e.state_mut().deposit(evm_address, gweis));
        Ok(())
    }

    fn process_big_tx(
        &self,
        executor: &mut Executor,
        accounts: AccountStructure,
        big_tx: EvmBigTransaction,
    ) -> Result<(), InstructionError> {
        debug!("executing big_tx = {:?}", big_tx);

        let mut storage = accounts
            .user()
            .ok_or_else(|| {
                error!("Not enough accounts");
                InstructionError::InvalidArgument
            })?
            .try_account_ref_mut()?;

        // TODO: storage.owner == crate::ID;

        let mut tx_chunks = TxChunks::new(storage.data.as_mut_slice());

        match big_tx {
            EvmBigTransaction::EvmTransactionAllocate { size } => {
                tx_chunks.init(size as usize).map_err(|e| {
                    error!("Tx allocate error: {:?}", e);
                    InstructionError::InvalidArgument
                })?;

                Ok(())
            }

            EvmBigTransaction::EvmTransactionWrite { offset, data } => {
                debug!("Tx chunks: Write offset = {}, data = {:?}", offset, data);
                tx_chunks.push(offset as usize, data).map_err(|e| {
                    error!("Tx write error: {:?}", e);
                    InstructionError::InvalidArgument
                })?;

                Ok(())
            }

            EvmBigTransaction::EvmTransactionExecute {} => {
                debug!("Tx chunks crc = {:#x}", tx_chunks.crc());

                let bytes = tx_chunks.take();

                debug!("Trying to deserialize tx chunks byte = {:?}", bytes);
                let tx = bincode::deserialize(&bytes).map_err(|e| {
                    debug!("Tx chunks deserialize error: {:?}", e);
                    InstructionError::InvalidArgument
                })?;

                debug!("Executing EVM tx = {:?}", tx);
                let result = executor
                    .transaction_execute(tx, precompiles::entrypoint(accounts))
                    .map_err(|_| InstructionError::InvalidArgument)?;

                debug!("Execute tx exit status = {:?}", result);
                if matches!(result.0, ExitReason::Fatal(_) | ExitReason::Error(_)) {
                    Err(InstructionError::InvalidError)
                } else {
                    Ok(())
                }
            }
        }
    }

    /// Ensure that first account is program itself, and it's locked for writes.
    fn check_evm_account<'a, 'b>(
        keyed_accounts: &'a [KeyedAccount<'b>],
    ) -> Result<(&'a KeyedAccount<'b>, &'a [KeyedAccount<'b>]), InstructionError> {
        let first = keyed_accounts
            .first()
            .ok_or(InstructionError::NotEnoughAccountKeys)?;

        trace!("first = {:?}", first);
        trace!("all = {:?}", keyed_accounts);
        if first.unsigned_key() != &solana::evm_state::id() || !first.is_writable() {
            error!("First account is not evm, or not writable");
            return Err(InstructionError::MissingAccount);
        }

        let keyed_accounts = &keyed_accounts[1..];
        Ok((first, keyed_accounts))
    }
}

const SECRET_KEY_DUMMY: [u8; 32] = [1; 32];

#[doc(hidden)]
pub fn dummy_call() -> evm::Transaction {
    let secret_key = evm::SecretKey::from_slice(&SECRET_KEY_DUMMY).unwrap();
    let dummy_address = evm::addr_from_public_key(&evm::PublicKey::from_secret_key(
        &evm::SECP256K1,
        &secret_key,
    ));

    let tx_call = evm::UnsignedTransaction {
        nonce: 0.into(),
        gas_price: 1.into(),
        gas_limit: 300000.into(),
        action: evm::TransactionAction::Call(dummy_address),
        value: 0.into(),
        input: vec![],
    };
    tx_call.sign(&secret_key, None)
}

#[cfg(test)]
mod test {
    use super::*;
    use evm_state::{
        transactions::{TransactionAction, TransactionSignature},
        FromKey,
    };
    use evm_state::{ExitReason, ExitSucceed};
    use primitive_types::{H160, H256, U256};
    use solana_sdk::keyed_account::KeyedAccount;
    use solana_sdk::native_loader;
    use solana_sdk::program_utils::limited_deserialize;
    use solana_sdk::sysvar::rent::Rent;

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

    #[test]
    fn execute_tx() {
        let mut executor = evm_state::Executor::with_config(
            evm_state::EvmState::default(),
            evm_state::Config::istanbul(),
            10000000,
            0,
        );
        let mut executor = Some(&mut executor);
        let processor = EvmProcessor::default();
        let evm_account = RefCell::new(crate::create_state_account());
        let evm_keyed_account = KeyedAccount::new(&solana::evm_state::ID, false, &evm_account);
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
            nonce: 1.into(),
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
    fn tx_preserve_nonce() {
        let mut executor = evm_state::Executor::with_config(
            evm_state::EvmState::default(),
            evm_state::Config::istanbul(),
            10000000,
            0,
        );
        let mut executor = Some(&mut executor);
        let processor = EvmProcessor::default();
        let evm_account = RefCell::new(crate::create_state_account());
        let evm_keyed_account = KeyedAccount::new(&solana::evm_state::ID, false, &evm_account);
        let keyed_accounts = [evm_keyed_account];
        let secret_key = evm::SecretKey::from_slice(&SECRET_KEY_DUMMY).unwrap();
        let burn_addr = H160::zero();
        let tx_0 = evm::UnsignedTransaction {
            nonce: 0.into(),
            gas_price: 1.into(),
            gas_limit: 300000.into(),
            action: TransactionAction::Call(burn_addr),
            value: 0.into(),
            input: vec![],
        };
        let tx_0_sign = tx_0.clone().sign(&secret_key, None);
        let mut tx_1 = tx_0.clone();
        tx_1.nonce += 1.into();
        let tx_1_sign = tx_1.sign(&secret_key, None);

        let mut tx_0_shadow = tx_0.clone();
        tx_0_shadow.input = vec![1];

        let tx_0_shadow_sign = tx_0.sign(&secret_key, None);

        // Execute of second tx should fail.
        assert!(processor
            .process_instruction(
                &crate::ID,
                &keyed_accounts,
                &bincode::serialize(&EvmInstruction::EvmTransaction {
                    evm_tx: tx_1_sign.clone()
                })
                .unwrap(),
                executor.as_deref_mut()
            )
            .is_err());

        // First tx should execute successfully.
        assert!(processor
            .process_instruction(
                &crate::ID,
                &keyed_accounts,
                &bincode::serialize(&EvmInstruction::EvmTransaction {
                    evm_tx: tx_0_sign.clone()
                })
                .unwrap(),
                executor.as_deref_mut()
            )
            .is_ok());

        // Executing copy of first tx with different signature, should not pass too.
        assert!(processor
            .process_instruction(
                &crate::ID,
                &keyed_accounts,
                &bincode::serialize(&EvmInstruction::EvmTransaction {
                    evm_tx: tx_0_shadow_sign.clone()
                })
                .unwrap(),
                executor.as_deref_mut()
            )
            .is_err());

        // But executing of second tx now should succeed.
        assert!(processor
            .process_instruction(
                &crate::ID,
                &keyed_accounts,
                &bincode::serialize(&EvmInstruction::EvmTransaction {
                    evm_tx: tx_1_sign.clone()
                })
                .unwrap(),
                executor.as_deref_mut()
            )
            .is_ok());

        println!("cx = {:?}", executor);
    }

    #[test]
    fn execute_tx_with_state_apply() {
        let mut state = evm_state::EvmState::default();
        let processor = EvmProcessor::default();
        let evm_account = RefCell::new(crate::create_state_account());
        let evm_keyed_account = KeyedAccount::new(&solana::evm_state::ID, false, &evm_account);
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

        assert_eq!(
            state
                .get_account_state(caller_address)
                .map(|account| account.nonce),
            None,
        );
        assert_eq!(
            state
                .get_account_state(tx_address)
                .map(|account| account.nonce),
            None,
        );
        {
            let mut executor_orig = evm_state::Executor::with_config(
                state.clone(),
                evm_state::Config::istanbul(),
                10000000,
                0,
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

            state = executor_orig.deconstruct();
            state.apply();
        }

        assert_eq!(
            state
                .get_account_state(caller_address)
                .map(|account| account.nonce),
            Some(1.into())
        );
        assert_eq!(
            state
                .get_account_state(tx_address)
                .map(|account| account.nonce),
            Some(1.into())
        );

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
            let mut executor_orig = evm_state::Executor::with_config(
                state.clone(),
                evm_state::Config::istanbul(),
                10000000,
                0,
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

            state = executor_orig.deconstruct();
            state.apply();
        }

        let receipt = state.get_transaction_receipt(tx_hash).unwrap();

        assert!(matches!(
            receipt.status,
            ExitReason::Succeed(ExitSucceed::Returned)
        ));
        // TODO: Assert that tx executed with result.
    }

    #[test]
    fn execute_native_transfer_tx() {
        let mut executor_orig = evm_state::Executor::with_config(
            evm_state::EvmState::default(),
            evm_state::Config::istanbul(),
            10000000,
            0,
        );
        let mut executor = Some(&mut executor_orig);
        let processor = EvmProcessor::default();
        let user_account = RefCell::new(solana_sdk::account::Account {
            lamports: 1000,
            data: vec![],
            owner: crate::ID,
            executable: false,
            rent_epoch: 0,
        });
        let user_id = Pubkey::new_unique();
        let user_keyed_account = KeyedAccount::new(&user_id, true, &user_account);

        let evm_account = RefCell::new(crate::create_state_account());
        let evm_keyed_account = KeyedAccount::new(&solana::evm_state::ID, false, &evm_account);
        let keyed_accounts = [evm_keyed_account, user_keyed_account];
        let ether_dummy_address = H160::repeat_byte(0x11);

        let lamports_before = keyed_accounts[0].try_account_ref_mut().unwrap().lamports;

        assert!(processor
            .process_instruction(
                &crate::ID,
                &keyed_accounts,
                &bincode::serialize(&EvmInstruction::SwapNativeToEther {
                    lamports: 1000,
                    ether_address: ether_dummy_address
                })
                .unwrap(),
                executor.as_deref_mut()
            )
            .is_ok());
        println!("cx = {:?}", executor);

        assert_eq!(
            keyed_accounts[0].try_account_ref_mut().unwrap().lamports,
            lamports_before + 1000
        );
        assert_eq!(keyed_accounts[1].try_account_ref_mut().unwrap().lamports, 0);
        assert!(processor
            .process_instruction(
                &crate::ID,
                &keyed_accounts,
                &bincode::serialize(&EvmInstruction::FreeOwnership {}).unwrap(),
                executor.as_deref_mut()
            )
            .is_ok());
        println!("cx = {:?}", executor);
        assert_eq!(
            keyed_accounts[1].try_account_ref_mut().unwrap().owner,
            solana_sdk::system_program::id()
        );

        let state = executor_orig.deconstruct();
        assert_eq!(
            state
                .get_account_state(ether_dummy_address)
                .unwrap()
                .balance,
            crate::scope::evm::lamports_to_gwei(1000)
        )
    }

    #[test]
    fn execute_transfer_to_native_without_needed_account() {
        let mut executor_orig = evm_state::Executor::with_config(
            evm_state::EvmState::default(),
            evm_state::Config::istanbul(),
            10000000,
            0,
        );
        let mut executor = Some(&mut executor_orig);
        let processor = EvmProcessor::default();
        let first_user_account = RefCell::new(solana_sdk::account::Account {
            lamports: 1000,
            data: vec![],
            owner: crate::ID,
            executable: false,
            rent_epoch: 0,
        });
        let user_id = Pubkey::new_unique();
        let user_keyed_account = KeyedAccount::new(&user_id, true, &first_user_account);

        let evm_account = RefCell::new(crate::create_state_account());
        let evm_keyed_account = KeyedAccount::new(&solana::evm_state::ID, false, &evm_account);
        let keyed_accounts = [evm_keyed_account, user_keyed_account];
        let mut rand = evm_state::rand::thread_rng();
        let ether_sc = evm::SecretKey::new(&mut rand);
        let ether_dummy_address = ether_sc.to_address();

        let lamports_before = keyed_accounts[0].try_account_ref_mut().unwrap().lamports;

        let lamports_to_send = 1000;
        let lamports_to_send_back = 300;
        assert!(processor
            .process_instruction(
                &crate::ID,
                &keyed_accounts,
                &bincode::serialize(&EvmInstruction::SwapNativeToEther {
                    lamports: lamports_to_send,
                    ether_address: ether_dummy_address
                })
                .unwrap(),
                executor.as_deref_mut()
            )
            .is_ok());
        println!("cx = {:?}", executor);

        assert_eq!(
            keyed_accounts[0].try_account_ref_mut().unwrap().lamports,
            lamports_before + lamports_to_send
        );
        assert_eq!(keyed_accounts[1].try_account_ref_mut().unwrap().lamports, 0);

        let mut state = executor_orig.deconstruct();
        assert_eq!(
            state
                .get_account_state(ether_dummy_address)
                .unwrap()
                .balance,
            crate::scope::evm::lamports_to_gwei(lamports_to_send)
        );

        // Transfer back

        let second_user_account = RefCell::new(solana_sdk::account::Account {
            lamports: 0,
            data: vec![],
            owner: crate::ID,
            executable: false,
            rent_epoch: 0,
        });
        let user_id = Pubkey::new_unique();
        let user_keyed_account = KeyedAccount::new(&user_id, true, &second_user_account);

        let evm_keyed_account = KeyedAccount::new(&solana::evm_state::ID, false, &evm_account);
        let keyed_accounts = [evm_keyed_account, user_keyed_account];

        let fake_user_id = Pubkey::new_unique();

        let tx_call = evm::UnsignedTransaction {
            nonce: 1.into(),
            gas_price: 1.into(),
            gas_limit: 300000.into(),
            action: TransactionAction::Call(*precompiles::ETH_TO_SOL_ADDR),
            value: crate::scope::evm::lamports_to_gwei(lamports_to_send_back),
            input: precompiles::ETH_TO_SOL_CODE
                .abi
                .encode_input(&[ethabi::Token::FixedBytes(fake_user_id.to_bytes().to_vec())])
                .unwrap(),
        };

        let tx_call = tx_call.sign(&ether_sc, None);
        {
            let mut executor_orig = evm_state::Executor::with_config(
                state.clone(),
                evm_state::Config::istanbul(),
                10000000,
                0,
            );
            let mut executor = Some(&mut executor_orig);

            // Error transaction has no needed account.
            assert!(processor
                .process_instruction(
                    &crate::ID,
                    &keyed_accounts,
                    &bincode::serialize(&EvmInstruction::EvmTransaction { evm_tx: tx_call })
                        .unwrap(),
                    executor.as_deref_mut()
                )
                .is_err());
            println!("cx = {:?}", executor);

            executor_orig.deconstruct().apply();
        }

        // Nothing should change, because of error
        assert_eq!(
            keyed_accounts[0].try_account_ref_mut().unwrap().lamports,
            lamports_before + lamports_to_send
        );
        assert_eq!(first_user_account.borrow().lamports, 0);
        assert_eq!(second_user_account.borrow().lamports, 0);

        assert_eq!(
            state
                .get_account_state(ether_dummy_address)
                .unwrap()
                .balance,
            crate::scope::evm::lamports_to_gwei(lamports_to_send)
        );
    }

    #[test]
    fn execute_transfer_roundtrip() {
        let _ = simple_logger::SimpleLogger::new().init();

        let mut executor_orig = evm_state::Executor::with_config(
            evm_state::EvmState::default(),
            evm_state::Config::istanbul(),
            10000000,
            0,
        );
        let mut executor = Some(&mut executor_orig);
        let processor = EvmProcessor::default();
        let first_user_account = RefCell::new(solana_sdk::account::Account {
            lamports: 1000,
            data: vec![],
            owner: crate::ID,
            executable: false,
            rent_epoch: 0,
        });
        let user_id = Pubkey::new_unique();
        let user_keyed_account = KeyedAccount::new(&user_id, true, &first_user_account);

        let evm_account = RefCell::new(crate::create_state_account());
        let evm_keyed_account = KeyedAccount::new(&solana::evm_state::ID, false, &evm_account);
        let keyed_accounts = [evm_keyed_account, user_keyed_account];
        let mut rand = evm_state::rand::thread_rng();
        let ether_sc = evm::SecretKey::new(&mut rand);
        let ether_dummy_address = ether_sc.to_address();

        let lamports_before = keyed_accounts[0].try_account_ref_mut().unwrap().lamports;

        let lamports_to_send = 1000;
        let lamports_to_send_back = 300;

        processor
            .process_instruction(
                &crate::ID,
                &keyed_accounts,
                &bincode::serialize(&EvmInstruction::SwapNativeToEther {
                    lamports: lamports_to_send,
                    ether_address: ether_dummy_address,
                })
                .unwrap(),
                executor.as_deref_mut(),
            )
            .unwrap();

        println!("cx = {:?}", executor);

        assert_eq!(
            keyed_accounts[0].try_account_ref_mut().unwrap().lamports,
            lamports_before + lamports_to_send
        );
        assert_eq!(keyed_accounts[1].try_account_ref_mut().unwrap().lamports, 0);

        let mut state = executor_orig.deconstruct();
        // state.apply();
        assert_eq!(
            state
                .get_account_state(ether_dummy_address)
                .unwrap()
                .balance,
            crate::scope::evm::lamports_to_gwei(lamports_to_send)
        );

        // Transfer back

        let second_user_account = RefCell::new(solana_sdk::account::Account {
            lamports: 0,
            data: vec![],
            owner: crate::ID,
            executable: false,
            rent_epoch: 0,
        });
        let user_id = Pubkey::new_unique();
        let user_keyed_account = KeyedAccount::new(&user_id, true, &second_user_account);

        let evm_keyed_account = KeyedAccount::new(&solana::evm_state::ID, false, &evm_account);
        let keyed_accounts = [evm_keyed_account, user_keyed_account];

        let tx_call = evm::UnsignedTransaction {
            nonce: 0.into(),
            gas_price: 1.into(),
            gas_limit: 300000.into(),
            action: TransactionAction::Call(*precompiles::ETH_TO_SOL_ADDR),
            value: crate::scope::evm::lamports_to_gwei(lamports_to_send_back),
            input: precompiles::ETH_TO_SOL_CODE
                .abi
                .encode_input(&[ethabi::Token::FixedBytes(user_id.to_bytes().to_vec())])
                .unwrap(),
        };

        let tx_call = tx_call.sign(&ether_sc, None);
        {
            let mut executor_orig = evm_state::Executor::with_config(
                state.clone(),
                evm_state::Config::istanbul(),
                10000000,
                0,
            );
            let mut executor = Some(&mut executor_orig);

            processor
                .process_instruction(
                    &crate::ID,
                    &keyed_accounts,
                    &bincode::serialize(&EvmInstruction::EvmTransaction { evm_tx: tx_call })
                        .unwrap(),
                    executor.as_deref_mut(),
                )
                .unwrap();
            println!("cx = {:?}", executor);

            state = executor_orig.deconstruct();
            state.apply();
        }

        assert_eq!(
            keyed_accounts[0].try_account_ref_mut().unwrap().lamports,
            lamports_before + lamports_to_send - lamports_to_send_back
        );
        assert_eq!(first_user_account.borrow().lamports, 0);
        assert_eq!(second_user_account.borrow().lamports, lamports_to_send_back);

        assert_eq!(
            state
                .get_account_state(ether_dummy_address)
                .unwrap()
                .balance,
            crate::scope::evm::lamports_to_gwei(lamports_to_send - lamports_to_send_back)
        );
    }

    fn all_ixs() -> Vec<solana_sdk::instruction::Instruction> {
        let tx_call = dummy_call();

        let signer = solana::Address::new_unique();
        vec![
            crate::transfer_native_to_eth(signer, 1, tx_call.address().unwrap()),
            crate::free_ownership(signer),
            crate::send_raw_tx(signer, tx_call),
        ]
    }

    fn account_by_key(pubkey: solana::Address) -> solana_sdk::account::Account {
        match &pubkey {
            id if id == &crate::ID => native_loader::create_loadable_account("Evm Processor", 1),
            id if id == &solana_sdk::sysvar::rent::id() => solana_sdk::account::Account {
                lamports: 10,
                owner: native_loader::id(),
                data: bincode::serialize(&Rent::default()).unwrap(),
                executable: false,
                rent_epoch: 0,
            },
            _rest => solana_sdk::account::Account {
                lamports: 20000000,
                owner: crate::ID, // EVM should only operate with accounts that it owns.
                data: vec![0u8],
                executable: false,
                rent_epoch: 0,
            },
        }
    }

    #[test]
    fn each_solana_tx_should_contain_writeable_evm_state() {
        let _ = simple_logger::SimpleLogger::new().init();
        let mut executor = evm_state::Executor::with_config(
            evm_state::EvmState::default(),
            evm_state::Config::istanbul(),
            10000000,
            0,
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
            let keyed_accounts: Vec<_> = ix
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
            // First execution without evm state key, should fail.
            let err = processor
                .process_instruction(
                    &crate::ID,
                    &keyed_accounts[1..],
                    &bincode::serialize(&data).unwrap(),
                    executor.as_deref_mut(),
                )
                .unwrap_err();

            match err {
                InstructionError::NotEnoughAccountKeys | InstructionError::MissingAccount => {}
                rest => panic!("Unexpected result = {:?}", rest),
            }

            // Because first execution is fail, state didn't changes, and second execution should pass.
            processor
                .process_instruction(
                    &crate::ID,
                    &keyed_accounts,
                    &bincode::serialize(&data).unwrap(),
                    executor.as_deref_mut(),
                )
                .unwrap();
        }
    }

    #[test]
    fn big_tx_allocation_error() {
        let mut executor = evm_state::Executor::with_config(
            evm_state::EvmState::default(),
            evm_state::Config::istanbul(),
            10000000,
            0,
        );
        let mut executor = Some(&mut executor);
        let processor = EvmProcessor::default();
        let evm_account = RefCell::new(crate::create_state_account());
        let evm_keyed_account = KeyedAccount::new(&solana::evm_state::ID, false, &evm_account);

        let user_account = RefCell::new(solana_sdk::account::Account {
            lamports: 1000,
            data: vec![0; evm_state::MAX_TX_LEN as usize],
            owner: crate::ID,
            executable: false,
            rent_epoch: 0,
        });
        let user_id = Pubkey::new_unique();
        let user_keyed_account = KeyedAccount::new(&user_id, true, &user_account);

        let keyed_accounts = [evm_keyed_account, user_keyed_account];

        let big_transaction = EvmBigTransaction::EvmTransactionAllocate {
            size: evm_state::MAX_TX_LEN + 1,
        };
        assert!(processor
            .process_instruction(
                &crate::ID,
                &keyed_accounts,
                &bincode::serialize(&EvmInstruction::EvmBigTransaction(big_transaction)).unwrap(),
                executor.as_deref_mut()
            )
            .is_err());
        println!("cx = {:?}", executor);

        let big_transaction = EvmBigTransaction::EvmTransactionAllocate {
            size: evm_state::MAX_TX_LEN,
        };

        processor
            .process_instruction(
                &crate::ID,
                &keyed_accounts,
                &bincode::serialize(&EvmInstruction::EvmBigTransaction(big_transaction)).unwrap(),
                executor.as_deref_mut(),
            )
            .unwrap();
        println!("cx = {:?}", executor);
    }

    #[test]
    fn big_tx_write_out_of_bound() {
        let _ = simple_logger::SimpleLogger::new().init();

        let mut executor = evm_state::Executor::with_config(
            evm_state::EvmState::default(),
            evm_state::Config::istanbul(),
            10000000,
            0,
        );
        let mut executor = Some(&mut executor);
        let processor = EvmProcessor::default();
        let evm_account = RefCell::new(crate::create_state_account());
        let evm_keyed_account = KeyedAccount::new(&solana::evm_state::ID, false, &evm_account);

        let batch_size: u64 = 500;

        let user_account = RefCell::new(solana_sdk::account::Account {
            lamports: 1000,
            data: vec![0; batch_size as usize],
            owner: crate::ID,
            executable: false,
            rent_epoch: 0,
        });
        let user_id = Pubkey::new_unique();
        let user_keyed_account = KeyedAccount::new(&user_id, true, &user_account);

        let keyed_accounts = [evm_keyed_account, user_keyed_account];

        let big_transaction = EvmBigTransaction::EvmTransactionAllocate { size: batch_size };
        processor
            .process_instruction(
                &crate::ID,
                &keyed_accounts,
                &bincode::serialize(&EvmInstruction::EvmBigTransaction(big_transaction)).unwrap(),
                executor.as_deref_mut(),
            )
            .unwrap();
        println!("cx = {:?}", executor);

        // out of bound write
        let big_transaction = EvmBigTransaction::EvmTransactionWrite {
            offset: batch_size,
            data: vec![1],
        };

        assert!(processor
            .process_instruction(
                &crate::ID,
                &keyed_accounts,
                &bincode::serialize(&EvmInstruction::EvmBigTransaction(big_transaction)).unwrap(),
                executor.as_deref_mut()
            )
            .is_err());

        println!("cx = {:?}", executor);
        // out of bound write
        let big_transaction = EvmBigTransaction::EvmTransactionWrite {
            offset: 0,
            data: vec![1; batch_size as usize + 1],
        };

        assert!(processor
            .process_instruction(
                &crate::ID,
                &keyed_accounts,
                &bincode::serialize(&EvmInstruction::EvmBigTransaction(big_transaction)).unwrap(),
                executor.as_deref_mut()
            )
            .is_err());

        println!("cx = {:?}", executor);

        // Write in bounds
        let big_transaction = EvmBigTransaction::EvmTransactionWrite {
            offset: 0,
            data: vec![1; batch_size as usize],
        };

        processor
            .process_instruction(
                &crate::ID,
                &keyed_accounts,
                &bincode::serialize(&EvmInstruction::EvmBigTransaction(big_transaction)).unwrap(),
                executor.as_deref_mut(),
            )
            .unwrap();

        println!("cx = {:?}", executor);
        // Overlaped writes is allowed
        let big_transaction = EvmBigTransaction::EvmTransactionWrite {
            offset: batch_size - 1,
            data: vec![1],
        };

        processor
            .process_instruction(
                &crate::ID,
                &keyed_accounts,
                &bincode::serialize(&EvmInstruction::EvmBigTransaction(big_transaction)).unwrap(),
                executor.as_deref_mut(),
            )
            .unwrap();

        println!("cx = {:?}", executor);
    }

    #[test]
    fn big_tx_write_without_alloc() {
        let mut executor = evm_state::Executor::with_config(
            evm_state::EvmState::default(),
            evm_state::Config::istanbul(),
            10000000,
            0,
        );
        let mut executor = Some(&mut executor);
        let processor = EvmProcessor::default();
        let evm_account = RefCell::new(crate::create_state_account());
        let evm_keyed_account = KeyedAccount::new(&solana::evm_state::ID, false, &evm_account);

        let user_account = RefCell::new(solana_sdk::account::Account {
            lamports: 1000,
            data: vec![],
            owner: crate::ID,
            executable: false,
            rent_epoch: 0,
        });
        let user_id = Pubkey::new_unique();
        let user_keyed_account = KeyedAccount::new(&user_id, true, &user_account);

        let keyed_accounts = [evm_keyed_account, user_keyed_account];

        let big_transaction = EvmBigTransaction::EvmTransactionWrite {
            offset: 0,
            data: vec![1],
        };

        assert!(processor
            .process_instruction(
                &crate::ID,
                &keyed_accounts,
                &bincode::serialize(&EvmInstruction::EvmBigTransaction(big_transaction)).unwrap(),
                executor.as_deref_mut()
            )
            .is_err());
        println!("cx = {:?}", executor);
    }

    #[test]
    fn check_tx_mtu_is_in_solanas_limit() {
        use solana_sdk::hash::hash;
        use solana_sdk::message::Message;
        use solana_sdk::signature::{Keypair, Signer};
        use solana_sdk::transaction::Transaction;

        let storage = Keypair::new();
        let ix = crate::big_tx_write(&storage.pubkey(), 0, vec![1; evm::TX_MTU]);
        let tx_before = Transaction::new(&[&storage], Message::new(&[ix], None), hash(&[1]));
        let tx = bincode::serialize(&tx_before).unwrap();
        let tx: Transaction = limited_deserialize(&tx).unwrap();
        assert_eq!(tx_before, tx);
    }
}
