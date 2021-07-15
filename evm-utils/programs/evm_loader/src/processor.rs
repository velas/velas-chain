use std::ops::DerefMut;

use super::account_structure::AccountStructure;
use super::instructions::{EvmBigTransaction, EvmInstruction};
use super::precompiles;
use super::scope::*;
use log::*;

use evm::{gweis_to_lamports, Executor, ExitReason};
use solana_sdk::ic_msg;
use solana_sdk::instruction::InstructionError;
use solana_sdk::process_instruction::InvokeContext;
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
        invoke_context: &mut dyn InvokeContext,
        cross_execution: bool,
    ) -> Result<(), InstructionError> {
        let (evm_state_account, keyed_accounts) = Self::check_evm_account(keyed_accounts)?;

        let cross_execution_enabled = invoke_context
            .is_feature_active(&solana_sdk::feature_set::velas_evm_cross_execution::id());
        if cross_execution && !cross_execution_enabled {
            ic_msg!(invoke_context, "Cross-Program evm execution not enabled.");
            return Err(InstructionError::InvalidError);
        }

        let evm_executor = if let Some(evm_executor) = invoke_context.get_evm_executor() {
            evm_executor
        } else {
            ic_msg!(
                invoke_context,
                "Invoke context didn't provide evm executor."
            );
            return Err(InstructionError::InvalidError);
        };
        // bind variable to increase lifetime of temporary RefCell borrow.
        let mut evm_executor_borrow;
        // evm executor cannot be borrowed, because it not exist in invoke context, or borrowing failed.
        let executor = if let Some(evm_executor) = evm_executor.try_borrow_mut().ok() {
            evm_executor_borrow = evm_executor;
            evm_executor_borrow.deref_mut()
        } else {
            ic_msg!(
                invoke_context,
                "Recursive cross-program evm execution not enabled."
            );
            return Err(InstructionError::InvalidError);
        };

        let accounts = AccountStructure::new(evm_state_account, keyed_accounts);

        let ix = limited_deserialize(data)?;
        trace!("Run evm exec with ix = {:?}.", ix);
        match ix {
            EvmInstruction::EvmTransaction { evm_tx } => {
                self.process_raw_tx(executor, invoke_context, accounts, evm_tx)
            }
            EvmInstruction::EvmAuthorizedTransaction { from, unsigned_tx } => {
                self.process_authorized_tx(executor, invoke_context, accounts, from, unsigned_tx)
            }
            EvmInstruction::FreeOwnership {} => {
                self.process_free_ownership(executor, invoke_context, accounts)
            }
            EvmInstruction::SwapNativeToEther {
                lamports,
                evm_address,
            } => {
                self.process_swap_to_evm(executor, invoke_context, accounts, lamports, evm_address)
            }
            EvmInstruction::EvmBigTransaction(big_tx) => {
                self.process_big_tx(executor, invoke_context, accounts, big_tx)
            }
        }
    }

    fn process_raw_tx(
        &self,
        executor: &mut Executor,
        invoke_context: &dyn InvokeContext,
        accounts: AccountStructure,
        evm_tx: evm::Transaction,
    ) -> Result<(), InstructionError> {
        // TODO: Handle gas price in EVM Bridge

        ic_msg!(
            invoke_context,
            "EvmTransaction: Executing transaction: gas_limit:{}, gas_price:{}, value:{}, action:{:?},",
            evm_tx.gas_limit,
            evm_tx.gas_price,
            evm_tx.value,
            evm_tx.action
        );
        let tx_gas_price = evm_tx.gas_price;
        let result = executor
            .transaction_execute(
                evm_tx,
                precompiles::entrypoint(accounts, executor.support_precompile()),
            )
            .map_err(|e| {
                ic_msg!(
                    invoke_context,
                    "EvmTransaction: transaction execution error: {}",
                    e
                );
                InstructionError::InvalidArgument
            })?;

        ic_msg!(
            invoke_context,
            "EvmTransaction: Executed transaction result: {:?}",
            result
        );
        if matches!(
            result.exit_reason,
            ExitReason::Fatal(_) | ExitReason::Error(_)
        ) {
            return Err(InstructionError::InvalidError);
        }
        let fee = tx_gas_price * result.used_gas;
        if let Some(payer) = accounts.users.first() {
            let (fee, _) = gweis_to_lamports(fee);
            ic_msg!(
                invoke_context,
                "EvmTransaction: Refunding transaction fee to transaction sender fee:{:?}, sender:{}",
                fee,
                payer.unsigned_key()
            );
            accounts.evm.account.borrow_mut().lamports -= fee;
            payer.account.borrow_mut().lamports += fee;
        } else {
            ic_msg!(
                invoke_context,
                "EvmTransaction: Sender didnt give his account, ignoring fee refund.",
            );
        }
        Ok(())
    }

    fn process_authorized_tx(
        &self,
        executor: &mut Executor,
        invoke_context: &dyn InvokeContext,
        accounts: AccountStructure,
        from: evm::Address,
        unsigned_tx: evm::UnsignedTransaction,
    ) -> Result<(), InstructionError> {
        // TODO: Check that it is from program?
        // TODO: Gas limit?
        let program_account = accounts.first().ok_or_else(|| {
            ic_msg!(
                invoke_context,
                "EvmAuthorizedTransaction: Not enough accounts, expected signer address as second account."
            );
            InstructionError::NotEnoughAccountKeys
        })?;
        let key = if let Some(key) = program_account.signer_key() {
            key
        } else {
            ic_msg!(
                invoke_context,
                "EvmAuthorizedTransaction: Second account is not a signer, cannot execute transaction."
            );
            return Err(InstructionError::MissingRequiredSignature);
        };
        let from_expected = crate::evm_address_for_program(*key);

        if from_expected != from {
            ic_msg!(
                invoke_context,
                "EvmAuthorizedTransaction: From is not calculated with evm_address_for_program."
            );
            return Err(InstructionError::InvalidArgument);
        }

        ic_msg!(
            invoke_context,
            "EvmAuthorizedTransaction: Executing authorized transaction: gas_limit:{}, gas_price:{}, value:{}, action:{:?},",
            unsigned_tx.gas_limit,
            unsigned_tx.gas_price,
            unsigned_tx.value,
            unsigned_tx.action
        );

        let tx_gas_price = unsigned_tx.gas_price;
        let result = executor
            .transaction_execute_unsinged(
                from,
                unsigned_tx,
                precompiles::entrypoint(accounts, executor.support_precompile()),
            )
            .map_err(|e| {
                ic_msg!(
                    invoke_context,
                    "EvmAuthorizedTransaction: transaction execution error: {}",
                    e
                );
                InstructionError::InvalidArgument
            })?;
        ic_msg!(
            invoke_context,
            "EvmAuthorizedTransaction: Executed transaction result: {:?}",
            result
        );
        if matches!(
            result.exit_reason,
            ExitReason::Fatal(_) | ExitReason::Error(_)
        ) {
            return Err(InstructionError::InvalidError);
        }
        let fee = tx_gas_price * result.used_gas;
        let payer = accounts
            .first()
            .expect("Payer is program account, and was checked before");
        let (fee, _) = gweis_to_lamports(fee);
        ic_msg!(
            invoke_context,
            "EvmAuthorizedTransaction: Refunding transaction fee to transaction sender fee:{:?}, sender:{}",
            fee,
            payer.unsigned_key()
        );
        accounts.evm.account.borrow_mut().lamports -= fee;
        payer.account.borrow_mut().lamports += fee;

        Ok(())
    }

    fn process_free_ownership(
        &self,
        _executor: &mut Executor,
        invoke_context: &dyn InvokeContext,
        accounts: AccountStructure,
    ) -> Result<(), InstructionError> {
        let user = accounts.first().ok_or_else(|| {
            ic_msg!(
                invoke_context,
                "FreeOwnership: expected account as argument."
            );
            InstructionError::NotEnoughAccountKeys
        })?;
        let user_pk = user.unsigned_key();
        let mut user = user.try_account_ref_mut()?;

        if user.owner != crate::ID || *user_pk == solana::evm_state::ID {
            ic_msg!(
                invoke_context,
                "FreeOwnership: Incorrect account provided, maybe this account is not owned by evm."
            );
            return Err(InstructionError::InvalidError);
        }
        user.owner = solana_sdk::system_program::id();
        Ok(())
    }

    fn process_swap_to_evm(
        &self,
        executor: &mut Executor,
        invoke_context: &dyn InvokeContext,
        accounts: AccountStructure,
        lamports: u64,
        evm_address: evm::Address,
    ) -> Result<(), InstructionError> {
        let register_swap_tx_in_evm = invoke_context
            .is_feature_active(&solana_sdk::feature_set::velas_native_swap_in_evm_history::id());
        let gweis = evm::lamports_to_gwei(lamports);
        let user = accounts.first().ok_or_else(|| {
            ic_msg!(
                invoke_context,
                "SwapNativeToEther: No sender account found in swap to evm."
            );
            InstructionError::NotEnoughAccountKeys
        })?;

        ic_msg!(
            invoke_context,
            "SwapNativeToEther: Sending tokens from native to evm chain from={},to={}",
            user.unsigned_key(),
            evm_address
        );

        if lamports == 0 {
            return Ok(());
        }

        if user.signer_key().is_none() {
            ic_msg!(invoke_context, "SwapNativeToEther: from must sign");
            return Err(InstructionError::MissingRequiredSignature);
        }

        let mut user_account = user.try_account_ref_mut()?;
        if lamports > user_account.lamports {
            ic_msg!(
                invoke_context,
                "SwapNativeToEther: insufficient lamports ({}, need {})",
                user_account.lamports,
                lamports
            );
            return Err(InstructionError::InsufficientFunds);
        }

        user_account.lamports -= lamports;
        accounts.evm.try_account_ref_mut()?.lamports += lamports;
        executor.deposit(evm_address, gweis);
        Ok(())
    }

    fn process_big_tx(
        &self,
        executor: &mut Executor,
        invoke_context: &dyn InvokeContext,
        accounts: AccountStructure,
        big_tx: EvmBigTransaction,
    ) -> Result<(), InstructionError> {
        debug!("executing big_tx = {:?}", big_tx);

        let storage = accounts.first().ok_or_else(|| {
            ic_msg!(
                invoke_context,
                "EvmBigTransaction: No storage account found."
            );
            InstructionError::InvalidArgument
        })?;

        if storage.signer_key().is_none() {
            ic_msg!(invoke_context, "EvmBigTransaction: from must sign");
            return Err(InstructionError::MissingRequiredSignature);
        }
        let mut storage = storage.try_account_ref_mut()?;

        let mut tx_chunks = TxChunks::new(storage.data.as_mut_slice());

        match big_tx {
            EvmBigTransaction::EvmTransactionAllocate { size } => {
                tx_chunks.init(size as usize).map_err(|e| {
                    ic_msg!(
                        invoke_context,
                        "EvmTransactionAllocate: allocate error: {:?}",
                        e
                    );
                    InstructionError::InvalidArgument
                })?;

                Ok(())
            }

            EvmBigTransaction::EvmTransactionWrite { offset, data } => {
                ic_msg!(
                    invoke_context,
                    "EvmTransactionWrite: Writing at offset = {}, data = {:?}",
                    offset,
                    data
                );
                tx_chunks.push(offset as usize, data).map_err(|e| {
                    ic_msg!(
                        invoke_context,
                        "EvmTransactionWrite: Tx write error: {:?}",
                        e
                    );
                    InstructionError::InvalidArgument
                })?;

                Ok(())
            }

            EvmBigTransaction::EvmTransactionExecute {} => {
                debug!("Tx chunks crc = {:#x}", tx_chunks.crc());

                let bytes = tx_chunks.take();

                debug!("Trying to deserialize tx chunks byte = {:?}", bytes);
                let tx: evm::Transaction = bincode::deserialize(&bytes).map_err(|e| {
                    ic_msg!(
                        invoke_context,
                        "BigTransaction::EvmTransactionExecute: Tx chunks deserialize error: {:?}",
                        e
                    );
                    InstructionError::InvalidArgument
                })?;

                debug!("Executing EVM tx = {:?}", tx);
                ic_msg!(
                    invoke_context,
                    "BigTransaction::EvmTransactionExecute: Executing transaction: gas_limit:{}, gas_price:{}, value:{}, action:{:?},",
                    tx.gas_limit,
                    tx.gas_price,
                    tx.value,
                    tx.action
                );
                let tx_gas_price = tx.gas_price;
                let result = executor
                    .transaction_execute(tx, precompiles::entrypoint(accounts, executor.support_precompile()))
                    .map_err(|e| {
                        ic_msg!(
                            invoke_context,
                            "BigTransaction::EvmTransactionExecute: transaction execution error: {}",
                            e
                        );
                        InstructionError::InvalidArgument
                    })?;

                ic_msg!(
                    invoke_context,
                    "BigTransaction::EvmTransactionExecute: Execute tx exit status = {:?}",
                    result
                );
                if matches!(
                    result.exit_reason,
                    ExitReason::Fatal(_) | ExitReason::Error(_)
                ) {
                    return Err(InstructionError::InvalidError);
                }
                let fee = tx_gas_price * result.used_gas;
                if let Some(payer) = accounts.users.get(1) {
                    let (fee, _) = gweis_to_lamports(fee);
                    ic_msg!(
                        invoke_context,
                        "BigTransaction::EvmTransactionExecute: Refunding transaction fee to transaction sender fee:{:?}, sender:{}",
                        fee,
                        payer.unsigned_key()
                    );
                    accounts.evm.account.borrow_mut().lamports -= fee;
                    payer.account.borrow_mut().lamports += fee;
                } else {
                    ic_msg!(
                        invoke_context,
                        "BigTransaction::EvmTransactionExecute: Sender didnt give his account, ignoring fee refund.",
                    );
                }
                Ok(())
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
            debug!("First account is not evm, or not writable");
            return Err(InstructionError::MissingAccount);
        }

        let keyed_accounts = &keyed_accounts[1..];
        Ok((first, keyed_accounts))
    }
}

const SECRET_KEY_DUMMY: [u8; 32] = [1; 32];

const TEST_CHAIN_ID: u64 = 0xdead;
#[doc(hidden)]
pub fn dummy_call(nonce: usize) -> (evm::Transaction, evm::UnsignedTransaction) {
    let secret_key = evm::SecretKey::from_slice(&SECRET_KEY_DUMMY).unwrap();
    let dummy_address = evm::addr_from_public_key(&evm::PublicKey::from_secret_key(
        &evm::SECP256K1,
        &secret_key,
    ));

    let tx_call = evm::UnsignedTransaction {
        nonce: nonce.into(),
        gas_price: 1.into(),
        gas_limit: 300000.into(),
        action: evm::TransactionAction::Call(dummy_address),
        value: 0.into(),
        input: vec![],
    };

    (
        tx_call.clone().sign(&secret_key, Some(TEST_CHAIN_ID)),
        tx_call,
    )
}

#[cfg(test)]
mod test {
    use super::*;
    use evm_state::{
        transactions::{TransactionAction, TransactionSignature},
        FromKey,
    };
    use evm_state::{AccountProvider, ExitReason, ExitSucceed};
    use primitive_types::{H160, H256, U256};
    use solana_sdk::keyed_account::KeyedAccount;
    use solana_sdk::native_loader;
    use solana_sdk::process_instruction::MockInvokeContext;
    use solana_sdk::program_utils::limited_deserialize;
    use solana_sdk::sysvar::rent::Rent;

    use super::TEST_CHAIN_ID as CHAIN_ID;
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
        let _logger = simple_logger::SimpleLogger::new().init();
        let mut executor = evm_state::Executor::testing();
        let processor = EvmProcessor::default();
        let evm_account = RefCell::new(crate::create_state_account(0));
        let evm_keyed_account = KeyedAccount::new(&solana::evm_state::ID, false, &evm_account);
        let keyed_accounts = [evm_keyed_account];
        let secret_key = evm::SecretKey::from_slice(&SECRET_KEY_DUMMY).unwrap();

        let address = secret_key.to_address();
        executor.deposit(address, U256::from(2) * 300000);
        let tx_create = evm::UnsignedTransaction {
            nonce: 0.into(),
            gas_price: 1.into(),
            gas_limit: 300000.into(),
            action: TransactionAction::Create,
            value: 0.into(),
            input: hex::decode(evm_state::HELLO_WORLD_CODE).unwrap().to_vec(),
        };
        let tx_create = tx_create.sign(&secret_key, Some(CHAIN_ID));

        let mut invoke_context = MockInvokeContext::with_evm(executor);
        assert!(processor
            .process_instruction(
                &crate::ID,
                &keyed_accounts,
                &bincode::serialize(&EvmInstruction::EvmTransaction {
                    evm_tx: tx_create.clone()
                })
                .unwrap(),
                &mut invoke_context,
                false,
            )
            .is_ok());
        let executor = invoke_context.deconstruct().unwrap();
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

        let tx_call = tx_call.sign(&secret_key, Some(CHAIN_ID));
        let tx_hash = tx_call.tx_id_hash();

        let mut invoke_context = MockInvokeContext::with_evm(executor);
        assert!(processor
            .process_instruction(
                &crate::ID,
                &keyed_accounts,
                &bincode::serialize(&EvmInstruction::EvmTransaction { evm_tx: tx_call }).unwrap(),
                &mut invoke_context,
                false,
            )
            .is_ok());

        let mut executor = invoke_context.deconstruct().unwrap();
        println!("cx = {:?}", executor);
        assert!(executor.get_tx_receipt_by_hash(tx_hash).is_some())
    }

    #[test]
    fn deploy_tx_refund_fee() {
        let _logger = simple_logger::SimpleLogger::new().init();
        let mut executor = evm_state::Executor::testing();
        let processor = EvmProcessor::default();
        let user_id = Pubkey::new_unique();
        let first_user_account = RefCell::new(solana_sdk::account::Account {
            lamports: 0,
            data: vec![],
            owner: crate::ID,
            executable: false,
            rent_epoch: 0,
        });
        let user_keyed_account = KeyedAccount::new(&user_id, true, &first_user_account);

        let init_evm_balance = 1000000;
        let evm_account = RefCell::new(crate::create_state_account(init_evm_balance));
        let evm_keyed_account = KeyedAccount::new(&solana::evm_state::ID, false, &evm_account);
        let keyed_accounts = [evm_keyed_account, user_keyed_account];
        let secret_key = evm::SecretKey::from_slice(&SECRET_KEY_DUMMY).unwrap();

        let address = secret_key.to_address();
        executor.deposit(
            address,
            U256::from(crate::evm::LAMPORTS_TO_GWEI_PRICE) * 300000,
        );
        let tx_create = evm::UnsignedTransaction {
            nonce: 0.into(),
            gas_price: crate::evm::LAMPORTS_TO_GWEI_PRICE.into(),
            gas_limit: 300000.into(),
            action: TransactionAction::Create,
            value: 0.into(),
            input: hex::decode(evm_state::HELLO_WORLD_CODE).unwrap().to_vec(),
        };
        let tx_create = tx_create.sign(&secret_key, Some(CHAIN_ID));
        let mut mock = MockInvokeContext::with_evm(executor);
        assert!(processor
            .process_instruction(
                &crate::ID,
                &keyed_accounts,
                &bincode::serialize(&EvmInstruction::EvmTransaction { evm_tx: tx_create }).unwrap(),
                &mut mock,
                false,
            )
            .is_ok());
        println!("logger = {:?}", mock.logger);
        let executor = mock.deconstruct().unwrap();
        println!("cx = {:?}", executor);
        let used_gas_for_hello_world_deploy = 114985;
        let fee = used_gas_for_hello_world_deploy; // price is 1lamport
        assert_eq!(first_user_account.borrow().lamports, fee);
        assert_eq!(
            evm_account.borrow().lamports,
            init_evm_balance + 1 // evm balance is always has 1 lamports reserve, because it is system account
                             - fee
        );
    }

    #[test]
    fn tx_preserve_nonce() {
        let mut executor = evm_state::Executor::testing();
        let processor = EvmProcessor::default();
        let evm_account = RefCell::new(crate::create_state_account(0));
        let evm_keyed_account = KeyedAccount::new(&solana::evm_state::ID, false, &evm_account);
        let keyed_accounts = [evm_keyed_account];
        let secret_key = evm::SecretKey::from_slice(&SECRET_KEY_DUMMY).unwrap();
        let address = secret_key.to_address();
        executor.deposit(address, U256::from(2) * 300000);
        let burn_addr = H160::zero();
        let tx_0 = evm::UnsignedTransaction {
            nonce: 0.into(),
            gas_price: 1.into(),
            gas_limit: 300000.into(),
            action: TransactionAction::Call(burn_addr),
            value: 0.into(),
            input: vec![],
        };
        let tx_0_sign = tx_0.clone().sign(&secret_key, Some(CHAIN_ID));
        let mut tx_1 = tx_0.clone();
        tx_1.nonce += 1.into();
        let tx_1_sign = tx_1.sign(&secret_key, Some(CHAIN_ID));

        let mut tx_0_shadow = tx_0.clone();
        tx_0_shadow.input = vec![1];

        let tx_0_shadow_sign = tx_0.sign(&secret_key, Some(CHAIN_ID));

        let mut invoke_context = MockInvokeContext::with_evm(executor);
        // Execute of second tx should fail.
        assert!(processor
            .process_instruction(
                &crate::ID,
                &keyed_accounts,
                &bincode::serialize(&EvmInstruction::EvmTransaction {
                    evm_tx: tx_1_sign.clone()
                })
                .unwrap(),
                &mut invoke_context,
                false,
            )
            .is_err());

        let executor = invoke_context.deconstruct().unwrap();
        let mut invoke_context = MockInvokeContext::with_evm(executor);
        // First tx should execute successfully.
        assert!(processor
            .process_instruction(
                &crate::ID,
                &keyed_accounts,
                &bincode::serialize(&EvmInstruction::EvmTransaction { evm_tx: tx_0_sign }).unwrap(),
                &mut invoke_context,
                false,
            )
            .is_ok());

        let executor = invoke_context.deconstruct().unwrap();
        let mut invoke_context = MockInvokeContext::with_evm(executor);
        // Executing copy of first tx with different signature, should not pass too.
        assert!(processor
            .process_instruction(
                &crate::ID,
                &keyed_accounts,
                &bincode::serialize(&EvmInstruction::EvmTransaction {
                    evm_tx: tx_0_shadow_sign,
                })
                .unwrap(),
                &mut invoke_context,
                false,
            )
            .is_err());

        let executor = invoke_context.deconstruct().unwrap();
        let mut invoke_context = MockInvokeContext::with_evm(executor);
        // But executing of second tx now should succeed.
        assert!(processor
            .process_instruction(
                &crate::ID,
                &keyed_accounts,
                &bincode::serialize(&EvmInstruction::EvmTransaction { evm_tx: tx_1_sign }).unwrap(),
                &mut invoke_context,
                false,
            )
            .is_ok());

        let executor = invoke_context.deconstruct().unwrap();
        println!("cx = {:?}", executor);
    }

    #[test]
    fn tx_preserve_gas() {
        let mut executor = evm_state::Executor::testing();
        let processor = EvmProcessor::default();
        let evm_account = RefCell::new(crate::create_state_account(0));
        let evm_keyed_account = KeyedAccount::new(&solana::evm_state::ID, false, &evm_account);
        let keyed_accounts = [evm_keyed_account];
        let secret_key = evm::SecretKey::from_slice(&SECRET_KEY_DUMMY).unwrap();
        let address = secret_key.to_address();
        executor.deposit(address, U256::from(1));
        let burn_addr = H160::zero();
        let tx_0 = evm::UnsignedTransaction {
            nonce: 0.into(),
            gas_price: 1.into(),
            gas_limit: 300000.into(),
            action: TransactionAction::Call(burn_addr),
            value: 0.into(),
            input: vec![],
        };
        let tx_0_sign = tx_0.sign(&secret_key, Some(CHAIN_ID));

        let mut invoke_context = MockInvokeContext::with_evm(executor);
        // Transaction should fail because can't pay the bill.
        assert!(processor
            .process_instruction(
                &crate::ID,
                &keyed_accounts,
                &bincode::serialize(&EvmInstruction::EvmTransaction { evm_tx: tx_0_sign }).unwrap(),
                &mut invoke_context,
                false,
            )
            .is_err());

        let executor = invoke_context.deconstruct().unwrap();
        println!("cx = {:?}", executor);
    }

    #[test]
    fn execute_tx_with_state_apply() {
        let mut state = evm_state::EvmBackend::default();
        let processor = EvmProcessor::default();
        let evm_account = RefCell::new(crate::create_state_account(0));
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

        let tx_create = tx_create.sign(&secret_key, Some(CHAIN_ID));

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
            let mut executor = evm_state::Executor::default_configs(state);
            let address = secret_key.to_address();
            executor.deposit(address, U256::from(2) * 300000);

            let mut invoke_context = MockInvokeContext::with_evm(executor);
            assert!(processor
                .process_instruction(
                    &crate::ID,
                    &keyed_accounts,
                    &bincode::serialize(&EvmInstruction::EvmTransaction { evm_tx: tx_create })
                        .unwrap(),
                    &mut invoke_context,
                    false,
                )
                .is_ok());

            let executor = invoke_context.deconstruct().unwrap();
            println!("cx = {:?}", executor);
            let committed = executor.deconstruct().commit_block(0, Default::default());
            state = committed.next_incomming(0);
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

        let tx_call = tx_call.sign(&secret_key, Some(CHAIN_ID));
        let tx_hash = tx_call.tx_id_hash();
        {
            let mut executor = evm_state::Executor::default_configs(state);

            let address = secret_key.to_address();
            executor.deposit(address, U256::from(2) * 300000);

            let mut invoke_context = MockInvokeContext::with_evm(executor);
            assert!(processor
                .process_instruction(
                    &crate::ID,
                    &keyed_accounts,
                    &bincode::serialize(&EvmInstruction::EvmTransaction { evm_tx: tx_call })
                        .unwrap(),
                    &mut invoke_context,
                    false,
                )
                .is_ok());

            let executor = invoke_context.deconstruct().unwrap();
            println!("cx = {:?}", executor);

            let committed = executor.deconstruct().commit_block(0, Default::default());

            let receipt = committed.find_committed_transaction(tx_hash).unwrap();
            assert!(matches!(
                receipt.status,
                ExitReason::Succeed(ExitSucceed::Returned)
            ));
        }

        // TODO: Assert that tx executed with result.
    }

    #[test]
    fn execute_native_transfer_tx() {
        let executor = evm_state::Executor::testing();
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

        let evm_account = RefCell::new(crate::create_state_account(0));
        let evm_keyed_account = KeyedAccount::new(&solana::evm_state::ID, false, &evm_account);
        let keyed_accounts = [evm_keyed_account, user_keyed_account];
        let ether_dummy_address = H160::repeat_byte(0x11);

        let lamports_before = keyed_accounts[0].try_account_ref_mut().unwrap().lamports;

        let mut invoke_context = MockInvokeContext::with_evm(executor);
        assert!(processor
            .process_instruction(
                &crate::ID,
                &keyed_accounts,
                &bincode::serialize(&EvmInstruction::SwapNativeToEther {
                    lamports: 1000,
                    evm_address: ether_dummy_address
                })
                .unwrap(),
                &mut invoke_context,
                false,
            )
            .is_ok());

        let executor = invoke_context.deconstruct().unwrap();
        println!("cx = {:?}", executor);

        assert_eq!(
            keyed_accounts[0].try_account_ref_mut().unwrap().lamports,
            lamports_before + 1000
        );
        assert_eq!(keyed_accounts[1].try_account_ref_mut().unwrap().lamports, 0);

        let mut invoke_context = MockInvokeContext::with_evm(executor);
        assert!(processor
            .process_instruction(
                &crate::ID,
                &keyed_accounts,
                &bincode::serialize(&EvmInstruction::FreeOwnership {}).unwrap(),
                &mut invoke_context,
                false,
            )
            .is_ok());

        let executor = invoke_context.deconstruct().unwrap();
        println!("cx = {:?}", executor);
        assert_eq!(
            keyed_accounts[1].try_account_ref_mut().unwrap().owner,
            solana_sdk::system_program::id()
        );

        let state = executor.deconstruct();
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
        let executor = evm_state::Executor::testing();
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

        let evm_account = RefCell::new(crate::create_state_account(0));
        let evm_keyed_account = KeyedAccount::new(&solana::evm_state::ID, false, &evm_account);
        let keyed_accounts = [evm_keyed_account, user_keyed_account];
        let mut rand = evm_state::rand::thread_rng();
        let ether_sc = evm::SecretKey::new(&mut rand);
        let ether_dummy_address = ether_sc.to_address();

        let lamports_before = keyed_accounts[0].try_account_ref_mut().unwrap().lamports;

        let lamports_to_send = 1000;
        let lamports_to_send_back = 300;

        let mut invoke_context = MockInvokeContext::with_evm(executor);
        assert!(processor
            .process_instruction(
                &crate::ID,
                &keyed_accounts,
                &bincode::serialize(&EvmInstruction::SwapNativeToEther {
                    lamports: lamports_to_send,
                    evm_address: ether_dummy_address
                })
                .unwrap(),
                &mut invoke_context,
                false,
            )
            .is_ok());

        let executor = invoke_context.deconstruct().unwrap();
        println!("cx = {:?}", executor);

        assert_eq!(
            keyed_accounts[0].try_account_ref_mut().unwrap().lamports,
            lamports_before + lamports_to_send
        );
        assert_eq!(keyed_accounts[1].try_account_ref_mut().unwrap().lamports, 0);

        let mut state = executor.deconstruct();
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
            action: TransactionAction::Call(*precompiles::ETH_TO_VLX_ADDR),
            value: crate::scope::evm::lamports_to_gwei(lamports_to_send_back),
            input: precompiles::ETH_TO_VLX_CODE
                .abi
                .encode_input(&[ethabi::Token::FixedBytes(fake_user_id.to_bytes().to_vec())])
                .unwrap(),
        };

        let tx_call = tx_call.sign(&ether_sc, Some(CHAIN_ID));
        {
            let executor = evm_state::Executor::default_configs(state);

            let mut invoke_context = MockInvokeContext::with_evm(executor);
            // Error transaction has no needed account.
            assert!(processor
                .process_instruction(
                    &crate::ID,
                    &keyed_accounts,
                    &bincode::serialize(&EvmInstruction::EvmTransaction { evm_tx: tx_call })
                        .unwrap(),
                    &mut invoke_context,
                    false,
                )
                .is_err());

            let executor = invoke_context.deconstruct().unwrap();
            println!("cx = {:?}", executor);
            let committed = executor.deconstruct().commit_block(0, Default::default());
            state = committed.next_incomming(0);
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

        let executor = evm_state::Executor::testing();
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

        let evm_account = RefCell::new(crate::create_state_account(0));
        let evm_keyed_account = KeyedAccount::new(&solana::evm_state::ID, false, &evm_account);
        let keyed_accounts = [evm_keyed_account, user_keyed_account];
        let mut rand = evm_state::rand::thread_rng();
        let ether_sc = evm::SecretKey::new(&mut rand);
        let ether_dummy_address = ether_sc.to_address();

        let lamports_before = keyed_accounts[0].try_account_ref_mut().unwrap().lamports;

        let lamports_to_send = 1000;
        let lamports_to_send_back = 300;

        let mut invoke_context = MockInvokeContext::with_evm(executor);
        processor
            .process_instruction(
                &crate::ID,
                &keyed_accounts,
                &bincode::serialize(&EvmInstruction::SwapNativeToEther {
                    lamports: lamports_to_send,
                    evm_address: ether_dummy_address,
                })
                .unwrap(),
                &mut invoke_context,
                false,
            )
            .unwrap();

        let executor = invoke_context.deconstruct().unwrap();
        println!("cx = {:?}", executor);

        assert_eq!(
            keyed_accounts[0].try_account_ref_mut().unwrap().lamports,
            lamports_before + lamports_to_send
        );
        assert_eq!(keyed_accounts[1].try_account_ref_mut().unwrap().lamports, 0);

        let mut state = executor.deconstruct();
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
            action: TransactionAction::Call(*precompiles::ETH_TO_VLX_ADDR),
            value: crate::scope::evm::lamports_to_gwei(lamports_to_send_back),
            input: precompiles::ETH_TO_VLX_CODE
                .abi
                .encode_input(&[ethabi::Token::FixedBytes(user_id.to_bytes().to_vec())])
                .unwrap(),
        };

        let tx_call = tx_call.sign(&ether_sc, Some(CHAIN_ID));
        {
            let executor = evm_state::Executor::default_configs(state);

            println!("cx before = {:?}", executor);
            let mut invoke_context = MockInvokeContext::with_evm(executor);

            let result = processor.process_instruction(
                &crate::ID,
                &keyed_accounts,
                &bincode::serialize(&EvmInstruction::EvmTransaction { evm_tx: tx_call }).unwrap(),
                &mut invoke_context,
                false,
            );
            println!("logger = {:?}", invoke_context.logger);

            let executor = invoke_context.deconstruct().unwrap();

            println!("cx = {:?}", executor);
            result.unwrap();

            let committed = executor.deconstruct().commit_block(0, Default::default());
            state = committed.next_incomming(0);
        }

        assert_eq!(
            keyed_accounts[0].try_account_ref_mut().unwrap().lamports,
            lamports_before + lamports_to_send - lamports_to_send_back
        );
        assert_eq!(first_user_account.borrow().lamports, 0);
        assert_eq!(second_user_account.borrow().lamports, lamports_to_send_back);

        assert!(
            state
                .get_account_state(ether_dummy_address)
                .unwrap()
                .balance
                < crate::scope::evm::lamports_to_gwei(lamports_to_send - lamports_to_send_back)
                && state
                    .get_account_state(ether_dummy_address)
                    .unwrap()
                    .balance
                    > crate::scope::evm::lamports_to_gwei(lamports_to_send - lamports_to_send_back)
                        - 300000 //(max_fee)
        );
    }

    #[test]
    fn execute_transfer_roundtrip_insufficient_amount() {
        let _ = simple_logger::SimpleLogger::new().init();

        let executor = evm_state::Executor::testing();
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

        let evm_account = RefCell::new(crate::create_state_account(0));
        let evm_keyed_account = KeyedAccount::new(&solana::evm_state::ID, false, &evm_account);
        let keyed_accounts = [evm_keyed_account, user_keyed_account];
        let mut rand = evm_state::rand::thread_rng();
        let ether_sc = evm::SecretKey::new(&mut rand);
        let ether_dummy_address = ether_sc.to_address();

        let lamports_before = keyed_accounts[0].try_account_ref_mut().unwrap().lamports;

        let lamports_to_send = 1000;
        let lamports_to_send_back = 1001;

        let mut invoke_context = MockInvokeContext::with_evm(executor);
        processor
            .process_instruction(
                &crate::ID,
                &keyed_accounts,
                &bincode::serialize(&EvmInstruction::SwapNativeToEther {
                    lamports: lamports_to_send,
                    evm_address: ether_dummy_address,
                })
                .unwrap(),
                &mut invoke_context,
                false,
            )
            .unwrap();
        let executor = invoke_context.deconstruct().unwrap();
        println!("cx = {:?}", executor);

        assert_eq!(
            keyed_accounts[0].try_account_ref_mut().unwrap().lamports,
            lamports_before + lamports_to_send
        );
        assert_eq!(keyed_accounts[1].try_account_ref_mut().unwrap().lamports, 0);

        let mut state = executor.deconstruct();
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
            action: TransactionAction::Call(*precompiles::ETH_TO_VLX_ADDR),
            value: crate::scope::evm::lamports_to_gwei(lamports_to_send_back),
            input: precompiles::ETH_TO_VLX_CODE
                .abi
                .encode_input(&[ethabi::Token::FixedBytes(user_id.to_bytes().to_vec())])
                .unwrap(),
        };

        let tx_call = tx_call.sign(&ether_sc, Some(CHAIN_ID));
        {
            let executor = evm_state::Executor::default_configs(state);
            println!("cx before = {:?}", executor);
            let mut invoke_context = MockInvokeContext::with_evm(executor);

            let result = processor.process_instruction(
                &crate::ID,
                &keyed_accounts,
                &bincode::serialize(&EvmInstruction::EvmTransaction { evm_tx: tx_call }).unwrap(),
                &mut invoke_context,
                false,
            );

            println!("logger = {:?}", invoke_context.logger);
            let executor = invoke_context.deconstruct().unwrap();
            println!("cx = {:?}", executor);
            result.unwrap_err();

            let committed = executor.deconstruct().commit_block(0, Default::default());
            state = committed.next_incomming(0);
        }

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

    fn all_ixs() -> Vec<solana_sdk::instruction::Instruction> {
        let (tx_call, unsigned_tx) = dummy_call(0);

        let signer = solana::Address::new_unique();
        vec![
            crate::transfer_native_to_eth(signer, 1, tx_call.address().unwrap()),
            crate::free_ownership(signer),
            crate::send_raw_tx(signer, tx_call, None),
            crate::authorized_tx(signer, unsigned_tx),
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
        let processor = EvmProcessor::default();

        let mut dummy_accounts = BTreeMap::new();

        for ix in all_ixs() {
            // Create clear executor for each run, to avoid state conflicts in instructions (signed and unsigned tx with same nonce).
            let mut executor = evm_state::Executor::testing();

            let secret_key = evm::SecretKey::from_slice(&SECRET_KEY_DUMMY).unwrap();
            executor.deposit(secret_key.to_address(), U256::from(2) * 300000); // deposit some small amount for gas payments
                                                                               // insert new accounts, if some missing
            for acc in &ix.accounts {
                // also deposit to instruction callers shadow evm addresses (to allow authorized tx call)
                executor.deposit(
                    crate::evm_address_for_program(acc.pubkey),
                    U256::from(2) * 300000,
                );
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
            let mut context = MockInvokeContext::with_evm(executor);
            println!("Keyed accounts = {:?}", keyed_accounts);
            // First execution without evm state key, should fail.
            let err = processor
                .process_instruction(
                    &crate::ID,
                    &keyed_accounts[1..],
                    &bincode::serialize(&data).unwrap(),
                    &mut context,
                    false,
                )
                .unwrap_err();
            println!("logg = {:?}", context.logger);
            match err {
                InstructionError::NotEnoughAccountKeys | InstructionError::MissingAccount => {}
                rest => panic!("Unexpected result = {:?}", rest),
            }

            // Because first execution is fail, state didn't changes, and second execution should pass.
            let result = processor.process_instruction(
                &crate::ID,
                &keyed_accounts,
                &bincode::serialize(&data).unwrap(),
                &mut context,
                false,
            );

            println!("logg = {:?}", context.logger);
            let executor = context.deconstruct().unwrap();
            println!("cx =  {:?}", executor);
            result.unwrap();
        }
    }

    #[test]
    fn authorized_tx_only_from_signer() {
        let _ = simple_logger::SimpleLogger::new().init();
        let mut executor = evm_state::Executor::testing();

        let secret_key = evm::SecretKey::from_slice(&SECRET_KEY_DUMMY).unwrap();

        let address = secret_key.to_address();
        executor.deposit(address, U256::from(2) * 300000);
        let tx_create = evm::UnsignedTransaction {
            nonce: 0.into(),
            gas_price: 1.into(),
            gas_limit: 300000.into(),
            action: TransactionAction::Create,
            value: 0.into(),
            input: hex::decode(evm_state::HELLO_WORLD_CODE).unwrap().to_vec(),
        };

        let tx_create = tx_create.sign(&secret_key, Some(CHAIN_ID));

        let processor = EvmProcessor::default();

        let first_user_account = RefCell::new(solana_sdk::account::Account {
            lamports: 1000,
            data: vec![],
            owner: crate::ID,
            executable: false,
            rent_epoch: 0,
        });
        let user_id = Pubkey::new_unique();
        let user_keyed_account = KeyedAccount::new(&user_id, false, &first_user_account);

        let evm_account = RefCell::new(crate::create_state_account(0));
        let evm_keyed_account = KeyedAccount::new(&solana::evm_state::ID, false, &evm_account);
        let keyed_accounts = [evm_keyed_account, user_keyed_account];

        let dummy_address = tx_create.address().unwrap();
        let ix = crate::send_raw_tx(user_id, tx_create, None);

        let mut invoke_context = MockInvokeContext::with_evm(executor);
        processor
            .process_instruction(
                &crate::ID,
                &keyed_accounts,
                &ix.data,
                &mut invoke_context,
                false,
            )
            .unwrap();

        let unsigned_tx = evm::UnsignedTransaction {
            nonce: 0.into(),
            gas_price: 1.into(),
            gas_limit: 300000.into(),
            action: TransactionAction::Call(dummy_address),
            value: 0.into(),
            input: hex::decode(evm_state::HELLO_WORLD_ABI).unwrap().to_vec(),
        };

        let mut executor = invoke_context.deconstruct().unwrap();
        executor.deposit(
            crate::evm_address_for_program(user_id),
            U256::from(2) * 300000,
        );
        let ix = crate::authorized_tx(user_id, unsigned_tx);

        println!("Keyed accounts = {:?}", &keyed_accounts);

        let mut invoke_context = MockInvokeContext::with_evm(executor);
        // First execution without signer user key, should fail.
        let err = processor
            .process_instruction(
                &crate::ID,
                &keyed_accounts,
                &ix.data,
                &mut invoke_context,
                false,
            )
            .unwrap_err();

        match err {
            InstructionError::MissingRequiredSignature => {}
            rest => panic!("Unexpected result = {:?}", rest),
        }

        let user_keyed_account = KeyedAccount::new(&user_id, true, &first_user_account);
        let evm_keyed_account = KeyedAccount::new(&solana::evm_state::ID, false, &evm_account);
        let keyed_accounts = [evm_keyed_account, user_keyed_account];

        let executor = invoke_context.deconstruct().unwrap();
        // Because first execution is fail, state didn't changes, and second execution should pass.
        processor
            .process_instruction(
                &crate::ID,
                &keyed_accounts,
                &ix.data,
                &mut MockInvokeContext::with_evm(executor),
                false,
            )
            .unwrap();
    }

    #[test]
    fn big_tx_allocation_error() {
        let executor = evm_state::Executor::testing();
        let processor = EvmProcessor::default();
        let evm_account = RefCell::new(crate::create_state_account(0));
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

        let mut invoke_context = MockInvokeContext::with_evm(executor);
        assert!(processor
            .process_instruction(
                &crate::ID,
                &keyed_accounts,
                &bincode::serialize(&EvmInstruction::EvmBigTransaction(big_transaction)).unwrap(),
                &mut invoke_context,
                false,
            )
            .is_err());

        let executor = invoke_context.deconstruct().unwrap();
        println!("cx = {:?}", executor);

        let big_transaction = EvmBigTransaction::EvmTransactionAllocate {
            size: evm_state::MAX_TX_LEN,
        };

        let mut invoke_context = MockInvokeContext::with_evm(executor);
        processor
            .process_instruction(
                &crate::ID,
                &keyed_accounts,
                &bincode::serialize(&EvmInstruction::EvmBigTransaction(big_transaction)).unwrap(),
                &mut invoke_context,
                false,
            )
            .unwrap();

        let executor = invoke_context.deconstruct().unwrap();
        println!("cx = {:?}", executor);
    }

    #[test]
    fn big_tx_write_out_of_bound() {
        let _ = simple_logger::SimpleLogger::new().init();

        let executor = evm_state::Executor::testing();
        let processor = EvmProcessor::default();
        let evm_account = RefCell::new(crate::create_state_account(0));
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

        let mut invoke_context = MockInvokeContext::with_evm(executor);
        processor
            .process_instruction(
                &crate::ID,
                &keyed_accounts,
                &bincode::serialize(&EvmInstruction::EvmBigTransaction(big_transaction)).unwrap(),
                &mut invoke_context,
                false,
            )
            .unwrap();

        let executor = invoke_context.deconstruct().unwrap();
        println!("cx = {:?}", executor);

        // out of bound write
        let big_transaction = EvmBigTransaction::EvmTransactionWrite {
            offset: batch_size,
            data: vec![1],
        };

        let mut invoke_context = MockInvokeContext::with_evm(executor);
        assert!(processor
            .process_instruction(
                &crate::ID,
                &keyed_accounts,
                &bincode::serialize(&EvmInstruction::EvmBigTransaction(big_transaction)).unwrap(),
                &mut invoke_context,
                false,
            )
            .is_err());

        let executor = invoke_context.deconstruct().unwrap();
        println!("cx = {:?}", executor);
        // out of bound write
        let big_transaction = EvmBigTransaction::EvmTransactionWrite {
            offset: 0,
            data: vec![1; batch_size as usize + 1],
        };

        let mut invoke_context = MockInvokeContext::with_evm(executor);
        assert!(processor
            .process_instruction(
                &crate::ID,
                &keyed_accounts,
                &bincode::serialize(&EvmInstruction::EvmBigTransaction(big_transaction)).unwrap(),
                &mut invoke_context,
                false,
            )
            .is_err());

        let executor = invoke_context.deconstruct().unwrap();
        println!("cx = {:?}", executor);

        // Write in bounds
        let big_transaction = EvmBigTransaction::EvmTransactionWrite {
            offset: 0,
            data: vec![1; batch_size as usize],
        };

        let mut invoke_context = MockInvokeContext::with_evm(executor);
        processor
            .process_instruction(
                &crate::ID,
                &keyed_accounts,
                &bincode::serialize(&EvmInstruction::EvmBigTransaction(big_transaction)).unwrap(),
                &mut invoke_context,
                false,
            )
            .unwrap();

        let executor = invoke_context.deconstruct().unwrap();
        println!("cx = {:?}", executor);
        // Overlaped writes is allowed
        let big_transaction = EvmBigTransaction::EvmTransactionWrite {
            offset: batch_size - 1,
            data: vec![1],
        };

        let mut invoke_context = MockInvokeContext::with_evm(executor);
        processor
            .process_instruction(
                &crate::ID,
                &keyed_accounts,
                &bincode::serialize(&EvmInstruction::EvmBigTransaction(big_transaction)).unwrap(),
                &mut invoke_context,
                false,
            )
            .unwrap();

        let executor = invoke_context.deconstruct().unwrap();
        println!("cx = {:?}", executor);
    }

    #[test]
    fn big_tx_write_without_alloc() {
        let executor = evm_state::Executor::testing();
        let processor = EvmProcessor::default();
        let evm_account = RefCell::new(crate::create_state_account(0));
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

        let mut invoke_context = MockInvokeContext::with_evm(executor);
        assert!(processor
            .process_instruction(
                &crate::ID,
                &keyed_accounts,
                &bincode::serialize(&EvmInstruction::EvmBigTransaction(big_transaction)).unwrap(),
                &mut invoke_context,
                false,
            )
            .is_err());

        let executor = invoke_context.deconstruct().unwrap();
        println!("cx = {:?}", executor);
    }

    #[test]
    fn check_tx_mtu_is_in_solanas_limit() {
        use solana_sdk::hash::hash;
        use solana_sdk::message::Message;
        use solana_sdk::signature::{Keypair, Signer};
        use solana_sdk::transaction::Transaction;

        let storage = Keypair::new();
        let bridge = Keypair::new();
        let ix = crate::big_tx_write(&storage.pubkey(), 0, vec![1; evm::TX_MTU]);
        let tx_before = Transaction::new(
            &[&bridge, &storage],
            Message::new(&[ix], Some(&bridge.pubkey())),
            hash(&[1]),
        );
        let tx = bincode::serialize(&tx_before).unwrap();
        let tx: Transaction = limited_deserialize(&tx).unwrap();
        assert_eq!(tx_before, tx);
    }
}
