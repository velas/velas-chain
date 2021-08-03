use std::cell::RefMut;
use std::ops::DerefMut;

use super::account_structure::AccountStructure;
use super::instructions::{EvmBigTransaction, EvmInstruction};
use super::precompiles;
use super::scope::*;
use log::*;

use evm::{gweis_to_lamports, Executor, ExitReason};
use solana_sdk::account::Account;
use solana_sdk::ic_msg;
use solana_sdk::instruction::InstructionError;
use solana_sdk::process_instruction::InvokeContext;
use solana_sdk::pubkey::Pubkey;
use solana_sdk::{keyed_account::KeyedAccount, program_utils::limited_deserialize};

use super::error::EvmError;
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
            .is_feature_active(&solana_sdk::feature_set::velas::evm_cross_execution::id());
        let register_swap_tx_in_evm = invoke_context
            .is_feature_active(&solana_sdk::feature_set::velas::native_swap_in_evm_history::id());
        let new_error_handling = invoke_context
            .is_feature_active(&solana_sdk::feature_set::velas::evm_new_error_handling::id());
        let unsigned_tx_fix = invoke_context
            .is_feature_active(&solana_sdk::feature_set::velas::unsigned_tx_fix::id());
        if cross_execution && !cross_execution_enabled {
            ic_msg!(invoke_context, "Cross-Program evm execution not enabled.");
            return Err(EvmError::CrossExecutionNotEnabled.into());
        }

        let evm_executor = if let Some(evm_executor) = invoke_context.get_evm_executor() {
            evm_executor
        } else {
            ic_msg!(
                invoke_context,
                "Invoke context didn't provide evm executor."
            );
            return Err(EvmError::EvmExecutorNotFound.into());
        };
        // bind variable to increase lifetime of temporary RefCell borrow.
        let mut evm_executor_borrow;
        // evm executor cannot be borrowed, because it not exist in invoke context, or borrowing failed.
        let executor = if let Ok(evm_executor) = evm_executor.try_borrow_mut() {
            evm_executor_borrow = evm_executor;
            evm_executor_borrow.deref_mut()
        } else {
            ic_msg!(
                invoke_context,
                "Recursive cross-program evm execution not enabled."
            );
            return Err(EvmError::RecursiveCrossExecution.into());
        };

        let accounts = AccountStructure::new(evm_state_account, keyed_accounts);

        let ix = limited_deserialize(data)?;
        trace!("Run evm exec with ix = {:?}.", ix);
        let result = match ix {
            EvmInstruction::EvmTransaction { evm_tx } => {
                self.process_raw_tx(executor, invoke_context, accounts, evm_tx)
            }
            EvmInstruction::EvmAuthorizedTransaction { from, unsigned_tx } => self
                .process_authorized_tx(
                    executor,
                    invoke_context,
                    accounts,
                    from,
                    unsigned_tx,
                    unsigned_tx_fix,
                ),
            EvmInstruction::EvmBigTransaction(big_tx) => {
                self.process_big_tx(executor, invoke_context, accounts, big_tx, unsigned_tx_fix)
            }
            EvmInstruction::FreeOwnership {} => {
                self.process_free_ownership(executor, invoke_context, accounts)
            }
            EvmInstruction::SwapNativeToEther {
                lamports,
                evm_address,
            } => self.process_swap_to_evm(
                executor,
                invoke_context,
                accounts,
                lamports,
                evm_address,
                register_swap_tx_in_evm,
                unsigned_tx_fix,
            ),
        };

        if register_swap_tx_in_evm {
            executor.reset_balance(*precompiles::ETH_TO_VLX_ADDR)
        }

        // When old error handling, manually convert EvmError to InstructionError
        result.or_else(|error| {
            ic_msg!(invoke_context, "Execution error: {}", error);

            let err = if !new_error_handling {
                use EvmError::*;
                match error {
                    CrossExecutionNotEnabled
                    | EvmExecutorNotFound
                    | RecursiveCrossExecution
                    | FreeNotEvmAccount
                    | InternalTransactionError => InstructionError::InvalidError,

                    InternalExecutorError
                    | AuthorizedTransactionIncorrectAddress
                    | AllocateStorageFailed
                    | WriteStorageFailed
                    | DeserializationError => InstructionError::InvalidArgument,

                    MissingAccount => InstructionError::MissingAccount,
                    MissingRequiredSignature => InstructionError::MissingRequiredSignature,
                    SwapInsufficient => InstructionError::InsufficientFunds,
                    BorrowingFailed => InstructionError::AccountBorrowFailed,
                    RevertTransaction => return Ok(()), // originally revert was not an error
                    // future error would be just invalid errors.
                    _ => InstructionError::InvalidError,
                }
            } else {
                error.into()
            };

            Err(err)
        })
    }

    fn process_raw_tx(
        &self,
        executor: &mut Executor,
        invoke_context: &dyn InvokeContext,
        accounts: AccountStructure,
        evm_tx: evm::Transaction,
    ) -> Result<(), EvmError> {
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
        let result = executor.transaction_execute(
            evm_tx,
            precompiles::entrypoint(accounts, executor.support_precompile()),
        );
        let sender = accounts.users.first();

        self.handle_transaction_result(invoke_context, accounts, sender, tx_gas_price, result)
    }

    fn process_authorized_tx(
        &self,
        executor: &mut Executor,
        invoke_context: &dyn InvokeContext,
        accounts: AccountStructure,
        from: evm::Address,
        unsigned_tx: evm::UnsignedTransaction,
        unsigned_tx_fix: bool,
    ) -> Result<(), EvmError> {
        // TODO: Check that it is from program?
        // TODO: Gas limit?
        let program_account = accounts.first().ok_or_else(|| {
            ic_msg!(
                invoke_context,
                "EvmAuthorizedTransaction: Not enough accounts, expected signer address as second account."
            );
            EvmError::MissingAccount
        })?;
        let key = if let Some(key) = program_account.signer_key() {
            key
        } else {
            ic_msg!(
                invoke_context,
                "EvmAuthorizedTransaction: Second account is not a signer, cannot execute transaction."
            );
            return Err(EvmError::MissingRequiredSignature);
        };
        let from_expected = crate::evm_address_for_program(*key);

        if from_expected != from {
            ic_msg!(
                invoke_context,
                "EvmAuthorizedTransaction: From is not calculated with evm_address_for_program."
            );
            return Err(EvmError::AuthorizedTransactionIncorrectAddress);
        }

        ic_msg!(
            invoke_context,
            "EvmAuthorizedTransaction: Executing authorized transaction: gas_limit:{}, gas_price:{}, value:{}, action:{:?},",
            unsigned_tx.gas_limit,
            unsigned_tx.gas_price,
            unsigned_tx.value,
            unsigned_tx.action
        );

        if unsigned_tx_fix {
            let program_caller = invoke_context.get_caller().map(|k| *k).unwrap_or_default();
            let program_owner = program_account
                .try_account_ref()
                .map_err(|_| EvmError::BorrowingFailed)?
                .owner;
            if program_owner != program_caller {
                return Err(EvmError::AuthorizedTransactionIncorrectOwner);
            }
        }

        let tx_gas_price = unsigned_tx.gas_price;
        let result = executor.transaction_execute_unsinged(
            from,
            unsigned_tx,
            unsigned_tx_fix,
            precompiles::entrypoint(accounts, executor.support_precompile()),
        );
        let sender = accounts.first();

        self.handle_transaction_result(invoke_context, accounts, sender, tx_gas_price, result)
    }

    fn process_free_ownership(
        &self,
        _executor: &mut Executor,
        invoke_context: &dyn InvokeContext,
        accounts: AccountStructure,
    ) -> Result<(), EvmError> {
        let user = accounts.first().ok_or_else(|| {
            ic_msg!(
                invoke_context,
                "FreeOwnership: expected account as argument."
            );
            EvmError::MissingAccount
        })?;
        let user_pk = user.unsigned_key();
        let mut user = user
            .try_account_ref_mut()
            .map_err(|_| EvmError::BorrowingFailed)?;

        if user.owner != crate::ID || *user_pk == solana::evm_state::ID {
            ic_msg!(
                invoke_context,
                "FreeOwnership: Incorrect account provided, maybe this account is not owned by evm."
            );
            return Err(EvmError::FreeNotEvmAccount);
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
        register_swap_tx_in_evm: bool,
        unsigned_tx_fix: bool,
    ) -> Result<(), EvmError> {
        let gweis = evm::lamports_to_gwei(lamports);
        let user = accounts.first().ok_or_else(|| {
            ic_msg!(
                invoke_context,
                "SwapNativeToEther: No sender account found in swap to evm."
            );
            EvmError::MissingAccount
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
            return Err(EvmError::MissingRequiredSignature);
        }

        let mut user_account = user
            .try_account_ref_mut()
            .map_err(|_| EvmError::BorrowingFailed)?;
        if lamports > user_account.lamports {
            ic_msg!(
                invoke_context,
                "SwapNativeToEther: insufficient lamports ({}, need {})",
                user_account.lamports,
                lamports
            );
            return Err(EvmError::SwapInsufficient);
        }

        user_account.lamports -= lamports;
        accounts
            .evm
            .try_account_ref_mut()
            .map_err(|_| EvmError::BorrowingFailed)?
            .lamports += lamports;
        executor.deposit(evm_address, gweis);
        if register_swap_tx_in_evm {
            executor.register_swap_tx_in_evm(
                *precompiles::ETH_TO_VLX_ADDR,
                evm_address,
                gweis,
                unsigned_tx_fix,
            )
        }
        Ok(())
    }

    fn process_big_tx(
        &self,
        executor: &mut Executor,
        invoke_context: &dyn InvokeContext,
        accounts: AccountStructure,
        big_tx: EvmBigTransaction,
        unsigned_tx_fix: bool,
    ) -> Result<(), EvmError> {
        debug!("executing big_tx = {:?}", big_tx);

        let storage_account = accounts.first().ok_or_else(|| {
            ic_msg!(
                invoke_context,
                "EvmBigTransaction: No storage account found."
            );
            EvmError::MissingAccount
        })?;

        if storage_account.signer_key().is_none() {
            ic_msg!(
                invoke_context,
                "EvmBigTransaction: Storage should sign instruction."
            );
            return Err(EvmError::MissingRequiredSignature);
        }
        let mut storage = storage_account
            .try_account_ref_mut()
            .map_err(|_| EvmError::BorrowingFailed)?;

        let mut tx_chunks = TxChunks::new(storage.data.as_mut_slice());

        match big_tx {
            EvmBigTransaction::EvmTransactionAllocate { size } => {
                tx_chunks.init(size as usize).map_err(|e| {
                    ic_msg!(
                        invoke_context,
                        "EvmTransactionAllocate: allocate error: {:?}",
                        e
                    );
                    EvmError::AllocateStorageFailed
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
                    EvmError::WriteStorageFailed
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
                    EvmError::DeserializationError
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
                let result = executor.transaction_execute(
                    tx,
                    precompiles::entrypoint(accounts, executor.support_precompile()),
                );

                let sender = accounts.users.get(1);
                if unsigned_tx_fix {
                    self.cleanup_storage(invoke_context, storage, &sender.unwrap_or(accounts.evm))?;
                }

                self.handle_transaction_result(
                    invoke_context,
                    accounts,
                    sender,
                    tx_gas_price,
                    result,
                )
            }
            EvmBigTransaction::EvmTransactionExecuteUnsigned { from } => {
                if !unsigned_tx_fix {
                    ic_msg!(
                        invoke_context,
                        "BigTransaction::EvmTransactionExecuteUnsigned: Unsigned tx fix is not activated, this instruction is not supported."
                    );
                    return Err(EvmError::InstructionNotSupportedYet);
                }
                debug!("Tx chunks crc = {:#x}", tx_chunks.crc());

                let bytes = tx_chunks.take();

                debug!("Trying to deserialize tx chunks byte = {:?}", bytes);
                let unsigned_tx: evm::UnsignedTransaction =
                    bincode::deserialize(&bytes).map_err(|e| {
                        ic_msg!(
                        invoke_context,
                        "BigTransaction::EvmTransactionExecute: Tx chunks deserialize error: {:?}",
                        e
                    );
                        EvmError::DeserializationError
                    })?;

                debug!("Executing EVM tx = {:?}", unsigned_tx);
                // TODO: Gas limit?
                let program_account = accounts.users.get(1).ok_or_else(|| {
                    ic_msg!(
                        invoke_context,
                        "BigTransaction::EvmTransactionExecuteUnsigned: Not enough accounts, expected signer address as second account."
                    );
                    EvmError::MissingAccount
                })?;
                let key = if let Some(key) = program_account.signer_key() {
                    key
                } else {
                    ic_msg!(
                        invoke_context,
                        "BigTransaction::EvmTransactionExecuteUnsigned: Second account is not a signer, cannot execute transaction."
                    );
                    return Err(EvmError::MissingRequiredSignature);
                };
                let from_expected = crate::evm_address_for_program(*key);

                if from_expected != from {
                    ic_msg!(
                        invoke_context,
                        "BigTransaction::EvmTransactionExecuteUnsigned: From is not calculated with evm_address_for_program."
                    );
                    return Err(EvmError::AuthorizedTransactionIncorrectAddress);
                }

                ic_msg!(
                    invoke_context,
                    "BigTransaction::EvmTransactionExecuteUnsigned: Executing authorized transaction: gas_limit:{}, gas_price:{}, value:{}, action:{:?},",
                    unsigned_tx.gas_limit,
                    unsigned_tx.gas_price,
                    unsigned_tx.value,
                    unsigned_tx.action
                );

                if unsigned_tx_fix {
                    let program_caller =
                        invoke_context.get_caller().map(|k| *k).unwrap_or_default();
                    let program_owner = program_account
                        .try_account_ref()
                        .map_err(|_| EvmError::BorrowingFailed)?
                        .owner;
                    if program_owner != program_caller {
                        return Err(EvmError::AuthorizedTransactionIncorrectOwner);
                    }
                }
                let tx_gas_price = unsigned_tx.gas_price;
                let result = executor.transaction_execute_unsinged(
                    from,
                    unsigned_tx,
                    unsigned_tx_fix,
                    precompiles::entrypoint(accounts, executor.support_precompile()),
                );

                self.cleanup_storage(invoke_context, storage, &program_account)?;
                self.handle_transaction_result(
                    invoke_context,
                    accounts,
                    Some(program_account),
                    tx_gas_price,
                    result,
                )
            }
        }
    }

    pub fn cleanup_storage<'a>(
        &self,
        invoke_context: &dyn InvokeContext,
        mut storage_ref: RefMut<Account>,
        user: &'a KeyedAccount<'a>,
    ) -> Result<(), EvmError> {
        let balance = storage_ref.lamports;

        storage_ref.lamports = 0;

        user.try_account_ref_mut()
            .map_err(|_| EvmError::BorrowingFailed)?
            .lamports += balance;

        ic_msg!(
            invoke_context,
            "Refunding storage rent fee to transaction sender fee:{:?}, sender:{}",
            balance,
            user.unsigned_key()
        );
        Ok(())
    }

    // Handle executor errors.
    // refund fee
    pub fn handle_transaction_result(
        &self,
        invoke_context: &dyn InvokeContext,
        accounts: AccountStructure,
        sender: Option<&KeyedAccount>,
        tx_gas_price: evm_state::U256,
        result: Result<evm_state::ExecutionResult, evm_state::error::Error>,
    ) -> Result<(), EvmError> {
        let result = result.map_err(|e| {
            ic_msg!(invoke_context, "Transaction execution error: {}", e);
            EvmError::InternalExecutorError
        })?;

        ic_msg!(
            invoke_context,
            "Transaction execution status = {:?}",
            result
        );
        if matches!(
            result.exit_reason,
            ExitReason::Fatal(_) | ExitReason::Error(_)
        ) {
            return Err(EvmError::InternalTransactionError);
        }
        // Fee refund will not work with revert, because transaction will be reverted from native chain too.
        if let ExitReason::Revert(_) = result.exit_reason {
            return Err(EvmError::RevertTransaction);
        }

        let fee = tx_gas_price * result.used_gas;
        if let Some(payer) = sender {
            let (fee, _) = gweis_to_lamports(fee);
            ic_msg!(
                invoke_context,
                "Refunding transaction fee to transaction sender fee:{:?}, sender:{}",
                fee,
                payer.unsigned_key()
            );
            accounts.refund_fee(payer, fee)?;
        } else {
            ic_msg!(
                invoke_context,
                "Sender didnt give his account, ignoring fee refund.",
            );
        }

        Ok(())
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
        let first_user_account = RefCell::new(solana_sdk::account::AccountSharedData {
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
        let user_account = RefCell::new(solana_sdk::account::AccountSharedData {
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
        let first_user_account = RefCell::new(solana_sdk::account::AccountSharedData {
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

        let second_user_account = RefCell::new(solana_sdk::account::AccountSharedData {
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
            assert_eq!(
                state
                    .get_account_state(*precompiles::ETH_TO_VLX_ADDR)
                    .unwrap()
                    .balance,
                0.into()
            )
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
        let first_user_account = RefCell::new(solana_sdk::account::AccountSharedData {
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

        let second_user_account = RefCell::new(solana_sdk::account::AccountSharedData {
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
            assert_eq!(
                state
                    .get_account_state(*precompiles::ETH_TO_VLX_ADDR)
                    .unwrap()
                    .balance,
                0.into()
            )
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
        let first_user_account = RefCell::new(solana_sdk::account::AccountSharedData {
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

        let second_user_account = RefCell::new(solana_sdk::account::AccountSharedData {
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

    fn account_by_key(pubkey: solana::Address) -> solana_sdk::account::AccountSharedData {
        match &pubkey {
            id if id == &crate::ID => {
                native_loader::create_loadable_account_for_test("EVM Processor")
            }
            id if id == &solana_sdk::sysvar::rent::id() => solana_sdk::account::AccountSharedData {
                lamports: 10,
                owner: native_loader::id(),
                data: bincode::serialize(&Rent::default()).unwrap(),
                executable: false,
                rent_epoch: 0,
            },
            _rest => solana_sdk::account::AccountSharedData {
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

    // Contract receive ether, and then try to spend 1 ether, when other method called.
    // Spend is done with native swap.
    #[test]
    fn execute_swap_with_revert() {
        use hex_literal::hex;
        let _ = simple_logger::SimpleLogger::new().init();
        let code_without_revert = hex!("608060405234801561001057600080fd5b5061021a806100206000396000f3fe6080604052600436106100295760003560e01c80639c320d0b1461002e578063a3e76c0f14610089575b600080fd5b34801561003a57600080fd5b506100876004803603604081101561005157600080fd5b81019080803573ffffffffffffffffffffffffffffffffffffffff16906020019092919080359060200190929190505050610093565b005b6100916101e2565b005b8173ffffffffffffffffffffffffffffffffffffffff16670de0b6b3a764000082604051602401808281526020019150506040516020818303038152906040527fb1d6927a000000000000000000000000000000000000000000000000000000007bffffffffffffffffffffffffffffffffffffffffffffffffffffffff19166020820180517bffffffffffffffffffffffffffffffffffffffffffffffffffffffff83818316178352505050506040518082805190602001908083835b602083106101745780518252602082019150602081019050602083039250610151565b6001836020036101000a03801982511681845116808217855250505050505090500191505060006040518083038185875af1925050503d80600081146101d6576040519150601f19603f3d011682016040523d82523d6000602084013e6101db565b606091505b5050505050565b56fea2646970667358221220b9c91ba5fa12925c1988f74e7b6cc9f8047a3a0c36f13b65773a6b608d08b17a64736f6c634300060c0033");
        let code_with_revert = hex!("608060405234801561001057600080fd5b5061021b806100206000396000f3fe6080604052600436106100295760003560e01c80639c320d0b1461002e578063a3e76c0f14610089575b600080fd5b34801561003a57600080fd5b506100876004803603604081101561005157600080fd5b81019080803573ffffffffffffffffffffffffffffffffffffffff16906020019092919080359060200190929190505050610093565b005b6100916101e3565b005b8173ffffffffffffffffffffffffffffffffffffffff16670de0b6b3a764000082604051602401808281526020019150506040516020818303038152906040527fb1d6927a000000000000000000000000000000000000000000000000000000007bffffffffffffffffffffffffffffffffffffffffffffffffffffffff19166020820180517bffffffffffffffffffffffffffffffffffffffffffffffffffffffff83818316178352505050506040518082805190602001908083835b602083106101745780518252602082019150602081019050602083039250610151565b6001836020036101000a03801982511681845116808217855250505050505090500191505060006040518083038185875af1925050503d80600081146101d6576040519150601f19603f3d011682016040523d82523d6000602084013e6101db565b606091505b505050600080fd5b56fea2646970667358221220ca731585b5955eee8418d7952d7537d5e7576a8ac5047530ddb0282f369e7f8e64736f6c634300060c0033");

        // abi encode "address _contract": "0x56454c41532D434841494e000000000053574150", "bytes32 native_recipient": "0x9b73845fe592e092a13df83a8f8485296ba9c0a28c7c0824c33b1b3b352b4043"
        let contract_take_ether_abi = hex!("9c320d0b00000000000000000000000056454c41532d434841494e0000000000535741509b73845fe592e092a13df83a8f8485296ba9c0a28c7c0824c33b1b3b352b4043");
        let _receive_tokens_abi = hex!("a3e76c0f"); // no need because we use fn deposit from vm.

        for code in [&code_without_revert[..], &code_with_revert[..]] {
            let revert = code == &code_with_revert[..];
            let mut state = evm_state::EvmBackend::default();
            let processor = EvmProcessor::default();
            let evm_account = RefCell::new(crate::create_state_account(1_000_000_000));
            let evm_keyed_account = KeyedAccount::new(&solana::evm_state::ID, false, &evm_account);
            let receiver = Pubkey::new(&hex!(
                "9b73845fe592e092a13df83a8f8485296ba9c0a28c7c0824c33b1b3b352b4043"
            ));
            let user_account = RefCell::new(solana_sdk::account::AccountSharedData::new(
                0,
                0,
                &solana_sdk::system_program::id(),
            ));
            let user_account = KeyedAccount::new(&receiver, false, &user_account);
            let keyed_accounts = [evm_keyed_account, user_account];

            let secret_key = evm::SecretKey::from_slice(&SECRET_KEY_DUMMY).unwrap();

            let tx_create = evm::UnsignedTransaction {
                nonce: 0.into(),
                gas_price: 1.into(),
                gas_limit: 300000.into(),
                action: TransactionAction::Create,
                value: 0.into(),
                input: code.to_vec(),
            };
            let tx_create = tx_create.sign(&secret_key, Some(CHAIN_ID));

            let _caller_address = tx_create.caller().unwrap();

            let tx_address = tx_create.address().unwrap();

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

            {
                let mut executor = evm_state::Executor::default_configs(state);

                executor.deposit(
                    tx_address,
                    U256::from(1_000_000_000) * U256::from(1_000_000_000),
                ); // 1ETHER

                let tx_call = evm::UnsignedTransaction {
                    nonce: 1.into(),
                    gas_price: 1.into(),
                    gas_limit: 300000.into(),
                    action: TransactionAction::Call(tx_address),
                    value: 0.into(),
                    input: contract_take_ether_abi.to_vec(),
                };

                let tx_call = tx_call.sign(&secret_key, Some(CHAIN_ID));
                let tx_hash = tx_call.tx_id_hash();

                let mut invoke_context = MockInvokeContext::with_evm(executor);

                let result = processor.process_instruction(
                    &crate::ID,
                    &keyed_accounts,
                    &bincode::serialize(&EvmInstruction::EvmTransaction { evm_tx: tx_call })
                        .unwrap(),
                    &mut invoke_context,
                    false,
                );
                if !revert {
                    result.unwrap();
                } else {
                    assert_eq!(result.unwrap_err(), EvmError::RevertTransaction.into())
                }
                println!("logs = {:?}", invoke_context.logger);
                let mut executor = invoke_context.deconstruct().unwrap();
                println!("cx = {:?}", executor);
                let tx = executor.get_tx_receipt_by_hash(tx_hash).unwrap();
                if revert {
                    println!("status = {:?}", tx.status);
                    assert!(matches!(tx.status, ExitReason::Revert(_)));
                }

                let committed = executor.deconstruct().commit_block(0, Default::default());
                state = committed.next_incomming(0);

                let lamports = keyed_accounts[1].account.borrow().lamports;
                if !revert {
                    assert_eq!(
                        state.get_account_state(tx_address).unwrap().balance,
                        0.into()
                    );
                    assert_eq!(lamports, 1_000_000_000)
                } else {
                    assert_eq!(
                        state.get_account_state(tx_address).unwrap().balance,
                        U256::from(1_000_000_000) * U256::from(1_000_000_000)
                    );
                    // assert_eq!(lamports, 0), solana runtime will revert this account
                }
            }
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

        let first_user_account = RefCell::new(solana_sdk::account::AccountSharedData {
            lamports: 1000,
            data: vec![],
            owner: solana_sdk::system_program::id(),
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
            e @ InstructionError::Custom(_) => {
                assert_eq!(e, crate::error::EvmError::MissingRequiredSignature.into())
            } // new_error_handling feature always activated at MockInvokeContext
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

        let user_account = RefCell::new(solana_sdk::account::AccountSharedData {
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

        let user_account = RefCell::new(solana_sdk::account::AccountSharedData {
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

        let user_account = RefCell::new(solana_sdk::account::AccountSharedData {
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
