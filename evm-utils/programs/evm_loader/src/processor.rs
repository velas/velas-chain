use std::cell::RefMut;
use std::fmt::Write;
use std::ops::DerefMut;

use super::account_structure::AccountStructure;
use super::instructions::{
    EvmBigTransaction, EvmInstruction, ExecuteTransaction, FeePayerType,
    EVM_INSTRUCTION_BORSH_PREFIX,
};
use super::precompiles;
use super::scope::*;
use evm_state::U256;
use log::*;

use borsh::BorshDeserialize;
use evm::{gweis_to_lamports, Executor, ExitReason};
use evm_state::ExecutionResult;
use serde::de::DeserializeOwned;
use solana_program_runtime::ic_msg;
use solana_program_runtime::invoke_context::InvokeContext;
use solana_sdk::account::{AccountSharedData, ReadableAccount, WritableAccount};
use solana_sdk::instruction::InstructionError;
use solana_sdk::{keyed_account::KeyedAccount, program_utils::limited_deserialize};

use super::error::EvmError;
use super::tx_chunks::TxChunks;

pub const BURN_ADDR: evm_state::H160 = evm_state::H160::zero();

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
        first_keyed_account: usize,
        data: &[u8],
        invoke_context: &mut InvokeContext,
    ) -> Result<(), InstructionError> {
        let (evm_state_account, keyed_accounts) =
            Self::check_evm_account(first_keyed_account, invoke_context)?;

        let cross_execution_enabled = invoke_context
            .feature_set
            .is_active(&solana_sdk::feature_set::velas::evm_cross_execution::id());
        let register_swap_tx_in_evm = invoke_context
            .feature_set
            .is_active(&solana_sdk::feature_set::velas::native_swap_in_evm_history::id());
        let new_error_handling = invoke_context
            .feature_set
            .is_active(&solana_sdk::feature_set::velas::evm_new_error_handling::id());
        let ignore_reset_on_cleared = invoke_context
            .feature_set
            .is_active(&solana_sdk::feature_set::velas::ignore_reset_on_cleared::id());
        let free_ownership_require_signer = invoke_context
            .feature_set
            .is_active(&solana_sdk::feature_set::velas::free_ownership_require_signer::id());
        let borsh_serialization_enabled = invoke_context
            .feature_set
            .is_active(&solana_sdk::feature_set::velas::evm_instruction_borsh_serialization::id());

        let cross_execution = invoke_context.get_stack_height() != 1;

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

        let mut borsh_serialization_used = false;
        let ix = match (borsh_serialization_enabled, data.split_first()) {
            (true, Some((&prefix, borsh_data))) if prefix == EVM_INSTRUCTION_BORSH_PREFIX => {
                borsh_serialization_used = true;
                BorshDeserialize::deserialize(&mut &*borsh_data)
                    .map_err(|_| InstructionError::InvalidInstructionData)?
            }
            _ => limited_deserialize(data)?,
        };
        trace!("Run evm exec with ix = {:?}.", ix);
        let result = match ix {
            EvmInstruction::EvmBigTransaction(big_tx) => {
                self.process_big_tx(invoke_context, accounts, big_tx)
            }
            EvmInstruction::FreeOwnership {} => self.process_free_ownership(
                executor,
                invoke_context,
                accounts,
                free_ownership_require_signer,
            ),
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
            ),
            EvmInstruction::ExecuteTransaction { tx, fee_type } => self.process_execute_tx(
                executor,
                invoke_context,
                accounts,
                tx,
                fee_type,
                borsh_serialization_used,
            ),
        };

        if register_swap_tx_in_evm {
            executor.reset_balance(*precompiles::ETH_TO_VLX_ADDR, ignore_reset_on_cleared)
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

    fn process_execute_tx(
        &self,
        executor: &mut Executor,
        invoke_context: &InvokeContext,
        accounts: AccountStructure,
        tx: ExecuteTransaction,
        fee_type: FeePayerType,
        borsh_used: bool,
    ) -> Result<(), EvmError> {
        let is_big = tx.is_big();
        let keep_old_errors = true;
        // TODO: Add logic for fee collector
        let (sender, _fee_collector) = if is_big {
            (accounts.users.get(1), accounts.users.get(2))
        } else {
            (accounts.first(), accounts.users.get(1))
        };

        // FeePayerType::Native is possible only in new serialization format
        if fee_type.is_native() && sender.is_none() {
            ic_msg!(invoke_context, "Fee payer is native but no sender providen",);
            return Err(EvmError::MissingRequiredSignature);
        }

        fn precompile_set(
            support_precompile: bool,
            evm_new_precompiles: bool,
        ) -> precompiles::PrecompileSet {
            match (support_precompile, evm_new_precompiles) {
                (false, _) => precompiles::PrecompileSet::No,
                (true, false) => precompiles::PrecompileSet::VelasClassic,
                (true, true) => precompiles::PrecompileSet::VelasNext,
            }
        }

        let withdraw_fee_from_evm = fee_type.is_evm();
        let mut tx_gas_price;
        let result = match tx {
            ExecuteTransaction::Signed { tx } => {
                let tx = match tx {
                    Some(tx) => tx,
                    None => Self::get_tx_from_storage(invoke_context, accounts, borsh_used)?,
                };
                ic_msg!(
                    invoke_context,
                    "Executing transaction: gas_limit:{}, gas_price:{}, value:{}, action:{:?},",
                    tx.gas_limit,
                    tx.gas_price,
                    tx.value,
                    tx.action
                );
                tx_gas_price = tx.gas_price;
                let activate_precompile = precompile_set(
                    executor.support_precompile(),
                    invoke_context
                        .feature_set
                        .is_active(&solana_sdk::feature_set::velas::evm_new_precompiles::id()),
                );
                executor.transaction_execute(
                    tx,
                    withdraw_fee_from_evm,
                    precompiles::entrypoint(accounts, activate_precompile, keep_old_errors),
                )
            }
            ExecuteTransaction::ProgramAuthorized { tx, from } => {
                let program_account = sender.ok_or_else(|| {
                    ic_msg!(
                        invoke_context,
                        "Not enough accounts, expected signer address as second account."
                    );
                    EvmError::MissingAccount
                })?;
                Self::check_program_account(
                    invoke_context,
                    program_account,
                    from,
                    executor.feature_set.is_unsigned_tx_fix_enabled(),
                )?;
                let tx = match tx {
                    Some(tx) => tx,
                    None => Self::get_tx_from_storage(invoke_context, accounts, borsh_used)?,
                };
                ic_msg!(
                    invoke_context,
                    "Executing authorized transaction: gas_limit:{}, gas_price:{}, value:{}, action:{:?},",
                    tx.gas_limit,
                    tx.gas_price,
                    tx.value,
                    tx.action
                );
                tx_gas_price = tx.gas_price;
                let activate_precompile = precompile_set(
                    executor.support_precompile(),
                    invoke_context
                        .feature_set
                        .is_active(&solana_sdk::feature_set::velas::evm_new_precompiles::id()),
                );
                executor.transaction_execute_unsinged(
                    from,
                    tx,
                    withdraw_fee_from_evm,
                    precompiles::entrypoint(accounts, activate_precompile, keep_old_errors),
                )
            }
        };

        if executor.feature_set.is_unsigned_tx_fix_enabled() && is_big {
            let storage = Self::get_big_transaction_storage(invoke_context, &accounts)?;
            self.cleanup_storage(invoke_context, storage, sender.unwrap_or(accounts.evm))?;
        }
        if executor
            .feature_set
            .is_accept_zero_gas_price_with_native_fee_enabled()
            && fee_type.is_native()
            && tx_gas_price.is_zero()
        {
            tx_gas_price = executor.config().burn_gas_price;
        }
        self.handle_transaction_result(
            executor,
            invoke_context,
            accounts,
            sender,
            tx_gas_price,
            result,
            withdraw_fee_from_evm,
        )
    }

    fn process_free_ownership(
        &self,
        _executor: &mut Executor,
        invoke_context: &InvokeContext,
        accounts: AccountStructure,
        free_ownership_require_signer: bool,
    ) -> Result<(), EvmError> {
        let user = accounts.first().ok_or_else(|| {
            ic_msg!(
                invoke_context,
                "FreeOwnership: expected account as argument."
            );
            EvmError::MissingAccount
        })?;
        if free_ownership_require_signer && user.signer_key().is_none() {
            ic_msg!(invoke_context, "FreeOwnership: Missing signer key.");
            return Err(EvmError::MissingRequiredSignature);
        }

        let user_pk = user.unsigned_key();
        let mut user = user
            .try_account_ref_mut()
            .map_err(|_| EvmError::BorrowingFailed)?;

        if *user.owner() != crate::ID || *user_pk == solana::evm_state::ID {
            ic_msg!(
                invoke_context,
                "FreeOwnership: Incorrect account provided, maybe this account is not owned by evm."
            );
            return Err(EvmError::FreeNotEvmAccount);
        }
        user.set_owner(solana_sdk::system_program::id());
        Ok(())
    }

    fn process_swap_to_evm(
        &self,
        executor: &mut Executor,
        invoke_context: &InvokeContext,
        accounts: AccountStructure,
        lamports: u64,
        evm_address: evm::Address,
        register_swap_tx_in_evm: bool,
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
            "SwapNativeToEther: Sending tokens from native to evm chain from={},to={:?}",
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
        if lamports > user_account.lamports() {
            ic_msg!(
                invoke_context,
                "SwapNativeToEther: insufficient lamports ({}, need {})",
                user_account.lamports(),
                lamports
            );
            return Err(EvmError::SwapInsufficient);
        }

        let user_account_lamports = user_account.lamports().saturating_sub(lamports);
        user_account.set_lamports(user_account_lamports);
        let mut evm_account = accounts
            .evm
            .try_account_ref_mut()
            .map_err(|_| EvmError::BorrowingFailed)?;

        let evm_account_lamports = evm_account.lamports().saturating_add(lamports);
        evm_account.set_lamports(evm_account_lamports);
        executor.deposit(evm_address, gweis);
        if register_swap_tx_in_evm {
            executor.register_swap_tx_in_evm(*precompiles::ETH_TO_VLX_ADDR, evm_address, gweis)
        }
        Ok(())
    }

    fn process_big_tx(
        &self,
        invoke_context: &InvokeContext,
        accounts: AccountStructure,
        big_tx: EvmBigTransaction,
    ) -> Result<(), EvmError> {
        debug!("executing big_tx = {:?}", big_tx);

        let mut storage = Self::get_big_transaction_storage(invoke_context, &accounts)?;
        let mut tx_chunks = TxChunks::new(storage.data_as_mut_slice());

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
        }
    }

    pub fn cleanup_storage<'a>(
        &self,
        invoke_context: &InvokeContext,
        mut storage_ref: RefMut<AccountSharedData>,
        user: &'a KeyedAccount<'a>,
    ) -> Result<(), EvmError> {
        let balance = storage_ref.lamports();

        storage_ref.set_lamports(0);

        let mut user_acc = user
            .try_account_ref_mut()
            .map_err(|_| EvmError::BorrowingFailed)?;
        let user_acc_lamports = user_acc.lamports().saturating_add(balance);
        user_acc.set_lamports(user_acc_lamports);

        ic_msg!(
            invoke_context,
            "Refunding storage rent fee to transaction sender fee:{:?}, sender:{}",
            balance,
            user.unsigned_key()
        );
        Ok(())
    }

    fn check_program_account(
        invoke_context: &InvokeContext,
        program_account: &KeyedAccount,
        from: evm::Address,
        unsigned_tx_fix: bool,
    ) -> Result<(), EvmError> {
        let key = program_account.signer_key().ok_or_else(|| {
            ic_msg!(
                invoke_context,
                "Second account is not a signer, cannot execute transaction."
            );
            EvmError::MissingRequiredSignature
        })?;
        let from_expected = crate::evm_address_for_program(*key);
        if from_expected != from {
            ic_msg!(
                invoke_context,
                "From is not calculated with evm_address_for_program."
            );
            return Err(EvmError::AuthorizedTransactionIncorrectAddress);
        }

        if unsigned_tx_fix {
            let program_caller = invoke_context
                .get_parent_caller()
                .copied()
                .unwrap_or_default();
            let program_owner = *program_account
                .try_account_ref()
                .map_err(|_| EvmError::BorrowingFailed)?
                .owner();
            if program_owner != program_caller {
                ic_msg!(
                    invoke_context,
                    "Incorrect caller program_caller:{}, program_owner:{}",
                    program_caller,
                    program_owner,
                );
                return Err(EvmError::AuthorizedTransactionIncorrectOwner);
            }
        }
        Ok(())
    }

    fn get_tx_from_storage<T>(
        invoke_context: &InvokeContext,
        accounts: AccountStructure,
        deserialize_chunks_with_borsh: bool,
    ) -> Result<T, EvmError>
    where
        T: BorshDeserialize + DeserializeOwned,
    {
        let mut storage = Self::get_big_transaction_storage(invoke_context, &accounts)?;
        let tx_chunks = TxChunks::new(storage.data_mut().as_mut_slice());
        debug!("Tx chunks crc = {:#x}", tx_chunks.crc());

        let bytes = tx_chunks.take();
        debug!("Trying to deserialize tx chunks byte = {:?}", bytes);
        if deserialize_chunks_with_borsh {
            BorshDeserialize::deserialize(&mut bytes.as_slice()).map_err(|e| {
                ic_msg!(invoke_context, "Tx chunks deserialize error: {:?}", e);
                EvmError::DeserializationError
            })
        } else {
            bincode::deserialize(&bytes).map_err(|e| {
                ic_msg!(invoke_context, "Tx chunks deserialize error: {:?}", e);
                EvmError::DeserializationError
            })
        }
    }

    fn get_big_transaction_storage<'a>(
        invoke_context: &InvokeContext,
        accounts: &'a AccountStructure,
    ) -> Result<RefMut<'a, AccountSharedData>, EvmError> {
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
        storage_account
            .try_account_ref_mut()
            .map_err(|_| EvmError::BorrowingFailed)
    }

    /// Calculate fee based on transaction result and charge native account
    pub fn charge_native_account(
        tx_result: &ExecutionResult,
        fee: U256,
        native_account: &KeyedAccount,
        evm_account: &KeyedAccount,
    ) -> Result<(), EvmError> {
        // Charge only when transaction succeeded
        if matches!(tx_result.exit_reason, ExitReason::Succeed(_)) {
            let (fee, _) = gweis_to_lamports(fee);

            trace!("Charging account for fee {}", fee);
            let mut account_data = native_account
                .try_account_ref_mut()
                .map_err(|_| EvmError::BorrowingFailed)?;
            let new_lamports = account_data
                .lamports()
                .checked_sub(fee)
                .ok_or(EvmError::NativeAccountInsufficientFunds)?;
            account_data.set_lamports(new_lamports);

            let mut evm_account = evm_account
                .try_account_ref_mut()
                .map_err(|_| EvmError::BorrowingFailed)?;
            let new_evm_lamports = evm_account
                .lamports()
                .checked_add(fee)
                .ok_or(EvmError::OverflowInRefund)?;
            evm_account.set_lamports(new_evm_lamports);
        }
        Ok(())
    }

    // Handle executor errors.
    // refund fee
    pub fn handle_transaction_result(
        &self,
        executor: &mut Executor,
        invoke_context: &InvokeContext,
        accounts: AccountStructure,
        sender: Option<&KeyedAccount>,
        tx_gas_price: evm_state::U256,
        result: Result<evm_state::ExecutionResult, evm_state::error::Error>,
        withdraw_fee_from_evm: bool,
    ) -> Result<(), EvmError> {
        let remove_native_logs_after_swap = true;
        let mut result = result.map_err(|e| {
            ic_msg!(invoke_context, "Transaction execution error: {}", e);
            EvmError::InternalExecutorError
        })?;

        if remove_native_logs_after_swap {
            executor.modify_tx_logs(result.tx_id, |logs| {
                if let Some(logs) = logs {
                    precompiles::filter_native_logs(accounts, logs).map_err(|e| {
                        ic_msg!(invoke_context, "Filter native logs error: {}", e);
                        EvmError::PrecompileError
                    })?;
                } else {
                    ic_msg!(invoke_context, "Unable to find tx by txid");
                    return Err(EvmError::PrecompileError);
                }
                Ok(())
            })?;
        } else {
            // same logic, but don't save result to block
            precompiles::filter_native_logs(accounts, &mut result.tx_logs).map_err(|e| {
                ic_msg!(invoke_context, "Filter native logs error: {}", e);
                EvmError::PrecompileError
            })?;
        }

        write!(
            crate::solana_extension::MultilineLogger::new(invoke_context.get_log_collector()),
            "{}",
            result
        )
        .expect("no error during writes");
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

        let full_fee = tx_gas_price * result.used_gas;

        let burn_fee = executor.config().burn_gas_price * result.used_gas;

        if full_fee < burn_fee {
            ic_msg!(
                invoke_context,
                "Transaction execution error: fee less than need to burn (burn_gas_price = {})",
                executor.config().burn_gas_price
            );
            return Err(EvmError::OverflowInRefund);
        }

        // refund only remaining part
        let refund_fee = full_fee - burn_fee;
        let (refund_native_fee, _) = gweis_to_lamports(refund_fee);

        // 1. Fee can be charged from evm account or native. (evm part is done in Executor::transaction_execute* methods.)
        if !withdraw_fee_from_evm {
            let sender = sender.as_ref().ok_or(EvmError::MissingRequiredSignature)?;
            Self::charge_native_account(&result, full_fee, sender, accounts.evm)?;
        }

        // 2. Then we should burn some part of it.
        // This if only register burn to the deposit address, withdrawal is done in 1.
        if burn_fee > U256::zero() {
            trace!("Burning fee {}", burn_fee);
            // we already withdraw gas_price during transaction_execute,
            // if burn_fixed_fee is activated, we should deposit to burn addr (0x00..00)
            executor.deposit(BURN_ADDR, burn_fee);
        };

        // 3. And transfer back remaining fee to the bridge as refund of native fee that was used to wrap this transaction.
        if let Some(payer) = sender {
            ic_msg!(
                invoke_context,
                "Refunding transaction fee to transaction sender fee:{:?}, sender:{}",
                refund_native_fee,
                payer.unsigned_key()
            );
            accounts.refund_fee(payer, refund_native_fee)?;
        } else {
            ic_msg!(
                invoke_context,
                "Sender didnt give his account, ignoring fee refund.",
            );
        }

        Ok(())
    }

    /// Ensure that first account is program itself, and it's locked for writes.
    fn check_evm_account<'a>(
        first_keyed_account: usize,
        invoke_context: &'a InvokeContext,
    ) -> Result<(&'a KeyedAccount<'a>, &'a [KeyedAccount<'a>]), InstructionError> {
        let keyed_accounts = invoke_context.get_keyed_accounts()?;
        let first = keyed_accounts
            .get(first_keyed_account)
            .ok_or(InstructionError::NotEnoughAccountKeys)?;

        trace!("first = {:?}", first);
        trace!("all = {:?}", keyed_accounts);
        if first.unsigned_key() != &solana::evm_state::id() || !first.is_writable() {
            debug!("First account is not evm, or not writable");
            return Err(InstructionError::MissingAccount);
        }

        let keyed_accounts = &keyed_accounts[(first_keyed_account + 1)..];
        Ok((first, keyed_accounts))
    }
}

const SECRET_KEY_DUMMY: [u8; 32] = [1; 32];

const TEST_CHAIN_ID: u64 = 0xdead;
#[doc(hidden)]
pub fn dummy_call(nonce: usize) -> (evm::Transaction, evm::UnsignedTransaction) {
    let secret_key = evm::SecretKey::from_slice(&SECRET_KEY_DUMMY).unwrap();
    let dummy_address = evm::addr_from_public_key(&evm::PublicKey::from_secret_key(
        evm::SECP256K1,
        &secret_key,
    ));

    let tx_call = evm::UnsignedTransaction {
        nonce: nonce.into(),
        gas_price: 1u32.into(),
        gas_limit: 300000u32.into(),
        action: evm::TransactionAction::Call(dummy_address),
        value: 0u32.into(),
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
        AccountState, FromKey,
    };
    use evm_state::{AccountProvider, ExitReason, ExitSucceed};
    use hex_literal::hex;
    use num_traits::Zero;
    use primitive_types::{H160, H256, U256};
    use solana_program_runtime::{
        invoke_context::{BuiltinProgram, InvokeContext},
        timings::ExecuteTimings,
    };
    use solana_sdk::sysvar::rent::Rent;
    use solana_sdk::{instruction::CompiledInstruction, pubkey::Pubkey};
    use solana_sdk::{
        instruction::{AccountMeta, Instruction},
        message::{Message, SanitizedMessage},
    };
    use solana_sdk::{native_loader, transaction_context::TransactionContext};
    use solana_sdk::{program_utils::limited_deserialize, transaction_context::InstructionAccount};
    type MutableAccount = AccountSharedData;

    use super::TEST_CHAIN_ID as CHAIN_ID;
    use borsh::BorshSerialize;
    use std::rc::Rc;
    use std::sync::Arc;
    use std::{
        cell::RefCell,
        collections::{BTreeMap, BTreeSet},
    };

    // Testing object that emulate Bank work, and can execute transactions.
    // Emulate batch of native transactions.
    #[derive(Debug, Clone)]
    struct EvmMockContext {
        evm_state: evm_state::EvmBackend<evm_state::Incomming>,
        evm_state_account: AccountSharedData,
        evm_program_account: AccountSharedData,
        rest_accounts: BTreeMap<Pubkey, MutableAccount>,
        feature_set: solana_sdk::feature_set::FeatureSet,
    }

    impl EvmMockContext {
        fn new(evm_balance: u64) -> Self {
            let _logger = simple_logger::SimpleLogger::new()
                .with_utc_timestamps()
                .init();
            Self {
                evm_state: evm_state::EvmBackend::default(),
                evm_state_account: crate::create_state_account(evm_balance),
                evm_program_account: AccountSharedData::new(1, 0, &native_loader::ID),
                rest_accounts: Default::default(),
                feature_set: solana_sdk::feature_set::FeatureSet::all_enabled(),
            }
        }

        fn disable_feature(&mut self, pubkey: &Pubkey) {
            self.feature_set.deactivate(pubkey);
        }

        fn native_account(&mut self, pubkey: Pubkey) -> &mut AccountSharedData {
            if pubkey == solana::evm_state::id() {
                &mut self.evm_state_account
            } else if pubkey == crate::ID {
                &mut self.evm_program_account
            } else {
                let entry = self.rest_accounts.entry(pubkey).or_default();
                entry
            }
        }

        fn native_account_cloned(&mut self, pubkey: Pubkey) -> AccountSharedData {
            self.native_account(pubkey).clone()
        }

        fn process_instruction(&mut self, ix: Instruction) -> Result<(), InstructionError> {
            self.process_transaction(vec![ix])
        }

        fn deposit_evm(&mut self, evm_addr: evm_state::Address, amount: evm_state::U256) {
            let mut account_state = self
                .evm_state
                .get_account_state(evm_addr)
                .unwrap_or_default();
            account_state.balance += amount;
            self.evm_state.set_account_state(evm_addr, account_state)
        }

        // Emulate native transaction
        fn process_transaction(&mut self, ixs: Vec<Instruction>) -> Result<(), InstructionError> {
            let evm_state_clone = self.evm_state.clone();
            let evm_executor = evm_state::Executor::with_config(
                evm_state_clone,
                Default::default(),
                evm::EvmConfig::new(
                    evm::TEST_CHAIN_ID,
                    self.feature_set
                        .is_active(&solana_sdk::feature_set::velas::burn_fee::id()),
                ),
                evm_state::executor::FeatureSet::new(
                    self.feature_set
                        .is_active(&solana_sdk::feature_set::velas::unsigned_tx_fix::id()),
                    self.feature_set
                        .is_active(&solana_sdk::feature_set::velas::clear_logs_on_error::id()),
                    self.feature_set.is_active(
                        &solana_sdk::feature_set::velas::accept_zero_gas_price_with_native_fee::id(
                        ),
                    ),
                ),
            );

            let evm_program = BuiltinProgram {
                program_id: solana_sdk::evm_loader::id(),
                process_instruction: |acc, data, context| {
                    let processor = EvmProcessor::default();
                    processor.process_instruction(acc, data, context)
                },
            };
            let builtins = &[evm_program];
            let mut accs = vec![(crate::ID, self.native_account_cloned(crate::ID))];
            let mut keys = vec![crate::ID];
            for ix in &ixs {
                for acc in ix.accounts.clone() {
                    accs.push((acc.pubkey, self.native_account_cloned(acc.pubkey)));
                    keys.push(acc.pubkey);
                }
            }
            // keys.dedup();

            let mut transaction_context = TransactionContext::new(accs, ixs.len(), ixs.len());
            let mut invoke_context =
                InvokeContext::new_mock_evm(&mut transaction_context, builtins, evm_executor);
            invoke_context.feature_set = Arc::new(self.feature_set.clone());

            let program_index = keys
                .iter()
                .position(|k: &Pubkey| *k == crate::ID)
                .unwrap_or(keys.len());

            for instruction in ixs {
                let mut accounts = instruction.accounts.clone();

                dbg!(&instruction.accounts);
                // accounts.remove(program_index);
                let program_indices = vec![program_index];

                dbg!(&program_indices);
                let instruction_accounts = accounts
                    .iter()
                    .map(|acc| {
                        let index_in_transaction =
                            keys.iter().position(|k| *k == acc.pubkey).unwrap();
                        InstructionAccount {
                            index_in_transaction,
                            index_in_caller: index_in_transaction,
                            is_signer: acc.is_signer,
                            is_writable: acc.is_writable,
                        }
                    })
                    .collect::<Vec<_>>();

                dbg!(&instruction_accounts);
                let mut compute_units_consumed = 0;
                if let Err(e) = invoke_context.process_instruction(
                    &instruction.data,
                    &instruction_accounts,
                    &program_indices,
                    &mut compute_units_consumed,
                    &mut ExecuteTimings::default(),
                ) {
                    dbg!(&e);
                    let executor = invoke_context
                        .deconstruct_evm()
                        .expect("Evm executor should exist");
                    let clear_logs = self.feature_set.is_active(
                        &solana_sdk::feature_set::velas::clear_logs_on_native_error::id(),
                    );
                    self.evm_state
                        .apply_failed_update(&executor.evm_backend, clear_logs);
                    return Err(e);
                }
            }

            // invoke context will apply native accounts chages, but evm should be applied manually.
            let executor = invoke_context
                .deconstruct_evm()
                .expect("Evm executor should exist");
            self.evm_state = executor.evm_backend;
            let (accs, _contexts) = transaction_context.deconstruct();
            for acc in accs {
                *self.native_account(acc.0) = acc.1
            }
            Ok(())
        }
    }

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
        {
            let sol_ix = EvmInstruction::new_execute_tx(tx.clone(), FeePayerType::Evm);
            let ser = bincode::serialize(&sol_ix).unwrap();
            assert_eq!(sol_ix, limited_deserialize(&ser).unwrap());
        }
        {
            let sol_ix = EvmInstruction::new_execute_authorized_tx(
                tx.clone().into(),
                H160::zero(),
                FeePayerType::Evm,
            );
            let ser = bincode::serialize(&sol_ix).unwrap();
            assert_eq!(sol_ix, limited_deserialize(&ser).unwrap());
        }
        {
            let sol_ix = EvmInstruction::SwapNativeToEther {
                lamports: 0,
                evm_address: H160::zero(),
            };
            let ser = bincode::serialize(&sol_ix).unwrap();
            assert_eq!(sol_ix, limited_deserialize(&ser).unwrap());
        }
        {
            let sol_ix = EvmInstruction::FreeOwnership {};
            let ser = bincode::serialize(&sol_ix).unwrap();
            assert_eq!(sol_ix, limited_deserialize(&ser).unwrap());
        }
    }

    #[test]
    fn execute_tx() {
        let mut evm_context = EvmMockContext::new(0);
        evm_context.disable_feature(&solana_sdk::feature_set::velas::burn_fee::id());
        let secret_key = evm::SecretKey::from_slice(&SECRET_KEY_DUMMY).unwrap();

        let address = secret_key.to_address();
        evm_context.deposit_evm(address, U256::from(2u32) * 300000u32);
        let tx_create = evm::UnsignedTransaction {
            nonce: 0u32.into(),
            gas_price: 1u32.into(),
            gas_limit: 300000u32.into(),
            action: TransactionAction::Create,
            value: 0u32.into(),
            input: hex::decode(evm_state::HELLO_WORLD_CODE).unwrap().to_vec(),
        };
        let tx_create = tx_create.sign(&secret_key, Some(CHAIN_ID));

        assert!(evm_context
            .process_instruction(crate::send_raw_tx(
                Pubkey::new_unique(),
                tx_create.clone(),
                None,
                FeePayerType::Evm
            ))
            .is_ok());
        let tx_address = tx_create.address().unwrap();
        let tx_call = evm::UnsignedTransaction {
            nonce: 1u32.into(),
            gas_price: 1u32.into(),
            gas_limit: 300000u32.into(),
            action: TransactionAction::Call(tx_address),
            value: 0u32.into(),
            input: hex::decode(evm_state::HELLO_WORLD_ABI).unwrap().to_vec(),
        };

        let tx_call = tx_call.sign(&secret_key, Some(CHAIN_ID));
        let tx_hash = tx_call.tx_id_hash();

        assert!(evm_context
            .process_instruction(crate::send_raw_tx(
                Pubkey::new_unique(),
                tx_call,
                None,
                FeePayerType::Evm
            ))
            .is_ok());
        assert!(evm_context
            .evm_state
            .find_transaction_receipt(tx_hash)
            .is_some())
    }

    #[test]
    fn test_big_authorized_tx_execution() {
        let _logger = simple_logger::SimpleLogger::new()
            .env()
            .with_utc_timestamps()
            .init();
        let mut evm_context = EvmMockContext::new(0);
        evm_context.disable_feature(&solana_sdk::feature_set::velas::burn_fee::id());

        let user_id = Pubkey::new_unique();
        let program_id = Pubkey::new_unique();
        let from = crate::evm_address_for_program(program_id);
        evm_context.deposit_evm(from, U256::from(2) * 300000);
        let tx_create = evm::UnsignedTransaction {
            nonce: 0.into(),
            gas_price: 1.into(),
            gas_limit: 300000.into(),
            action: TransactionAction::Create,
            value: 0.into(),
            input: hex::decode(evm_state::HELLO_WORLD_CODE).unwrap().to_vec(),
        };
        let mut tx_bytes = vec![];
        BorshSerialize::serialize(&tx_create, &mut tx_bytes).unwrap();

        let acc = evm_context.native_account(user_id);
        acc.set_lamports(0);
        acc.set_data(vec![0; tx_bytes.len()]);
        acc.set_owner(crate::ID);

        let acc = evm_context.native_account(program_id);
        acc.set_lamports(1000);

        let big_tx_alloc = crate::big_tx_allocate(user_id, tx_bytes.len());
        evm_context.process_instruction(big_tx_alloc).unwrap();

        let big_tx_write = crate::big_tx_write(user_id, 0, tx_bytes);

        evm_context.process_instruction(big_tx_write).unwrap();

        let big_tx_execute =
            crate::big_tx_execute_authorized(user_id, from, program_id, FeePayerType::Native);

        assert!(evm_context.process_instruction(big_tx_execute).is_ok());
    }

    #[test]
    fn deploy_tx_refund_fee() {
        let init_evm_balance = 1000000;
        let mut evm_context = EvmMockContext::new(init_evm_balance);
        evm_context.disable_feature(&solana_sdk::feature_set::velas::burn_fee::id());
        let user_id = Pubkey::new_unique();
        evm_context.native_account(user_id).set_owner(crate::ID);

        let secret_key = evm::SecretKey::from_slice(&SECRET_KEY_DUMMY).unwrap();

        let address = secret_key.to_address();
        evm_context.deposit_evm(
            address,
            U256::from(crate::evm::LAMPORTS_TO_GWEI_PRICE) * 300000u32,
        );
        let tx_create = evm::UnsignedTransaction {
            nonce: 0u32.into(),
            gas_price: crate::evm::LAMPORTS_TO_GWEI_PRICE.into(),
            gas_limit: 300000u32.into(),
            action: TransactionAction::Create,
            value: 0u32.into(),
            input: hex::decode(evm_state::HELLO_WORLD_CODE).unwrap().to_vec(),
        };
        let tx_create = tx_create.sign(&secret_key, Some(CHAIN_ID));
        assert!(evm_context
            .process_instruction(crate::send_raw_tx(
                user_id,
                tx_create,
                None,
                FeePayerType::Evm
            ))
            .is_ok());
        let used_gas_for_hello_world_deploy = 114985;
        let fee = used_gas_for_hello_world_deploy; // price is 1lamport
        assert_eq!(evm_context.native_account(user_id).lamports(), fee);
        assert_eq!(
            evm_context
                .native_account(solana::evm_state::id())
                .lamports(),
            init_evm_balance + 1 // evm balance is always has 1 lamports reserve, because it is system account
                             - fee
        );
    }

    #[test]
    fn tx_preserve_nonce() {
        let mut evm_context = EvmMockContext::new(0);
        evm_context.disable_feature(&solana_sdk::feature_set::velas::burn_fee::id());
        let secret_key = evm::SecretKey::from_slice(&SECRET_KEY_DUMMY).unwrap();
        let address = secret_key.to_address();
        evm_context.deposit_evm(address, U256::from(2u32) * 300000u32);
        let burn_addr = H160::zero();
        let tx_0 = evm::UnsignedTransaction {
            nonce: 0u32.into(),
            gas_price: 1u32.into(),
            gas_limit: 300000u32.into(),
            action: TransactionAction::Call(burn_addr),
            value: 0u32.into(),
            input: vec![],
        };
        let tx_0_sign = tx_0.clone().sign(&secret_key, Some(CHAIN_ID));
        let mut tx_1 = tx_0.clone();
        tx_1.nonce += 1u32.into();
        let tx_1_sign = tx_1.sign(&secret_key, Some(CHAIN_ID));

        let mut tx_0_shadow = tx_0.clone();
        tx_0_shadow.input = vec![1];

        let tx_0_shadow_sign = tx_0.sign(&secret_key, Some(CHAIN_ID));

        // Execute of second tx before first should fail.
        assert!(evm_context
            .process_instruction(crate::send_raw_tx(
                Pubkey::new_unique(),
                tx_1_sign.clone(),
                None,
                FeePayerType::Evm
            ))
            .is_err());

        // First tx should execute successfully.

        assert!(evm_context
            .process_instruction(crate::send_raw_tx(
                Pubkey::new_unique(),
                tx_0_sign.clone(),
                None,
                FeePayerType::Evm
            ))
            .is_ok());

        // Executing copy of first tx with different signature, should not pass too.
        assert!(evm_context
            .process_instruction(crate::send_raw_tx(
                Pubkey::new_unique(),
                tx_0_shadow_sign.clone(),
                None,
                FeePayerType::Evm
            ))
            .is_err());

        // But executing of second tx now should succeed.
        assert!(evm_context
            .process_instruction(crate::send_raw_tx(
                Pubkey::new_unique(),
                tx_1_sign.clone(),
                None,
                FeePayerType::Evm
            ))
            .is_ok());
    }

    #[test]
    fn tx_preserve_gas() {
        let mut evm_context = EvmMockContext::new(0);
        let secret_key = evm::SecretKey::from_slice(&SECRET_KEY_DUMMY).unwrap();
        let address = secret_key.to_address();
        evm_context.deposit_evm(address, U256::from(1u32));
        let burn_addr = H160::zero();
        let tx_0 = evm::UnsignedTransaction {
            nonce: 0u32.into(),
            gas_price: 1u32.into(),
            gas_limit: 300000u32.into(),
            action: TransactionAction::Call(burn_addr),
            value: 0u32.into(),
            input: vec![],
        };
        let tx_0_sign = tx_0.sign(&secret_key, Some(CHAIN_ID));

        // Transaction should fail because can't pay the bill.
        assert!(evm_context
            .process_instruction(crate::send_raw_tx(
                Pubkey::new_unique(),
                tx_0_sign,
                None,
                FeePayerType::Evm
            ))
            .is_err());
    }

    #[test]
    fn execute_tx_with_state_apply() {
        let mut evm_context = EvmMockContext::new(0);
        evm_context.disable_feature(&solana_sdk::feature_set::velas::burn_fee::id());

        let secret_key = evm::SecretKey::from_slice(&SECRET_KEY_DUMMY).unwrap();

        let tx_create = evm::UnsignedTransaction {
            nonce: 0u32.into(),
            gas_price: 1u32.into(),
            gas_limit: 300000u32.into(),
            action: TransactionAction::Create,
            value: 0u32.into(),
            input: hex::decode(evm_state::HELLO_WORLD_CODE).unwrap().to_vec(),
        };

        let tx_create = tx_create.sign(&secret_key, Some(CHAIN_ID));

        let caller_address = tx_create.caller().unwrap();
        let tx_address = tx_create.address().unwrap();

        assert_eq!(
            evm_context
                .evm_state
                .get_account_state(caller_address)
                .map(|account| account.nonce),
            None,
        );
        assert_eq!(
            evm_context
                .evm_state
                .get_account_state(tx_address)
                .map(|account| account.nonce),
            None,
        );
        {
            let address = secret_key.to_address();
            evm_context.deposit_evm(address, U256::from(2u32) * 300000u32);

            assert!(evm_context
                .process_instruction(crate::send_raw_tx(
                    Pubkey::new_unique(),
                    tx_create,
                    None,
                    FeePayerType::Evm
                ))
                .is_ok());
        }

        assert_eq!(
            evm_context
                .evm_state
                .get_account_state(caller_address)
                .map(|account| account.nonce),
            Some(1u32.into())
        );
        assert_eq!(
            evm_context
                .evm_state
                .get_account_state(tx_address)
                .map(|account| account.nonce),
            Some(1u32.into())
        );

        let tx_call = evm::UnsignedTransaction {
            nonce: 1u32.into(),
            gas_price: 1u32.into(),
            gas_limit: 300000u32.into(),
            action: TransactionAction::Call(tx_address),
            value: 0u32.into(),
            input: hex::decode(evm_state::HELLO_WORLD_ABI).unwrap().to_vec(),
        };

        let tx_call = tx_call.sign(&secret_key, Some(CHAIN_ID));
        let tx_hash = tx_call.tx_id_hash();
        {
            let address = secret_key.to_address();
            evm_context.deposit_evm(address, U256::from(2u32) * 300000u32);

            assert!(evm_context
                .process_instruction(crate::send_raw_tx(
                    Pubkey::new_unique(),
                    tx_call,
                    None,
                    FeePayerType::Evm
                ))
                .is_ok());

            let committed = evm_context.evm_state.commit_block(0, Default::default());

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
        let mut evm_context = EvmMockContext::new(0);

        let user_id = Pubkey::new_unique();
        let acc = evm_context.native_account(user_id);
        acc.set_owner(crate::ID);
        acc.set_lamports(1000);

        let ether_dummy_address = H160::repeat_byte(0x11);

        let lamports_before = evm_context
            .native_account(solana::evm_state::id())
            .lamports();

        assert!(evm_context
            .process_instruction(crate::transfer_native_to_evm(
                user_id,
                1000,
                ether_dummy_address
            ))
            .is_ok());

        assert_eq!(
            evm_context
                .native_account(solana::evm_state::id())
                .lamports(),
            lamports_before + 1000
        );
        assert_eq!(evm_context.native_account(user_id).lamports(), 0);
        assert!(evm_context
            .process_instruction(crate::free_ownership(user_id))
            .is_ok());
        assert_eq!(
            *evm_context.native_account(user_id).owner(),
            solana_sdk::system_program::id()
        );

        assert_eq!(
            evm_context
                .evm_state
                .get_account_state(ether_dummy_address)
                .unwrap()
                .balance,
            crate::scope::evm::lamports_to_gwei(1000)
        )
    }

    #[test]
    fn execute_transfer_to_native_without_needed_account() {
        let mut evm_context = EvmMockContext::new(0);

        let user_id = Pubkey::new_unique();
        let acc = evm_context.native_account(user_id);
        acc.set_owner(crate::ID);
        acc.set_lamports(1000);

        let mut rand = evm_state::rand::thread_rng();
        let ether_sc = evm::SecretKey::new(&mut rand);
        let ether_dummy_address = ether_sc.to_address();

        let lamports_before = evm_context
            .native_account(solana::evm_state::id())
            .lamports();

        let lamports_to_send = 1000;
        let lamports_to_send_back = 300;

        assert!(evm_context
            .process_instruction(crate::transfer_native_to_evm(
                user_id,
                lamports_to_send,
                ether_dummy_address
            ))
            .is_ok());

        assert_eq!(
            evm_context
                .native_account(solana::evm_state::id())
                .lamports(),
            lamports_before + lamports_to_send
        );
        assert_eq!(evm_context.native_account(user_id).lamports(), 0);
        assert!(evm_context
            .process_instruction(crate::free_ownership(user_id))
            .is_ok());
        assert_eq!(
            *evm_context.native_account(user_id).owner(),
            solana_sdk::system_program::id()
        );

        assert_eq!(
            evm_context
                .evm_state
                .get_account_state(ether_dummy_address)
                .unwrap()
                .balance,
            crate::scope::evm::lamports_to_gwei(1000)
        );

        // Transfer back

        let second_user_id = Pubkey::new_unique();
        let second_user = evm_context.native_account(second_user_id);
        second_user.set_owner(crate::ID);

        let tx_call = evm::UnsignedTransaction {
            nonce: 0u32.into(),
            gas_price: 1u32.into(),
            gas_limit: 300000u32.into(),
            action: TransactionAction::Call(*precompiles::ETH_TO_VLX_ADDR),
            value: crate::scope::evm::lamports_to_gwei(lamports_to_send_back),
            input: precompiles::ETH_TO_VLX_CODE
                .abi
                .encode_input(&[ethabi::Token::FixedBytes(
                    second_user_id.to_bytes().to_vec(),
                )])
                .unwrap(),
        };

        let tx_call = tx_call.sign(&ether_sc, Some(CHAIN_ID));
        {
            let ix = crate::send_raw_tx(Pubkey::new_unique(), tx_call, None, FeePayerType::Evm);
            // if we don't add second account to account list, insctruction should fail
            let result = evm_context.process_instruction(ix);

            result.unwrap_err();

            evm_context.evm_state = evm_context
                .evm_state
                .commit_block(0, Default::default())
                .next_incomming(0);
            assert_eq!(
                evm_context
                    .evm_state
                    .get_account_state(*precompiles::ETH_TO_VLX_ADDR)
                    .unwrap()
                    .balance,
                0u32.into()
            )
        }

        // Nothing should change, because of error
        assert_eq!(
            evm_context
                .native_account(solana::evm_state::id())
                .lamports(),
            lamports_before + lamports_to_send
        );
        assert_eq!(evm_context.native_account(user_id).lamports(), 0);
        assert_eq!(evm_context.native_account(second_user_id).lamports(), 0);

        assert_eq!(
            evm_context
                .evm_state
                .get_account_state(ether_dummy_address)
                .unwrap()
                .balance,
            crate::scope::evm::lamports_to_gwei(lamports_to_send)
        );
    }

    #[test]
    fn execute_transfer_roundtrip() {
        let mut evm_context = EvmMockContext::new(0);
        evm_context.disable_feature(&solana_sdk::feature_set::velas::burn_fee::id());

        let user_id = Pubkey::new_unique();
        let acc = evm_context.native_account(user_id);
        acc.set_owner(crate::ID);
        acc.set_lamports(1000);

        let mut rand = evm_state::rand::thread_rng();
        let ether_sc = evm::SecretKey::new(&mut rand);
        let ether_dummy_address = ether_sc.to_address();

        let lamports_before = evm_context
            .native_account(solana::evm_state::id())
            .lamports();

        let lamports_to_send = 1000;
        let lamports_to_send_back = 300;

        assert!(evm_context
            .process_instruction(crate::transfer_native_to_evm(
                user_id,
                lamports_to_send,
                ether_dummy_address
            ))
            .is_ok());

        assert_eq!(
            evm_context
                .native_account(solana::evm_state::id())
                .lamports(),
            lamports_before + lamports_to_send
        );
        assert_eq!(evm_context.native_account(user_id).lamports(), 0);
        assert!(evm_context
            .process_instruction(crate::free_ownership(user_id))
            .is_ok());
        assert_eq!(
            *evm_context.native_account(user_id).owner(),
            solana_sdk::system_program::id()
        );

        assert_eq!(
            evm_context
                .evm_state
                .get_account_state(ether_dummy_address)
                .unwrap()
                .balance,
            crate::scope::evm::lamports_to_gwei(1000)
        );

        // Transfer back

        let second_user_id = Pubkey::new_unique();
        let second_user = evm_context.native_account(second_user_id);
        second_user.set_owner(crate::ID);

        let tx_call = evm::UnsignedTransaction {
            nonce: 0u32.into(),
            gas_price: 1u32.into(),
            gas_limit: 300000u32.into(),
            action: TransactionAction::Call(*precompiles::ETH_TO_VLX_ADDR),
            value: crate::scope::evm::lamports_to_gwei(lamports_to_send_back),
            input: precompiles::ETH_TO_VLX_CODE
                .abi
                .encode_input(&[ethabi::Token::FixedBytes(
                    second_user_id.to_bytes().to_vec(),
                )])
                .unwrap(),
        };

        let tx_call = tx_call.sign(&ether_sc, Some(CHAIN_ID));
        {
            let mut ix = crate::send_raw_tx(Pubkey::new_unique(), tx_call, None, FeePayerType::Evm);
            // add second account to account list, because we need account to be able to credit
            ix.accounts.push(AccountMeta::new(second_user_id, false));
            let result = evm_context.process_instruction(ix);

            dbg!(&evm_context);
            result.unwrap();

            evm_context.evm_state = evm_context
                .evm_state
                .commit_block(0, Default::default())
                .next_incomming(0);
            assert_eq!(
                evm_context
                    .evm_state
                    .get_account_state(*precompiles::ETH_TO_VLX_ADDR)
                    .unwrap()
                    .balance,
                0u32.into()
            )
        }

        assert_eq!(
            evm_context
                .native_account(solana::evm_state::id())
                .lamports(),
            lamports_before + lamports_to_send - lamports_to_send_back
        );
        assert_eq!(evm_context.native_account(user_id).lamports(), 0);
        assert_eq!(
            evm_context.native_account(second_user_id).lamports(),
            lamports_to_send_back
        );

        assert!(
            evm_context
                .evm_state
                .get_account_state(ether_dummy_address)
                .unwrap()
                .balance
                < crate::scope::evm::lamports_to_gwei(lamports_to_send - lamports_to_send_back)
                && evm_context
                    .evm_state
                    .get_account_state(ether_dummy_address)
                    .unwrap()
                    .balance
                    > crate::scope::evm::lamports_to_gwei(lamports_to_send - lamports_to_send_back)
                        - 300000u32 //(max_fee)
        );
    }

    #[test]
    fn execute_transfer_roundtrip_insufficient_amount() {
        let mut evm_context = EvmMockContext::new(0);

        let user_id = Pubkey::new_unique();
        let acc = evm_context.native_account(user_id);
        acc.set_owner(crate::ID);
        acc.set_lamports(1000);

        let mut rand = evm_state::rand::thread_rng();
        let ether_sc = evm::SecretKey::new(&mut rand);
        let ether_dummy_address = ether_sc.to_address();

        let lamports_before = evm_context
            .native_account(solana::evm_state::id())
            .lamports();

        let lamports_to_send = 1000;
        let lamports_to_send_back = 1001;

        assert!(evm_context
            .process_instruction(crate::transfer_native_to_evm(
                user_id,
                lamports_to_send,
                ether_dummy_address
            ))
            .is_ok());

        assert_eq!(
            evm_context
                .native_account(solana::evm_state::id())
                .lamports(),
            lamports_before + lamports_to_send
        );
        assert_eq!(evm_context.native_account(user_id).lamports(), 0);
        assert!(evm_context
            .process_instruction(crate::free_ownership(user_id))
            .is_ok());
        assert_eq!(
            *evm_context.native_account(user_id).owner(),
            solana_sdk::system_program::id()
        );

        assert_eq!(
            evm_context
                .evm_state
                .get_account_state(ether_dummy_address)
                .unwrap()
                .balance,
            crate::scope::evm::lamports_to_gwei(1000)
        );

        // Transfer back

        let second_user_id = Pubkey::new_unique();
        let second_user = evm_context.native_account(second_user_id);
        second_user.set_owner(crate::ID);

        let tx_call = evm::UnsignedTransaction {
            nonce: 0u32.into(),
            gas_price: 1u32.into(),
            gas_limit: 300000u32.into(),
            action: TransactionAction::Call(*precompiles::ETH_TO_VLX_ADDR),
            value: crate::scope::evm::lamports_to_gwei(lamports_to_send_back),
            input: precompiles::ETH_TO_VLX_CODE
                .abi
                .encode_input(&[ethabi::Token::FixedBytes(
                    second_user_id.to_bytes().to_vec(),
                )])
                .unwrap(),
        };

        let tx_call = tx_call.sign(&ether_sc, Some(CHAIN_ID));
        {
            let mut ix = crate::send_raw_tx(Pubkey::new_unique(), tx_call, None, FeePayerType::Evm);
            // add second account to account list, because we need account to be able to credit
            ix.accounts.push(AccountMeta::new(second_user_id, false));
            let result = evm_context.process_instruction(ix);

            result.unwrap_err();

            evm_context.evm_state = evm_context
                .evm_state
                .commit_block(0, Default::default())
                .next_incomming(0);
            assert_eq!(
                evm_context
                    .evm_state
                    .get_account_state(*precompiles::ETH_TO_VLX_ADDR)
                    .unwrap()
                    .balance,
                0u32.into()
            )
        }

        // Nothing should change, because of error
        assert_eq!(
            evm_context
                .native_account(solana::evm_state::id())
                .lamports(),
            lamports_before + lamports_to_send
        );
        assert_eq!(evm_context.native_account(user_id).lamports(), 0);
        assert_eq!(evm_context.native_account(second_user_id).lamports(), 0);

        assert_eq!(
            evm_context
                .evm_state
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
            crate::transfer_native_to_evm(signer, 1, tx_call.address().unwrap()),
            crate::free_ownership(signer),
            crate::send_raw_tx(signer, tx_call, None, FeePayerType::Evm),
            crate::authorized_tx(signer, unsigned_tx, FeePayerType::Evm),
        ]
    }

    fn account_by_key(pubkey: solana::Address) -> solana_sdk::account::AccountSharedData {
        match &pubkey {
            id if id == &crate::ID => {
                native_loader::create_loadable_account_for_test("EVM Processor")
            }
            id if id == &solana_sdk::sysvar::rent::id() => solana_sdk::account::Account {
                lamports: 10,
                owner: native_loader::id(),
                data: bincode::serialize(&Rent::default()).unwrap(),
                executable: false,
                rent_epoch: 0,
            }
            .into(),
            _rest => solana_sdk::account::Account {
                lamports: 20000000,
                owner: Pubkey::default(),
                data: vec![0u8],
                executable: false,
                rent_epoch: 0,
            }
            .into(),
        }
    }

    #[test]
    fn each_solana_tx_should_contain_writeable_evm_state() {
        for ix in all_ixs() {
            // Create clear executor for each run, to avoid state conflicts in instructions (signed and unsigned tx with same nonce).
            let mut evm_context = EvmMockContext::new(0);

            evm_context.disable_feature(&solana_sdk::feature_set::velas::burn_fee::id());
            let secret_key = evm::SecretKey::from_slice(&SECRET_KEY_DUMMY).unwrap();
            evm_context.deposit_evm(secret_key.to_address(), U256::from(2u32) * 300000u32); // deposit some small amount for gas payments
                                                                                            // insert new accounts, if some missing
            for acc in &ix.accounts {
                // also deposit to instruction callers shadow evm addresses (to allow authorized tx call)
                evm_context.deposit_evm(
                    crate::evm_address_for_program(acc.pubkey),
                    U256::from(2u32) * 300000u32,
                );
                *evm_context.native_account(acc.pubkey) = account_by_key(acc.pubkey);
            }

            let data: EvmInstruction = BorshDeserialize::deserialize(&mut &ix.data[1..]).unwrap();
            match data {
                EvmInstruction::SwapNativeToEther { .. } | EvmInstruction::FreeOwnership { .. } => {
                    let acc = ix.accounts[1].pubkey;
                    // EVM should only operate with accounts that it owns.
                    evm_context.native_account(acc).set_owner(crate::ID)
                }
                _ => {}
            }

            // First execution without evm state key, should fail.
            let mut ix_clone = ix.clone();
            ix_clone.accounts = ix_clone.accounts[1..].to_vec();
            let err = evm_context.process_instruction(ix_clone).unwrap_err();
            match err {
                InstructionError::NotEnoughAccountKeys | InstructionError::MissingAccount => {}
                rest => panic!("Unexpected result = {:?}", rest),
            }

            // Because first execution is fail, state didn't changes, and second execution should pass.
            let result = evm_context.process_instruction(ix);
            result.unwrap();
        }
    }

    // Contract receive ether, and then try to spend 1 ether, when other method called.
    // Spend is done with native swap.
    #[test]
    fn execute_swap_with_revert() {
        let _ = simple_logger::SimpleLogger::new()
            .with_utc_timestamps()
            .init();
        let code_without_revert = hex!("608060405234801561001057600080fd5b5061021a806100206000396000f3fe6080604052600436106100295760003560e01c80639c320d0b1461002e578063a3e76c0f14610089575b600080fd5b34801561003a57600080fd5b506100876004803603604081101561005157600080fd5b81019080803573ffffffffffffffffffffffffffffffffffffffff16906020019092919080359060200190929190505050610093565b005b6100916101e2565b005b8173ffffffffffffffffffffffffffffffffffffffff16670de0b6b3a764000082604051602401808281526020019150506040516020818303038152906040527fb1d6927a000000000000000000000000000000000000000000000000000000007bffffffffffffffffffffffffffffffffffffffffffffffffffffffff19166020820180517bffffffffffffffffffffffffffffffffffffffffffffffffffffffff83818316178352505050506040518082805190602001908083835b602083106101745780518252602082019150602081019050602083039250610151565b6001836020036101000a03801982511681845116808217855250505050505090500191505060006040518083038185875af1925050503d80600081146101d6576040519150601f19603f3d011682016040523d82523d6000602084013e6101db565b606091505b5050505050565b56fea2646970667358221220b9c91ba5fa12925c1988f74e7b6cc9f8047a3a0c36f13b65773a6b608d08b17a64736f6c634300060c0033");
        let code_with_revert = hex!("608060405234801561001057600080fd5b5061021b806100206000396000f3fe6080604052600436106100295760003560e01c80639c320d0b1461002e578063a3e76c0f14610089575b600080fd5b34801561003a57600080fd5b506100876004803603604081101561005157600080fd5b81019080803573ffffffffffffffffffffffffffffffffffffffff16906020019092919080359060200190929190505050610093565b005b6100916101e3565b005b8173ffffffffffffffffffffffffffffffffffffffff16670de0b6b3a764000082604051602401808281526020019150506040516020818303038152906040527fb1d6927a000000000000000000000000000000000000000000000000000000007bffffffffffffffffffffffffffffffffffffffffffffffffffffffff19166020820180517bffffffffffffffffffffffffffffffffffffffffffffffffffffffff83818316178352505050506040518082805190602001908083835b602083106101745780518252602082019150602081019050602083039250610151565b6001836020036101000a03801982511681845116808217855250505050505090500191505060006040518083038185875af1925050503d80600081146101d6576040519150601f19603f3d011682016040523d82523d6000602084013e6101db565b606091505b505050600080fd5b56fea2646970667358221220ca731585b5955eee8418d7952d7537d5e7576a8ac5047530ddb0282f369e7f8e64736f6c634300060c0033");

        // abi encode "address _contract": "0x56454c41532D434841494e000000000053574150", "bytes32 native_recipient": "0x9b73845fe592e092a13df83a8f8485296ba9c0a28c7c0824c33b1b3b352b4043"
        let contract_take_ether_abi = hex!("9c320d0b00000000000000000000000056454c41532d434841494e0000000000535741509b73845fe592e092a13df83a8f8485296ba9c0a28c7c0824c33b1b3b352b4043");
        let _receive_tokens_abi = hex!("a3e76c0f"); // no need because we use fn deposit from vm.

        for code in [&code_without_revert[..], &code_with_revert[..]] {
            let revert = code == &code_with_revert[..];
            if !revert {
                continue;
            }
            let mut evm_context = EvmMockContext::new(1_000_000_000);
            evm_context.disable_feature(&solana_sdk::feature_set::velas::burn_fee::id());
            let receiver = Pubkey::new(&hex!(
                "9b73845fe592e092a13df83a8f8485296ba9c0a28c7c0824c33b1b3b352b4043"
            ));
            let secret_key = evm::SecretKey::from_slice(&SECRET_KEY_DUMMY).unwrap();

            let tx_create = evm::UnsignedTransaction {
                nonce: 0u32.into(),
                gas_price: 1u32.into(),
                gas_limit: 300000u32.into(),
                action: TransactionAction::Create,
                value: 0u32.into(),
                input: code.to_vec(),
            };
            let tx_create = tx_create.sign(&secret_key, Some(CHAIN_ID));

            let _caller_address = tx_create.caller().unwrap();

            let tx_address = tx_create.address().unwrap();

            {
                let address = secret_key.to_address();
                evm_context.deposit_evm(address, U256::from(2u32) * 300000u32);

                evm_context
                    .process_instruction(crate::send_raw_tx(
                        Pubkey::new_unique(),
                        tx_create,
                        None,
                        FeePayerType::Evm,
                    ))
                    .unwrap();
                evm_context.evm_state = evm_context
                    .evm_state
                    .commit_block(0, Default::default())
                    .next_incomming(0);
            }

            {
                evm_context.deposit_evm(
                    tx_address,
                    U256::from(1_000_000_000u64) * U256::from(1_000_000_000u64),
                ); // 1ETHER

                let tx_call = evm::UnsignedTransaction {
                    nonce: 1u32.into(),
                    gas_price: 1u32.into(),
                    gas_limit: 300000u32.into(),
                    action: TransactionAction::Call(tx_address),
                    value: 0u32.into(),
                    input: contract_take_ether_abi.to_vec(),
                };

                let tx_call = tx_call.sign(&secret_key, Some(CHAIN_ID));
                let tx_hash = tx_call.tx_id_hash();
                let mut ix =
                    crate::send_raw_tx(Pubkey::new_unique(), tx_call, None, FeePayerType::Evm);
                ix.accounts.push(AccountMeta::new(receiver, false));
                let result = evm_context.process_instruction(ix);
                if !revert {
                    result.unwrap();
                } else {
                    assert_eq!(result.unwrap_err(), EvmError::RevertTransaction.into())
                }

                let tx = evm_context
                    .evm_state
                    .find_transaction_receipt(tx_hash)
                    .unwrap();
                if revert {
                    println!("status = {:?}", tx.status);
                    assert!(matches!(tx.status, ExitReason::Revert(_)));
                }
                assert!(tx.logs.is_empty());

                evm_context.evm_state = evm_context
                    .evm_state
                    .commit_block(1, Default::default())
                    .next_incomming(0);

                let lamports = evm_context.native_account(receiver).lamports();
                if !revert {
                    assert_eq!(
                        evm_context
                            .evm_state
                            .get_account_state(tx_address)
                            .unwrap()
                            .balance,
                        0u32.into()
                    );
                    assert_eq!(lamports, 1_000_000_000)
                } else {
                    assert_eq!(
                        evm_context
                            .evm_state
                            .get_account_state(tx_address)
                            .unwrap()
                            .balance,
                        U256::from(1_000_000_000u64) * U256::from(1_000_000_000u64)
                    );
                    // assert_eq!(lamports, 0); // solana runtime will revert this account
                }
            }
        }
    }

    #[test]
    fn test_revert_clears_logs() {
        let _ = simple_logger::SimpleLogger::new()
            .with_utc_timestamps()
            .init();
        let code_with_revert = hex!("608060405234801561001057600080fd5b506101de806100206000396000f3fe608060405234801561001057600080fd5b50600436106100365760003560e01c80636057361d1461003b578063cf280be114610057575b600080fd5b6100556004803603810190610050919061011d565b610073565b005b610071600480360381019061006c919061011d565b6100b8565b005b7f31431e8e0193815c649ffbfb9013954926640a5c67ada972108cdb5a47a0d728600054826040516100a6929190610159565b60405180910390a18060008190555050565b7f31431e8e0193815c649ffbfb9013954926640a5c67ada972108cdb5a47a0d728600054826040516100eb929190610159565b60405180910390a180600081905550600061010557600080fd5b50565b60008135905061011781610191565b92915050565b6000602082840312156101335761013261018c565b5b600061014184828501610108565b91505092915050565b61015381610182565b82525050565b600060408201905061016e600083018561014a565b61017b602083018461014a565b9392505050565b6000819050919050565b600080fd5b61019a81610182565b81146101a557600080fd5b5056fea2646970667358221220fc523ca900ab8140013266ce0ed772e285153c9d3292c12522c336791782a40b64736f6c63430008070033");
        let calldata =
            hex!("6057361d0000000000000000000000000000000000000000000000000000000000000001");
        let calldata_with_revert =
            hex!("cf280be10000000000000000000000000000000000000000000000000000000000000001");

        let mut evm_context = EvmMockContext::new(1_000_000_000);
        evm_context.disable_feature(&solana_sdk::feature_set::velas::burn_fee::id());
        let _receiver = Pubkey::new(&hex!(
            "9b73845fe592e092a13df83a8f8485296ba9c0a28c7c0824c33b1b3b352b4043"
        ));
        let secret_key = evm::SecretKey::from_slice(&SECRET_KEY_DUMMY).unwrap();

        let tx_create = evm::UnsignedTransaction {
            nonce: 0u32.into(),
            gas_price: 1u32.into(),
            gas_limit: 300000u32.into(),
            action: TransactionAction::Create,
            value: 0u32.into(),
            input: code_with_revert.to_vec(),
        };
        let tx_create = tx_create.sign(&secret_key, Some(CHAIN_ID));

        let _caller_address = tx_create.caller().unwrap();

        let tx_address = tx_create.address().unwrap();

        {
            let address = secret_key.to_address();
            evm_context.deposit_evm(address, U256::from(2u32) * 300000u32);

            evm_context
                .process_instruction(crate::send_raw_tx(
                    Pubkey::new_unique(),
                    tx_create,
                    None,
                    FeePayerType::Evm,
                ))
                .unwrap();
            evm_context.evm_state = evm_context
                .evm_state
                .commit_block(0, Default::default())
                .next_incomming(0);
        }

        {
            let evm_context = evm_context.clone(); // make copy for test
            let tx_call = evm::UnsignedTransaction {
                nonce: 1.into(),
                gas_price: 1.into(),
                gas_limit: 300000.into(),
                action: TransactionAction::Call(tx_address),
                value: 0.into(),
                input: calldata_with_revert.to_vec(),
            };
            let tx_call = tx_call.sign(&secret_key, Some(CHAIN_ID));
            let tx_hash = tx_call.tx_id_hash();
            let instruction =
                crate::send_raw_tx(Pubkey::new_unique(), tx_call, None, FeePayerType::Evm);

            // Reverted tx with clear_logs_on_error enabled must clear logs
            {
                let mut evm_context = evm_context.clone(); // make copy for test

                let _result = evm_context.process_instruction(instruction.clone());
                let executor = evm_context.evm_state;
                let tx = executor.find_transaction_receipt(tx_hash).unwrap();
                println!("status = {:?}", tx.status);
                assert!(matches!(tx.status, ExitReason::Revert(_)));
                assert!(tx.logs.is_empty());
            }

            // Reverted tx with clear_logs_on_error disabled don't clear logs
            {
                let mut evm_context = evm_context.clone(); // make copy for test
                evm_context
                    .disable_feature(&solana_sdk::feature_set::velas::clear_logs_on_error::id());
                let _result = evm_context.process_instruction(instruction);
                let executor = evm_context.evm_state;
                let tx = executor.find_transaction_receipt(tx_hash).unwrap();
                println!("status = {:?}", tx.status);
                assert!(matches!(tx.status, ExitReason::Revert(_)));
                assert!(!tx.logs.is_empty());
            }
        }

        // Successful tx don't affected by clear_logs_on_error
        {
            let tx_call = evm::UnsignedTransaction {
                nonce: 1.into(),
                gas_price: 1.into(),
                gas_limit: 300000.into(),
                action: TransactionAction::Call(tx_address),
                value: 0.into(),
                input: calldata.to_vec(),
            };
            let tx_call = tx_call.sign(&secret_key, Some(CHAIN_ID));
            let tx_hash = tx_call.tx_id_hash();
            let instruction =
                crate::send_raw_tx(Pubkey::new_unique(), tx_call, None, FeePayerType::Evm);

            {
                let mut evm_context = evm_context.clone(); // make copy for test

                let _result = evm_context.process_instruction(instruction.clone());
                let executor = evm_context.evm_state;
                let tx = executor.find_transaction_receipt(tx_hash).unwrap();

                println!("status = {:?}", tx.status);
                assert!(matches!(tx.status, ExitReason::Succeed(_)));
                assert!(!tx.logs.is_empty());
            }

            {
                let mut evm_context = evm_context.clone(); // make copy for test

                let _result = evm_context.process_instruction(instruction);
                evm_context
                    .disable_feature(&solana_sdk::feature_set::velas::clear_logs_on_error::id());

                let executor = evm_context.evm_state;
                let tx = executor.find_transaction_receipt(tx_hash).unwrap();
                println!("status = {:?}", tx.status);
                assert!(matches!(tx.status, ExitReason::Succeed(_)));
                assert!(!tx.logs.is_empty());
            }
        }
    }

    #[test]
    fn authorized_tx_only_from_signer() {
        let mut evm_context = EvmMockContext::new(0);
        evm_context.disable_feature(&solana_sdk::feature_set::velas::burn_fee::id());
        let secret_key = evm::SecretKey::from_slice(&SECRET_KEY_DUMMY).unwrap();

        let address = secret_key.to_address();
        evm_context.deposit_evm(address, U256::from(2u32) * 300000u32);
        let tx_create = evm::UnsignedTransaction {
            nonce: 0u32.into(),
            gas_price: 1u32.into(),
            gas_limit: 300000u32.into(),
            action: TransactionAction::Create,
            value: 0u32.into(),
            input: hex::decode(evm_state::HELLO_WORLD_CODE).unwrap().to_vec(),
        };

        let tx_create = tx_create.sign(&secret_key, Some(CHAIN_ID));
        let user_id = Pubkey::new_unique();

        evm_context.native_account(user_id).set_lamports(1000);

        let dummy_address = tx_create.address().unwrap();

        evm_context
            .process_instruction(crate::send_raw_tx(
                user_id,
                tx_create,
                None,
                FeePayerType::Evm,
            ))
            .unwrap();

        let unsigned_tx = evm::UnsignedTransaction {
            nonce: 0u32.into(),
            gas_price: 1u32.into(),
            gas_limit: 300000u32.into(),
            action: TransactionAction::Call(dummy_address),
            value: 0u32.into(),
            input: hex::decode(evm_state::HELLO_WORLD_ABI).unwrap().to_vec(),
        };

        evm_context.deposit_evm(
            crate::evm_address_for_program(user_id),
            U256::from(2u32) * 300000u32,
        );
        let ix = crate::authorized_tx(user_id, unsigned_tx, FeePayerType::Evm);
        let mut ix_clone = ix.clone();
        // remove signer marker from account meta to simulate unsigned tx
        ix_clone.accounts.last_mut().unwrap().is_signer = false;

        // First execution without signer user key, should fail.
        let err = evm_context.process_instruction(ix_clone).unwrap_err();

        match err {
            e @ InstructionError::Custom(_) => {
                assert_eq!(e, crate::error::EvmError::MissingRequiredSignature.into())
            } // new_error_handling feature always activated at MockInvokeContext
            rest => panic!("Unexpected result = {:?}", rest),
        }
        // Because first execution is fail, state didn't changes, and second execution should pass.
        evm_context.process_instruction(ix).unwrap();
    }

    #[test]
    fn authorized_tx_with_evm_fee_type() {
        let _ = simple_logger::SimpleLogger::new()
            .with_utc_timestamps()
            .init();
        let mut evm_context = EvmMockContext::new(
            gweis_to_lamports(U256::from(300000u64 * evm_state::BURN_GAS_PRICE * 2)).0,
        );

        let mut rand = evm_state::rand::thread_rng();
        let dummy_key = evm::SecretKey::new(&mut rand);
        let dummy_address = dummy_key.to_address();

        let user_id = Pubkey::new_unique();
        let user_evm_address = crate::evm_address_for_program(user_id);
        evm_context.deposit_evm(
            user_evm_address,
            U256::from(300000u64 * evm_state::BURN_GAS_PRICE * 2),
        );

        let unsigned_tx = evm::UnsignedTransaction {
            nonce: 0.into(),
            gas_price: U256::from(evm_state::BURN_GAS_PRICE) * 2,
            gas_limit: 300000.into(),
            action: TransactionAction::Call(dummy_address),
            value: 0.into(),
            input: vec![],
        };
        let from = crate::evm_address_for_program(user_id);
        let tx_hash = evm::UnsignedTransactionWithCaller {
            unsigned_tx: unsigned_tx.clone(),
            chain_id: evm::TEST_CHAIN_ID,
            caller: from,
            signed_compatible: true,
        }
        .tx_id_hash();

        let ix = crate::authorized_tx(user_id, unsigned_tx, FeePayerType::Evm);

        let evm_balance_before = evm_context
            .evm_state
            .get_account_state(user_evm_address)
            .unwrap()
            .balance;
        let user_balance_before = evm_context.native_account(user_id).lamports();

        evm_context.process_instruction(ix).unwrap();

        let executor = &evm_context.evm_state;
        let tx = executor.find_transaction_receipt(tx_hash).unwrap();
        let burn_fee = U256::from(tx.used_gas) * U256::from(evm_state::BURN_GAS_PRICE);
        // EVM balance has decreased
        assert!(
            evm_balance_before
                > executor
                    .get_account_state(user_evm_address)
                    .unwrap()
                    .balance
        );
        // Native balance has increased because of refund
        let evm_balance_difference = evm_balance_before
            - executor
                .get_account_state(user_evm_address)
                .unwrap()
                .balance;
        assert_eq!(burn_fee * 2, evm_balance_difference);
        assert_eq!(
            evm_context.native_account(user_id).lamports(),
            user_balance_before + gweis_to_lamports(evm_balance_difference).0 / 2
        );
    }

    #[test]
    fn authorized_tx_with_native_fee_type() {
        let _ = simple_logger::SimpleLogger::new()
            .env()
            .with_utc_timestamps()
            .init();
        let mut evm_context = EvmMockContext::new(1000);
        evm_context.disable_feature(&solana_sdk::feature_set::velas::burn_fee::id());

        let mut rand = evm_state::rand::thread_rng();
        let dummy_key = evm::SecretKey::new(&mut rand);
        let dummy_address = dummy_key.to_address();

        let user_id = Pubkey::new_unique();
        let user_evm_address = crate::evm_address_for_program(user_id);
        evm_context.deposit_evm(user_evm_address, U256::from(30000000000u64));
        evm_context
            .native_account(user_id)
            .set_lamports(30000000000u64);
        let unsigned_tx = evm::UnsignedTransaction {
            nonce: 0.into(),
            gas_price: 100000.into(),
            gas_limit: 300000.into(),
            action: TransactionAction::Call(dummy_address),
            value: 0.into(),
            input: vec![],
        };

        let ix = crate::authorized_tx(user_id, unsigned_tx, FeePayerType::Native);

        let evm_balance_before = evm_context
            .evm_state
            .get_account_state(user_evm_address)
            .unwrap()
            .balance;
        let user_balance_before = evm_context.native_account(user_id).lamports();

        evm_context.process_instruction(ix).unwrap();

        let executor = &evm_context.evm_state;
        // EVM balance hasn't decreased
        assert_eq!(
            evm_balance_before,
            executor
                .get_account_state(user_evm_address)
                .unwrap()
                .balance
        );
        // Native balance refunded
        assert_eq!(
            user_balance_before,
            evm_context.native_account(user_id).lamports()
        );
    }

    // Transaction with fee type Native should be executed correctly if signer has no balance on evm account
    #[test]
    fn evm_transaction_with_native_fee_type_and_zero_evm_balance_check_burn() {
        let _ = simple_logger::SimpleLogger::new()
            .env()
            .with_utc_timestamps()
            .init();
        let mut evm_context = EvmMockContext::new(1000);

        let mut rand = evm_state::rand::thread_rng();
        let dummy_key = evm::SecretKey::new(&mut rand);
        let dummy_address = dummy_key.to_address();

        let user_id = Pubkey::new_unique();
        let gas_price: U256 = evm::BURN_GAS_PRICE.into();
        evm_context
            .native_account(user_id)
            .set_lamports(30000000000u64);
        evm_context.native_account(user_id).set_owner(crate::ID); // only owner can withdraw tokens.
        let unsigned_tx = evm::UnsignedTransaction {
            nonce: 0.into(),
            gas_price: gas_price,
            gas_limit: 300000.into(),
            action: TransactionAction::Call(dummy_address),
            value: 0.into(),
            input: vec![],
        };

        let tx_create = unsigned_tx.sign(&dummy_key, Some(CHAIN_ID));
        let tx_hash = tx_create.tx_id_hash();
        let ix = crate::send_raw_tx(user_id, tx_create, None, FeePayerType::Native);

        let executor = &evm_context.evm_state;
        // Signer has zero balance but fee will be taken from native account
        assert_eq!(
            U256::from(0),
            executor
                .get_account_state(dummy_address)
                .unwrap_or_default()
                .balance
        );

        let user_balance_before = evm_context.native_account(user_id).lamports();

        evm_context.process_instruction(ix).unwrap();

        let executor = &evm_context.evm_state;
        let tx = executor.find_transaction_receipt(tx_hash).unwrap();
        let burn_fee =
            gweis_to_lamports(U256::from(tx.used_gas) * U256::from(evm_state::BURN_GAS_PRICE));

        // EVM balance is still zero
        assert_eq!(
            U256::from(0),
            executor
                .get_account_state(dummy_address)
                .unwrap_or_default()
                .balance
        );
        // Native balance refunded
        assert_eq!(
            user_balance_before - burn_fee.0,
            evm_context.native_account(user_id).lamports()
        );
    }

    // In case when fee type Native chosen but no native account provided fee will be taken from signer (EVM)
    #[test]
    fn evm_transaction_with_native_fee_type_and_and_no_native_account_provided() {
        let _ = simple_logger::SimpleLogger::new()
            .env()
            .with_utc_timestamps()
            .init();
        let mut evm_context = EvmMockContext::new(1000);
        evm_context.disable_feature(&solana_sdk::feature_set::velas::burn_fee::id());

        let mut rand = evm_state::rand::thread_rng();
        let dummy_key = evm::SecretKey::new(&mut rand);
        let dummy_address = dummy_key.to_address();

        let user_id = Pubkey::new_unique();
        evm_context
            .native_account(user_id)
            .set_lamports(30000000000u64);
        let unsigned_tx = evm::UnsignedTransaction {
            nonce: 0.into(),
            gas_price: 100000.into(),
            gas_limit: 300000.into(),
            action: TransactionAction::Call(dummy_address),
            value: 0.into(),
            input: vec![],
        };

        let tx_create = unsigned_tx.sign(&dummy_key, Some(CHAIN_ID));
        let mut ix = crate::send_raw_tx(user_id, tx_create, None, FeePayerType::Native);

        let executor = &evm_context.evm_state;
        // Signer has zero balance but fee will be taken from native account
        assert_eq!(
            U256::from(0),
            executor
                .get_account_state(dummy_address)
                .unwrap_or_default()
                .balance
        );

        ix.accounts.pop();
        // Ix should fail because no sender found
        evm_context.process_instruction(ix).unwrap_err();
    }

    #[test]
    fn evm_transaction_native_fee_handled_correctly_with_exit_reason_not_succeed() {
        let _ = simple_logger::SimpleLogger::new()
            .env()
            .with_utc_timestamps()
            .init();
        let mut evm_context = EvmMockContext::new(1000);
        evm_context.disable_feature(&solana_sdk::feature_set::velas::burn_fee::id());

        let mut rand = evm_state::rand::thread_rng();
        let dummy_key = evm::SecretKey::new(&mut rand);
        let dummy_address = dummy_key.to_address();

        let user_id = Pubkey::new_unique();
        evm_context
            .native_account(user_id)
            .set_lamports(30000000000u64);
        let unsigned_tx = evm::UnsignedTransaction {
            nonce: 0.into(),
            gas_price: 100000.into(),
            gas_limit: 3000.into(),
            action: TransactionAction::Create,
            value: 0.into(),
            input: hex::decode(evm_state::HELLO_WORLD_CODE).unwrap().to_vec(),
        };

        let tx_create = unsigned_tx.sign(&dummy_key, Some(CHAIN_ID));
        let ix = crate::send_raw_tx(user_id, tx_create, None, FeePayerType::Native);

        let executor = &evm_context.evm_state;
        // Signer has zero balance but fee will be taken from native account
        assert_eq!(
            U256::from(0),
            executor
                .get_account_state(dummy_address)
                .unwrap_or_default()
                .balance
        );

        let user_balance_before = evm_context.native_account(user_id).lamports();

        evm_context.process_instruction(ix).unwrap_err();

        // Native balance is unchanged
        assert_eq!(
            user_balance_before,
            evm_context.native_account(user_id).lamports()
        );
    }

    #[test]
    fn evm_transaction_with_insufficient_native_funds() {
        let _ = simple_logger::SimpleLogger::new()
            .env()
            .with_utc_timestamps()
            .init();
        let code_with_logs_and_revert = hex!("608060405234801561001057600080fd5b50600436106100365760003560e01c80636057361d1461003b578063cf280be114610057575b600080fd5b6100556004803603810190610050919061011d565b610073565b005b610071600480360381019061006c919061011d565b6100b8565b005b7f31431e8e0193815c649ffbfb9013954926640a5c67ada972108cdb5a47a0d728600054826040516100a6929190610159565b60405180910390a18060008190555050565b7f31431e8e0193815c649ffbfb9013954926640a5c67ada972108cdb5a47a0d728600054826040516100eb929190610159565b60405180910390a180600081905550600061010557600080fd5b50565b60008135905061011781610191565b92915050565b6000602082840312156101335761013261018c565b5b600061014184828501610108565b91505092915050565b61015381610182565b82525050565b600060408201905061016e600083018561014a565b61017b602083018461014a565b9392505050565b6000819050919050565b600080fd5b61019a81610182565b81146101a557600080fd5b5056fea2646970667358221220fc523ca900ab8140013266ce0ed772e285153c9d3292c12522c336791782a40b64736f6c63430008070033");
        let calldata =
            hex!("6057361d0000000000000000000000000000000000000000000000000000000000000001");

        let mut evm_context = EvmMockContext::new(1000);
        evm_context.disable_feature(&solana_sdk::feature_set::velas::burn_fee::id());

        let mut rand = evm_state::rand::thread_rng();
        let contract_address = evm::SecretKey::new(&mut rand).to_address();
        let dummy_key = evm::SecretKey::new(&mut rand);
        let dummy_address = dummy_key.to_address();
        evm_context.evm_state.set_account_state(
            contract_address,
            AccountState {
                code: code_with_logs_and_revert.to_vec().into(),
                ..AccountState::default()
            },
        );
        evm_context
            .evm_state
            .set_account_state(dummy_address, AccountState::default());

        let user_id = Pubkey::new_unique();
        let unsigned_tx = evm::UnsignedTransaction {
            nonce: 0.into(),
            gas_price: 100000.into(),
            gas_limit: 300000.into(),
            action: TransactionAction::Call(contract_address),
            value: 0.into(),
            input: calldata.to_vec(),
        };

        let tx_call = unsigned_tx.sign(&dummy_key, Some(CHAIN_ID));
        let tx_hash = tx_call.tx_id_hash();
        let ix = crate::send_raw_tx(user_id, tx_call, None, FeePayerType::Native);

        let executor = &evm_context.evm_state;
        // Signer has zero balance but fee will be taken from native account
        let evm_signer = executor.get_account_state(dummy_address).unwrap();
        assert!(evm_signer.balance.is_zero());

        let native_sender = evm_context.native_account(user_id);
        assert!(native_sender.lamports().is_zero());
        // Ix should fail because user has insufficient funds
        assert!(matches!(
            evm_context.process_instruction(ix).unwrap_err(),
            InstructionError::Custom(18)
        ));

        let executor = &evm_context.evm_state;
        // All balances remain the same
        let evm_signer = executor.get_account_state(dummy_address).unwrap();
        assert!(evm_signer.balance.is_zero());
        let native_sender = evm_context.native_account(user_id);
        assert!(native_sender.lamports().is_zero());

        let executor = evm_context.evm_state;
        let tx = executor.find_transaction_receipt(tx_hash).unwrap();
        println!("status = {:?}", tx.status);
        assert!(matches!(tx.status, ExitReason::Revert(_)));
        assert!(tx.logs.is_empty());
    }

    #[test]
    fn big_tx_allocation_error() {
        let mut evm_context = EvmMockContext::new(0);

        let user_id = Pubkey::new_unique();
        let user_acc = evm_context.native_account(user_id);
        user_acc.set_data(vec![0; evm_state::MAX_TX_LEN as usize]);
        user_acc.set_owner(crate::ID);
        user_acc.set_lamports(1000);

        evm_context
            .process_instruction(crate::big_tx_allocate(
                user_id,
                evm_state::MAX_TX_LEN as usize + 1,
            ))
            .unwrap_err();

        evm_context
            .process_instruction(crate::big_tx_allocate(
                user_id,
                evm_state::MAX_TX_LEN as usize,
            ))
            .unwrap();
    }

    #[test]
    fn big_tx_write_out_of_bound() {
        let batch_size: usize = 500;

        let mut evm_context = EvmMockContext::new(0);

        let user_id = Pubkey::new_unique();
        let user_acc = evm_context.native_account(user_id);
        user_acc.set_data(vec![0; batch_size as usize]);
        user_acc.set_owner(crate::ID);
        user_acc.set_lamports(1000);

        evm_context
            .process_instruction(crate::big_tx_allocate(user_id, batch_size))
            .unwrap();

        // out of bound write
        evm_context
            .process_instruction(crate::big_tx_write(user_id, batch_size as u64, vec![1]))
            .unwrap_err();

        // out of bound write

        evm_context
            .process_instruction(crate::big_tx_write(user_id, 0, vec![1; batch_size + 1]))
            .unwrap_err();

        // Write in bounds
        evm_context
            .process_instruction(crate::big_tx_write(user_id, 0, vec![1; batch_size]))
            .unwrap();
        // Overlaped writes is allowed
        evm_context
            .process_instruction(crate::big_tx_write(user_id, batch_size as u64 - 1, vec![1]))
            .unwrap();
        // make sure that data has been changed
        assert_eq!(
            evm_context.native_account(user_id).data(),
            vec![1; batch_size]
        );
    }

    #[test]
    fn big_tx_write_without_alloc() {
        let batch_size: usize = 500;

        let mut evm_context = EvmMockContext::new(0);

        let user_id = Pubkey::new_unique();
        let user_acc = evm_context.native_account(user_id);
        // skip allocate and assign instruction
        // user_acc.set_data(vec![0; batch_size as usize]);
        user_acc.set_owner(crate::ID);
        user_acc.set_lamports(1000);

        evm_context
            .process_instruction(crate::big_tx_write(user_id, 0, vec![1; batch_size]))
            .unwrap_err();
    }

    #[test]
    fn check_tx_mtu_is_in_solanas_limit() {
        use solana_sdk::hash::hash;
        use solana_sdk::message::Message;
        use solana_sdk::signature::{Keypair, Signer};
        use solana_sdk::transaction::Transaction;

        let storage = Keypair::new();
        let bridge = Keypair::new();
        let ix = crate::big_tx_write(storage.pubkey(), 0, vec![1; evm::TX_MTU]);
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
