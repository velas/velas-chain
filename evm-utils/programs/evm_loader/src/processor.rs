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
use evm_state::{ExecutionResult, Gas};
use serde::de::DeserializeOwned;
use solana_sdk::account::AccountSharedData;
use solana_sdk::ic_msg;
use solana_sdk::instruction::InstructionError;
use solana_sdk::process_instruction::InvokeContext;
use solana_sdk::pubkey::Pubkey;
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
        let ignore_reset_on_cleared = invoke_context
            .is_feature_active(&solana_sdk::feature_set::velas::ignore_reset_on_cleared::id());
        let free_ownership_require_signer = invoke_context.is_feature_active(
            &solana_sdk::feature_set::velas::free_ownership_require_signer::id(),
        );
        let borsh_serialization_enabled = invoke_context.is_feature_active(
            &solana_sdk::feature_set::velas::evm_instruction_borsh_serialization::id(),
        );

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
                BorshDeserialize::deserialize(&mut &borsh_data[..])
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
        invoke_context: &dyn InvokeContext,
        accounts: AccountStructure,
        tx: ExecuteTransaction,
        fee_type: FeePayerType,
        borsh_used: bool,
    ) -> Result<(), EvmError> {
        let is_big = tx.is_big();
        let sender = if is_big {
            accounts.users.get(1)
        } else {
            accounts.first()
        };
        let withdraw_fee_from_evm = fee_type.is_evm() || sender.is_none();
        let tx_gas_price;
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
                executor.transaction_execute(
                    tx,
                    withdraw_fee_from_evm,
                    precompiles::entrypoint(accounts, executor.support_precompile()),
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
                executor.transaction_execute_unsinged(
                    from,
                    tx,
                    withdraw_fee_from_evm,
                    precompiles::entrypoint(accounts, executor.support_precompile()),
                )
            }
        };

        if let (false, Ok(result)) = (withdraw_fee_from_evm, &result) {
            Self::charge_native_account(result, tx_gas_price, sender.unwrap())?;
        }
        if executor.feature_set.is_unsigned_tx_fix_enabled() && is_big {
            let storage = Self::get_big_transaction_storage(invoke_context, &accounts)?;
            self.cleanup_storage(invoke_context, storage, sender.unwrap_or(accounts.evm))?;
        }
        self.handle_transaction_result(
            executor,
            invoke_context,
            accounts,
            sender,
            tx_gas_price,
            result,
        )
    }

    fn process_free_ownership(
        &self,
        _executor: &mut Executor,
        invoke_context: &dyn InvokeContext,
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
            )
        }
        Ok(())
    }

    fn process_big_tx(
        &self,
        invoke_context: &dyn InvokeContext,
        accounts: AccountStructure,
        big_tx: EvmBigTransaction,
    ) -> Result<(), EvmError> {
        debug!("executing big_tx = {:?}", big_tx);

        let mut storage = Self::get_big_transaction_storage(invoke_context, &accounts)?;
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
        }
    }

    pub fn cleanup_storage<'a>(
        &self,
        invoke_context: &dyn InvokeContext,
        mut storage_ref: RefMut<AccountSharedData>,
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

    fn check_program_account(
        invoke_context: &dyn InvokeContext,
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
            let program_owner = program_account
                .try_account_ref()
                .map_err(|_| EvmError::BorrowingFailed)?
                .owner;
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
        invoke_context: &dyn InvokeContext,
        accounts: AccountStructure,
        deserialize_chunks_with_borsh: bool,
    ) -> Result<T, EvmError>
    where
        T: BorshDeserialize + DeserializeOwned,
    {
        let mut storage = Self::get_big_transaction_storage(invoke_context, &accounts)?;
        let tx_chunks = TxChunks::new(storage.data.as_mut_slice());
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
        invoke_context: &dyn InvokeContext,
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
        gas_price: Gas,
        native_account: &KeyedAccount,
    ) -> Result<(), EvmError> {
        // Charge only when transaction succeeded
        if matches!(tx_result.exit_reason, ExitReason::Succeed(_)) {
            let fee = gas_price * tx_result.used_gas;
            let (fee, _) = gweis_to_lamports(fee);
            let mut account_data = native_account
                .try_account_ref_mut()
                .map_err(|_| EvmError::BorrowingFailed)?;
            account_data.lamports = account_data
                .lamports
                .checked_sub(fee)
                .ok_or(EvmError::NativeAccountInsufficientFunds)?;
        }
        Ok(())
    }

    // Handle executor errors.
    // refund fee
    pub fn handle_transaction_result(
        &self,
        executor: &mut Executor,
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

        write!(
            crate::solana_extension::MultilineLogger::new(&*invoke_context.get_logger().borrow()),
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

        if burn_fee > U256::zero() {
            // we already withdraw gas_price during transaction_execute,
            // if burn_fixed_fee is activated, we should deposit to burn addr (0x00..00)
            executor.deposit(BURN_ADDR, burn_fee)
        };

        if let Some(payer) = sender {
            let (fee, _) = gweis_to_lamports(refund_fee);
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
        evm::SECP256K1,
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
    use evm_state::{AccountProvider, ExitReason, ExitSucceed, executor::FeatureSet};
    use primitive_types::{H160, H256, U256};
    use solana_sdk::keyed_account::KeyedAccount;
    use solana_sdk::native_loader;
    use solana_sdk::process_instruction::{
        BpfComputeBudget, ComputeMeter, Logger, MockComputeMeter, MockInvokeContext, MockLogger,
        ProcessInstructionWithContext,
    };
    use solana_sdk::program_utils::limited_deserialize;
    use solana_sdk::sysvar::rent::Rent;

    use super::TEST_CHAIN_ID as CHAIN_ID;
    use crate::instructions::ExecuteTransaction::ProgramAuthorized;
    use borsh::BorshSerialize;
    use solana_sdk::instruction::{CompiledInstruction, Instruction};
    use solana_sdk::message::Message;
    use std::rc::Rc;
    use std::sync::Arc;
    use std::{cell::RefCell, collections::BTreeMap};

    pub struct MockInvokeContextWithParentCaller {
        pub key: Pubkey,
        pub parent_caller: Pubkey,
        pub logger: MockLogger,
        pub bpf_compute_budget: BpfComputeBudget,
        pub compute_meter: MockComputeMeter,
        pub programs: Vec<(Pubkey, ProcessInstructionWithContext)>,
        pub accounts: Vec<(Pubkey, Rc<RefCell<AccountSharedData>>)>,
        pub invoke_depth: usize,
        pub evm_executor: Option<Rc<RefCell<evm_state::Executor>>>,
    }

    impl MockInvokeContextWithParentCaller {
        pub fn with_evm(evm_executor: evm_state::Executor) -> Self {
            Self {
                evm_executor: Some(Rc::new(RefCell::new(evm_executor))),
                ..Default::default()
            }
        }
        pub fn deconstruct(self) -> Option<evm_state::Executor> {
            self.evm_executor
                .and_then(|e| Some(Rc::try_unwrap(e).ok()?.into_inner()))
        }
    }

    impl Default for MockInvokeContextWithParentCaller {
        fn default() -> Self {
            MockInvokeContextWithParentCaller {
                key: Pubkey::default(),
                parent_caller: Pubkey::default(),
                logger: MockLogger::default(),
                bpf_compute_budget: BpfComputeBudget::default(),
                compute_meter: MockComputeMeter {
                    remaining: std::i64::MAX as u64,
                },
                programs: vec![],
                accounts: vec![],
                invoke_depth: 0,
                evm_executor: None,
            }
        }
    }

    impl InvokeContext for MockInvokeContextWithParentCaller {
        fn push(&mut self, _key: &Pubkey) -> Result<(), InstructionError> {
            self.invoke_depth = self.invoke_depth.saturating_add(1);
            Ok(())
        }
        fn pop(&mut self) {
            self.invoke_depth = self.invoke_depth.saturating_sub(1);
        }
        fn invoke_depth(&self) -> usize {
            self.invoke_depth
        }
        fn verify_and_update(
            &mut self,
            _message: &Message,
            _instruction: &CompiledInstruction,
            _accounts: &[Rc<RefCell<AccountSharedData>>],
            _caller_pivileges: Option<&[bool]>,
        ) -> Result<(), InstructionError> {
            Ok(())
        }
        fn get_evm_executor(&self) -> Option<Rc<RefCell<evm_state::Executor>>> {
            self.evm_executor.clone()
        }
        fn get_parent_caller(&self) -> Option<&Pubkey> {
            Some(&self.parent_caller)
        }
        fn get_caller(&self) -> Result<&Pubkey, InstructionError> {
            Ok(&self.key)
        }
        fn get_programs(&self) -> &[(Pubkey, ProcessInstructionWithContext)] {
            &self.programs
        }
        fn get_logger(&self) -> Rc<RefCell<dyn Logger>> {
            Rc::new(RefCell::new(self.logger.clone()))
        }
        fn get_bpf_compute_budget(&self) -> &BpfComputeBudget {
            &self.bpf_compute_budget
        }
        fn get_compute_meter(&self) -> Rc<RefCell<dyn ComputeMeter>> {
            Rc::new(RefCell::new(self.compute_meter.clone()))
        }
        fn add_executor(
            &self,
            _pubkey: &Pubkey,
            _executor: Arc<dyn solana_sdk::process_instruction::Executor>,
        ) {
        }
        fn get_executor(
            &self,
            _pubkey: &Pubkey,
        ) -> Option<Arc<dyn solana_sdk::process_instruction::Executor>> {
            None
        }
        fn record_instruction(&self, _instruction: &Instruction) {}
        fn is_feature_active(&self, _feature_id: &Pubkey) -> bool {
            true
        }
        fn get_account(&self, pubkey: &Pubkey) -> Option<Rc<RefCell<AccountSharedData>>> {
            for (key, account) in self.accounts.iter() {
                if key == pubkey {
                    return Some(account.clone());
                }
            }
            None
        }
        fn update_timing(
            &mut self,
            _serialize_us: u64,
            _create_vm_us: u64,
            _execute_us: u64,
            _deserialize_us: u64,
        ) {
        }
        fn get_sysvar_data(&self, _id: &Pubkey) -> Option<Rc<Vec<u8>>> {
            None
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
                &bincode::serialize(&EvmInstruction::new_execute_tx(
                    tx_create.clone(),
                    FeePayerType::Evm
                ))
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
                &bincode::serialize(&EvmInstruction::new_execute_tx(tx_call, FeePayerType::Evm))
                    .unwrap(),
                &mut invoke_context,
                false,
            )
            .is_ok());

        let mut executor = invoke_context.deconstruct().unwrap();
        println!("cx = {:?}", executor);
        assert!(executor.get_tx_receipt_by_hash(tx_hash).is_some())
    }

    #[test]
    fn test_cross_execution() {
        let _logger = simple_logger::SimpleLogger::new().init();
        let mut executor = evm_state::Executor::testing();
        let processor = EvmProcessor::default();
        let evm_account = RefCell::new(crate::create_state_account(0));
        let evm_keyed_account = KeyedAccount::new(&solana::evm_state::ID, false, &evm_account);

        let user_id = Pubkey::new_unique();
        let program_id = Pubkey::new_unique();
        let from = crate::evm_address_for_program(program_id);
        executor.deposit(from, U256::from(2) * 300000);
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
        let user_account = RefCell::new(solana_sdk::account::AccountSharedData {
            lamports: 1000,
            data: vec![0; tx_bytes.len()],
            owner: crate::ID,
            executable: false,
            rent_epoch: 0,
        });
        let user_keyed_account = KeyedAccount::new(&user_id, true, &user_account);
        let program_account = RefCell::new(crate::create_state_account(0));
        let program_keyed_account = KeyedAccount::new(&program_id, true, &program_account);
        let keyed_accounts = [evm_keyed_account, user_keyed_account, program_keyed_account];

        let mut invoke_context = MockInvokeContextWithParentCaller::with_evm(executor);
        invoke_context.parent_caller = crate::ID;

        let big_tx_alloc = EvmBigTransaction::EvmTransactionAllocate {
            size: tx_bytes.len() as u64,
        };
        let mut buf = vec![EVM_INSTRUCTION_BORSH_PREFIX];
        BorshSerialize::serialize(&EvmInstruction::EvmBigTransaction(big_tx_alloc), &mut buf)
            .unwrap();
        processor
            .process_instruction(&crate::ID, &keyed_accounts, &buf, &mut invoke_context, true)
            .unwrap();

        buf = vec![EVM_INSTRUCTION_BORSH_PREFIX];
        let big_tx_write = EvmBigTransaction::EvmTransactionWrite {
            offset: 0,
            data: tx_bytes,
        };
        BorshSerialize::serialize(&EvmInstruction::EvmBigTransaction(big_tx_write), &mut buf)
            .unwrap();
        processor
            .process_instruction(&crate::ID, &keyed_accounts, &buf, &mut invoke_context, true)
            .unwrap();

        buf = vec![EVM_INSTRUCTION_BORSH_PREFIX];
        BorshSerialize::serialize(
            &EvmInstruction::ExecuteTransaction {
                tx: ProgramAuthorized { tx: None, from },
                fee_type: FeePayerType::Native,
            },
            &mut buf,
        )
        .unwrap();
        assert!(processor
            .process_instruction(
                &crate::ID,
                &keyed_accounts,
                &buf,
                &mut invoke_context,
                false,
            )
            .is_ok());
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
                &bincode::serialize(&EvmInstruction::new_execute_tx(
                    tx_create,
                    FeePayerType::Evm
                ))
                .unwrap(),
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
                &bincode::serialize(&EvmInstruction::new_execute_tx(
                    tx_1_sign.clone(),
                    FeePayerType::Evm
                ))
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
                &bincode::serialize(&EvmInstruction::new_execute_tx(
                    tx_0_sign,
                    FeePayerType::Evm
                ))
                .unwrap(),
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
                &bincode::serialize(&EvmInstruction::new_execute_tx(
                    tx_0_shadow_sign,
                    FeePayerType::Evm
                ))
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
                &bincode::serialize(&EvmInstruction::new_execute_tx(
                    tx_1_sign,
                    FeePayerType::Evm
                ))
                .unwrap(),
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
                &bincode::serialize(&EvmInstruction::new_execute_tx(
                    tx_0_sign,
                    FeePayerType::Evm
                ))
                .unwrap(),
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
                    &bincode::serialize(&EvmInstruction::new_execute_tx(
                        tx_create,
                        FeePayerType::Evm
                    ))
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
                    &bincode::serialize(&EvmInstruction::new_execute_tx(
                        tx_call,
                        FeePayerType::Evm
                    ))
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
                    &bincode::serialize(&EvmInstruction::new_execute_tx(
                        tx_call,
                        FeePayerType::Evm
                    ))
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
                &bincode::serialize(&EvmInstruction::new_execute_tx(tx_call, FeePayerType::Evm))
                    .unwrap(),
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
                &bincode::serialize(&EvmInstruction::new_execute_tx(tx_call, FeePayerType::Evm))
                    .unwrap(),
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

            let data: EvmInstruction = BorshDeserialize::deserialize(&mut &ix.data[1..]).unwrap();
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
                        &bincode::serialize(&EvmInstruction::new_execute_tx(
                            tx_create,
                            FeePayerType::Evm
                        ))
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
                    &bincode::serialize(&EvmInstruction::new_execute_tx(
                        tx_call,
                        FeePayerType::Evm,
                    ))
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
                assert!(tx.logs.is_empty());

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
    fn test_revert_clears_logs() {
        use hex_literal::hex;
        let _ = simple_logger::SimpleLogger::new().init();
        let code_with_revert = hex!("608060405234801561001057600080fd5b506101de806100206000396000f3fe608060405234801561001057600080fd5b50600436106100365760003560e01c80636057361d1461003b578063cf280be114610057575b600080fd5b6100556004803603810190610050919061011d565b610073565b005b610071600480360381019061006c919061011d565b6100b8565b005b7f31431e8e0193815c649ffbfb9013954926640a5c67ada972108cdb5a47a0d728600054826040516100a6929190610159565b60405180910390a18060008190555050565b7f31431e8e0193815c649ffbfb9013954926640a5c67ada972108cdb5a47a0d728600054826040516100eb929190610159565b60405180910390a180600081905550600061010557600080fd5b50565b60008135905061011781610191565b92915050565b6000602082840312156101335761013261018c565b5b600061014184828501610108565b91505092915050565b61015381610182565b82525050565b600060408201905061016e600083018561014a565b61017b602083018461014a565b9392505050565b6000819050919050565b600080fd5b61019a81610182565b81146101a557600080fd5b5056fea2646970667358221220fc523ca900ab8140013266ce0ed772e285153c9d3292c12522c336791782a40b64736f6c63430008070033");
        let calldata =
            hex!("6057361d0000000000000000000000000000000000000000000000000000000000000001");
        let calldata_with_revert =
            hex!("cf280be10000000000000000000000000000000000000000000000000000000000000001");

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
            input: code_with_revert.to_vec(),
        };
        let tx_create = tx_create.sign(&secret_key, Some(CHAIN_ID));
        let tx_address = tx_create.address().unwrap();

        {
            let mut executor = evm_state::Executor::default_configs(state);
            let address = secret_key.to_address();
            executor.deposit(address, U256::from(2) * 300000);
            executor.deposit(
                tx_address,
                U256::from(1_000_000_000) * U256::from(1_000_000_000),
            ); // 1ETHER

            let mut invoke_context = MockInvokeContext::with_evm(executor);
            assert!(processor
                .process_instruction(
                    &crate::ID,
                    &keyed_accounts,
                    &bincode::serialize(&EvmInstruction::ExecuteTransaction {
                        tx: ExecuteTransaction::Signed { tx: Some(tx_create) },
                        fee_type: FeePayerType::Evm,
                    })
                        .unwrap(),
                    &mut invoke_context,
                    false,
                )
                .is_ok());

            let executor = invoke_context.deconstruct().unwrap();
            let committed = executor.deconstruct().commit_block(0, Default::default());
            state = committed.next_incomming(0);
        }

        {
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
            let instruction_data =
                bincode::serialize(&EvmInstruction::ExecuteTransaction {
                    tx: ExecuteTransaction::Signed { tx: Some(tx_call) },
                    fee_type: FeePayerType::Evm,
                })
                    .unwrap();

            // Reverted tx with clear_logs_on_error enabled must clear logs
            {
                let executor = evm_state::Executor::with_config(
                    state.clone(),
                    Default::default(),
                    Default::default(),
                    FeatureSet::new_with_all_enabled(),
                );
                let mut invoke_context = MockInvokeContext::with_evm(executor);

                let _result = processor.process_instruction(
                    &crate::ID,
                    &keyed_accounts,
                    &instruction_data,
                    &mut invoke_context,
                    false,
                );
                let mut executor = invoke_context.deconstruct().unwrap();
                let tx = executor.get_tx_receipt_by_hash(tx_hash).unwrap();
                println!("status = {:?}", tx.status);
                assert!(matches!(tx.status, ExitReason::Revert(_)));
                assert!(tx.logs.is_empty());
            }

            // Reverted tx with clear_logs_on_error disabled don't clear logs
            {
                let executor = evm_state::Executor::with_config(
                    state.clone(),
                    Default::default(),
                    Default::default(),
                    FeatureSet::new(true, false),
                );
                let mut invoke_context = MockInvokeContext::with_evm(executor);
                invoke_context
                    .disable_feature(&solana_sdk::feature_set::velas::clear_logs_on_error::id());

                let _result = processor.process_instruction(
                    &crate::ID,
                    &keyed_accounts,
                    &instruction_data,
                    &mut invoke_context,
                    false,
                );
                let mut executor = invoke_context.deconstruct().unwrap();
                let tx = executor.get_tx_receipt_by_hash(tx_hash).unwrap();
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
            let instruction_data =
                bincode::serialize(&EvmInstruction::ExecuteTransaction {
                    tx: ExecuteTransaction::Signed { tx: Some(tx_call) },
                    fee_type: FeePayerType::Evm
                })
                    .unwrap();

            {
                let executor = evm_state::Executor::with_config(
                    state.clone(),
                    Default::default(),
                    Default::default(),
                    FeatureSet::new_with_all_enabled(),
                );
                let mut invoke_context = MockInvokeContext::with_evm(executor);

                let _result = processor.process_instruction(
                    &crate::ID,
                    &keyed_accounts,
                    &instruction_data,
                    &mut invoke_context,
                    false,
                );
                let mut executor = invoke_context.deconstruct().unwrap();
                let tx = executor.get_tx_receipt_by_hash(tx_hash).unwrap();
                println!("status = {:?}", tx.status);
                assert!(matches!(tx.status, ExitReason::Succeed(_)));
                assert!(!tx.logs.is_empty());
            }

            {
                let executor = evm_state::Executor::with_config(
                    state.clone(),
                    Default::default(),
                    Default::default(),
                    FeatureSet::new(true, false),
                );
                let mut invoke_context = MockInvokeContext::with_evm(executor);
                invoke_context
                    .disable_feature(&solana_sdk::feature_set::velas::clear_logs_on_error::id());

                let _result = processor.process_instruction(
                    &crate::ID,
                    &keyed_accounts,
                    &instruction_data,
                    &mut invoke_context,
                    false,
                );
                let mut executor = invoke_context.deconstruct().unwrap();
                let tx = executor.get_tx_receipt_by_hash(tx_hash).unwrap();
                println!("status = {:?}", tx.status);
                assert!(matches!(tx.status, ExitReason::Succeed(_)));
                assert!(!tx.logs.is_empty());
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
        let ix = crate::send_raw_tx(user_id, tx_create, None, FeePayerType::Evm);

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
        let ix = crate::authorized_tx(user_id, unsigned_tx, FeePayerType::Evm);

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
    fn authorized_tx_with_evm_fee_type() {
        let _ = simple_logger::SimpleLogger::new().init();
        let mut executor = evm_state::Executor::testing();
        let processor = EvmProcessor::default();

        let mut rand = evm_state::rand::thread_rng();
        let dummy_key = evm::SecretKey::new(&mut rand);
        let dummy_address = dummy_key.to_address();

        let user_id = Pubkey::new_unique();
        let user_evm_address = crate::evm_address_for_program(user_id);
        executor.deposit(user_evm_address, U256::from(30000000000u64));
        let evm_account = RefCell::new(crate::create_state_account(10));

        let unsigned_tx = evm::UnsignedTransaction {
            nonce: 0.into(),
            gas_price: 100000.into(),
            gas_limit: 300000.into(),
            action: TransactionAction::Call(dummy_address),
            value: 0.into(),
            input: hex::decode(evm_state::HELLO_WORLD_ABI).unwrap().to_vec(),
        };

        let ix = crate::authorized_tx(user_id, unsigned_tx, FeePayerType::Evm);

        let user_account = RefCell::new(solana_sdk::account::AccountSharedData {
            lamports: 0,
            data: vec![],
            owner: solana_sdk::system_program::id(),
            executable: false,
            rent_epoch: 0,
        });
        let user_keyed_account = KeyedAccount::new(&user_id, true, &user_account);
        let evm_keyed_account = KeyedAccount::new(&solana::evm_state::ID, false, &evm_account);
        let keyed_accounts = [evm_keyed_account, user_keyed_account];
        println!("Keyed accounts = {:?}", &keyed_accounts);

        let evm_balance_before = executor.balance(user_evm_address);
        let user_balance_before = user_account.try_borrow().unwrap().lamports;

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

        let executor = invoke_context.deconstruct().unwrap();
        // EVM balance has decreased
        assert!(evm_balance_before > executor.balance(user_evm_address));
        // Native balance has increased because of refund
        let evm_balance_difference = evm_balance_before - executor.balance(user_evm_address);
        assert_eq!(
            user_account.try_borrow().unwrap().lamports,
            user_balance_before + gweis_to_lamports(evm_balance_difference).0
        );
    }

    #[test]
    fn authorized_tx_with_native_fee_type() {
        let _ = simple_logger::SimpleLogger::new().init();
        let mut executor = evm_state::Executor::testing();
        let processor = EvmProcessor::default();

        let mut rand = evm_state::rand::thread_rng();
        let dummy_key = evm::SecretKey::new(&mut rand);
        let dummy_address = dummy_key.to_address();

        let user_id = Pubkey::new_unique();
        let user_evm_address = crate::evm_address_for_program(user_id);
        executor.deposit(user_evm_address, U256::from(2) * 300000);
        let evm_account = RefCell::new(crate::create_state_account(10));

        let unsigned_tx = evm::UnsignedTransaction {
            nonce: 0.into(),
            gas_price: 100000.into(),
            gas_limit: 300000.into(),
            action: TransactionAction::Call(dummy_address),
            value: 0.into(),
            input: hex::decode(evm_state::HELLO_WORLD_ABI).unwrap().to_vec(),
        };

        let ix = crate::authorized_tx(user_id, unsigned_tx, FeePayerType::Native);

        let user_account = RefCell::new(solana_sdk::account::AccountSharedData {
            lamports: 1000,
            data: vec![],
            owner: solana_sdk::system_program::id(),
            executable: false,
            rent_epoch: 0,
        });
        let user_keyed_account = KeyedAccount::new(&user_id, true, &user_account);
        let evm_keyed_account = KeyedAccount::new(&solana::evm_state::ID, false, &evm_account);
        let keyed_accounts = [evm_keyed_account, user_keyed_account];
        println!("Keyed accounts = {:?}", &keyed_accounts);

        let evm_balance_before = executor.balance(user_evm_address);
        let user_balance_before = user_account.try_borrow().unwrap().lamports;

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

        let executor = invoke_context.deconstruct().unwrap();
        // EVM balance hasn't decreased
        assert_eq!(evm_balance_before, executor.balance(user_evm_address));
        // Native balance refunded
        assert_eq!(
            user_balance_before,
            user_account.try_borrow().unwrap().lamports
        );
    }

    // Transaction with fee type Native should be executed correctly if signer has no balance on evm account
    #[test]
    fn evm_transaction_with_native_fee_type_and_zero_evm_balance() {
        let _logger = simple_logger::SimpleLogger::new().init();
        let executor = evm_state::Executor::testing();
        let processor = EvmProcessor::default();

        let evm_account = RefCell::new(crate::create_state_account(100));
        let evm_keyed_account = KeyedAccount::new(&solana::evm_state::ID, false, &evm_account);

        let user_id = Pubkey::new_unique();
        let user_evm_address = crate::evm_address_for_program(user_id);
        let user_account = RefCell::new(solana_sdk::account::AccountSharedData {
            lamports: 1000,
            data: vec![],
            owner: solana_sdk::system_program::id(),
            executable: false,
            rent_epoch: 0,
        });
        let user_keyed_account = KeyedAccount::new(&user_id, true, &user_account);

        let keyed_accounts = [evm_keyed_account, user_keyed_account];
        let secret_key = evm::SecretKey::from_slice(&SECRET_KEY_DUMMY).unwrap();
        let tx_create = evm::UnsignedTransaction {
            nonce: 0.into(),
            gas_price: 100000.into(),
            gas_limit: 300000.into(),
            action: TransactionAction::Create,
            value: 0.into(),
            input: hex::decode(evm_state::HELLO_WORLD_CODE).unwrap().to_vec(),
        };
        // Signer has zero balance but fee will be taken from native account
        assert_eq!(executor.balance(user_evm_address), U256::from(0));
        let tx_create = tx_create.sign(&secret_key, Some(CHAIN_ID));
        let ix = crate::send_raw_tx(user_id, tx_create, None, FeePayerType::Native);

        let user_balance_before = user_account.try_borrow().unwrap().lamports;

        let mut invoke_context = MockInvokeContext::with_evm(executor);
        assert!(processor
            .process_instruction(
                &crate::ID,
                &keyed_accounts,
                &ix.data,
                &mut invoke_context,
                false,
            )
            .is_ok());

        let executor = invoke_context.deconstruct().unwrap();
        // Native balance refunded
        assert_eq!(
            user_balance_before,
            user_account.try_borrow().unwrap().lamports
        );
        assert_eq!(executor.balance(user_evm_address), U256::from(0));
    }

    // In case when fee type Native chosen but no native account provided fee will be taken from signer (EVM)
    #[test]
    fn evm_transaction_with_native_fee_type_and_and_no_native_account_provided() {
        let _logger = simple_logger::SimpleLogger::new().init();
        let mut executor = evm_state::Executor::testing();
        let processor = EvmProcessor::default();

        let evm_account = RefCell::new(crate::create_state_account(0));
        let evm_keyed_account = KeyedAccount::new(&solana::evm_state::ID, false, &evm_account);

        let keyed_accounts = [evm_keyed_account];
        let secret_key = evm::SecretKey::from_slice(&SECRET_KEY_DUMMY).unwrap();
        let signer_evm_address = secret_key.to_address();
        executor.deposit(signer_evm_address, U256::from(30000000000u64));
        let tx_create = evm::UnsignedTransaction {
            nonce: 0.into(),
            gas_price: 100000.into(),
            gas_limit: 300000.into(),
            action: TransactionAction::Create,
            value: 0.into(),
            input: hex::decode(evm_state::HELLO_WORLD_CODE).unwrap().to_vec(),
        };
        // Signer has zero balance
        let tx_create = tx_create.sign(&secret_key, Some(CHAIN_ID));
        //let ix = crate::send_raw_tx(user_id, tx_create, None, FeePayerType::Native);
        let mut buf = vec![EVM_INSTRUCTION_BORSH_PREFIX];
        BorshSerialize::serialize(
            &EvmInstruction::new_execute_tx(tx_create, FeePayerType::Native),
            &mut buf,
        )
        .unwrap();

        let evm_balance_before = executor.balance(signer_evm_address);

        let mut invoke_context = MockInvokeContext::with_evm(executor);
        assert!(processor
            .process_instruction(
                &crate::ID,
                &keyed_accounts,
                &buf,
                &mut invoke_context,
                false,
            )
            .is_ok());

        let executor = invoke_context.deconstruct().unwrap();
        assert!(evm_balance_before > executor.balance(signer_evm_address));
    }

    #[test]
    fn evm_transaction_native_fee_handled_correctly_with_exit_reason_not_succeed() {
        let _logger = simple_logger::SimpleLogger::new().init();
        let executor = evm_state::Executor::testing();
        let processor = EvmProcessor::default();

        let evm_account = RefCell::new(crate::create_state_account(100));
        let evm_keyed_account = KeyedAccount::new(&solana::evm_state::ID, false, &evm_account);

        let user_id = Pubkey::new_unique();
        let user_account = RefCell::new(solana_sdk::account::AccountSharedData {
            lamports: 1000,
            data: vec![],
            owner: solana_sdk::system_program::id(),
            executable: false,
            rent_epoch: 0,
        });
        let user_keyed_account = KeyedAccount::new(&user_id, true, &user_account);

        let keyed_accounts = [evm_keyed_account, user_keyed_account];
        let secret_key = evm::SecretKey::from_slice(&SECRET_KEY_DUMMY).unwrap();
        let tx_create = evm::UnsignedTransaction {
            nonce: 0.into(),
            gas_price: 100000.into(),
            gas_limit: 3000.into(),
            action: TransactionAction::Create,
            value: 0.into(),
            input: hex::decode(evm_state::HELLO_WORLD_CODE).unwrap().to_vec(),
        };
        let tx_create = tx_create.sign(&secret_key, Some(CHAIN_ID));
        let ix = crate::send_raw_tx(user_id, tx_create, None, FeePayerType::Native);

        let user_balance_before = user_account.try_borrow().unwrap().lamports;

        let mut invoke_context = MockInvokeContext::with_evm(executor);
        assert!(processor
            .process_instruction(
                &crate::ID,
                &keyed_accounts,
                &ix.data,
                &mut invoke_context,
                false,
            )
            .is_err());

        assert_eq!(
            user_balance_before,
            user_account.try_borrow().unwrap().lamports
        );
    }

    #[test]
    fn evm_transaction_with_insufficient_native_funds() {
        let _logger = simple_logger::SimpleLogger::new().init();
        let executor = evm_state::Executor::testing();
        let processor = EvmProcessor::default();

        let evm_account = RefCell::new(crate::create_state_account(100));
        let evm_keyed_account = KeyedAccount::new(&solana::evm_state::ID, false, &evm_account);

        let user_id = Pubkey::new_unique();
        let user_evm_address = crate::evm_address_for_program(user_id);
        let user_account = RefCell::new(solana_sdk::account::AccountSharedData {
            lamports: 1,
            data: vec![],
            owner: solana_sdk::system_program::id(),
            executable: false,
            rent_epoch: 0,
        });
        let user_keyed_account = KeyedAccount::new(&user_id, true, &user_account);

        let keyed_accounts = [evm_keyed_account, user_keyed_account];
        let secret_key = evm::SecretKey::from_slice(&SECRET_KEY_DUMMY).unwrap();
        let tx_create = evm::UnsignedTransaction {
            nonce: 0.into(),
            gas_price: 100000.into(),
            gas_limit: 300000.into(),
            action: TransactionAction::Create,
            value: 0.into(),
            input: hex::decode(evm_state::HELLO_WORLD_CODE).unwrap().to_vec(),
        };
        // Signer has zero balance but fee will be taken from native account
        assert_eq!(executor.balance(user_evm_address), U256::from(0));
        let tx_create = tx_create.sign(&secret_key, Some(CHAIN_ID));
        let ix = crate::send_raw_tx(user_id, tx_create, None, FeePayerType::Native);

        let user_balance_before = user_account.try_borrow().unwrap().lamports;
        let user_evm_balance_before = executor.balance(user_evm_address);

        let mut invoke_context = MockInvokeContext::with_evm(executor);
        assert!(processor
            .process_instruction(
                &crate::ID,
                &keyed_accounts,
                &ix.data,
                &mut invoke_context,
                false,
            )
            .is_err());

        let executor = invoke_context.deconstruct().unwrap();
        // All balances remain the same
        assert_eq!(
            user_balance_before,
            user_account.try_borrow().unwrap().lamports
        );
        assert_eq!(user_evm_balance_before, executor.balance(user_evm_address));
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
