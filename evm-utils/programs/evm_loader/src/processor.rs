use std::cell::RefMut;
use std::fmt::Write;
use std::ops::DerefMut;

use super::account_structure::AccountStructure;
use super::instructions::{EvmBigTransaction, EvmInstruction};
use super::precompiles;
use super::scope::*;
use evm_state::U256;
use log::*;

use evm::{gweis_to_lamports, Executor, ExitReason};
use solana_sdk::account::{AccountSharedData, ReadableAccount, WritableAccount};
use solana_program_runtime::ic_msg;
use solana_program_runtime::invoke_context::InvokeContext;
use solana_sdk::instruction::InstructionError;
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
        first_keyed_account: usize,
        data: &[u8],
        invoke_context: &mut InvokeContext,
    ) -> Result<(), InstructionError> {
        let (evm_state_account, keyed_accounts) = Self::check_evm_account(first_keyed_account, &invoke_context)?;

        let cross_execution_enabled = invoke_context
            .feature_set.is_active(&solana_sdk::feature_set::velas::evm_cross_execution::id());
        let register_swap_tx_in_evm = invoke_context
            .feature_set.is_active(&solana_sdk::feature_set::velas::native_swap_in_evm_history::id());
        let new_error_handling = invoke_context
            .feature_set.is_active(&solana_sdk::feature_set::velas::evm_new_error_handling::id());
        let unsigned_tx_fix = invoke_context
            .feature_set.is_active(&solana_sdk::feature_set::velas::unsigned_tx_fix::id());
        let ignore_reset_on_cleared = invoke_context
            .feature_set.is_active(&solana_sdk::feature_set::velas::ignore_reset_on_cleared::id());
        let free_ownership_require_signer = invoke_context.feature_set.is_active(
            &solana_sdk::feature_set::velas::free_ownership_require_signer::id(),
        );
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
                unsigned_tx_fix,
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

    fn process_raw_tx(
        &self,
        executor: &mut Executor,
        invoke_context: &InvokeContext,
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

        self.handle_transaction_result(
            executor,
            invoke_context,
            accounts,
            sender,
            tx_gas_price,
            result,
        )
    }

    fn process_authorized_tx(
        &self,
        executor: &mut Executor,
        invoke_context: &InvokeContext,
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
                    "EvmAuthorizedTransaction: Incorrect caller program_caller:{}, program_owner:{}",
                    program_caller, program_owner,
                );
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

        let user_account_lamports = user_account.lamports().saturating_sub( lamports);
        user_account.set_lamports(user_account_lamports);
        let mut evm_account = accounts
            .evm
            .try_account_ref_mut()
            .map_err(|_| EvmError::BorrowingFailed)?;

        let evm_account_lamports = evm_account.lamports().saturating_add(lamports);
        evm_account.set_lamports(evm_account_lamports);
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
        invoke_context: &InvokeContext,
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
                    let program_owner = *program_account
                        .try_account_ref()
                        .map_err(|_| EvmError::BorrowingFailed)?
                        .owner();
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

                self.cleanup_storage(invoke_context, storage, program_account)?;
                self.handle_transaction_result(
                    executor,
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
        invoke_context: &InvokeContext,
        mut storage_ref: RefMut<AccountSharedData>,
        user: &'a KeyedAccount<'a>,
    ) -> Result<(), EvmError> {
        let balance = storage_ref.lamports();

        storage_ref.set_lamports(0);

        let mut user_acc = user.try_account_ref_mut()
            .map_err(|_| EvmError::BorrowingFailed)?;
        let user_acc_lamports = user_acc.lamports().saturating_add( balance);
        user_acc.set_lamports(user_acc_lamports);

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
        executor: &mut Executor,
        invoke_context: &InvokeContext,
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
    fn check_evm_account<'a>(
        first_keyed_account: usize,
        invoke_context: &'a InvokeContext,
    ) -> Result<(&'a KeyedAccount<'a>, &'a [KeyedAccount<'a>]), InstructionError> {
        let keyed_accounts =  invoke_context.get_keyed_accounts()?;
        let first = keyed_accounts
            .get(first_keyed_account)
            .ok_or(InstructionError::NotEnoughAccountKeys)?;

        trace!("first = {:?}", first);
        trace!("all = {:?}", keyed_accounts);
        if first.unsigned_key() != &solana::evm_state::id() || !first.is_writable() {
            debug!("First account is not evm, or not writable");
            return Err(InstructionError::MissingAccount);
        }

        let keyed_accounts = &keyed_accounts[(first_keyed_account+1)..];
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
        FromKey,
    };
    use evm_state::{AccountProvider, ExitReason, ExitSucceed};
    use primitive_types::{H160, H256, U256};
    use solana_sdk::{instruction::{AccountMeta, Instruction}, message::{SanitizedMessage, Message}};
    use solana_sdk::native_loader;
    use solana_program_runtime::{invoke_context::{InvokeContext, BuiltinProgram}, timings::ExecuteTimings};
    use solana_sdk::program_utils::limited_deserialize;
    use solana_sdk::sysvar::rent::Rent;

    type MutableAccount = Rc<RefCell<AccountSharedData>>;

    // Testing object that emulate Bank work, and can execute transactions.
    // Emulate batch of native transactions.
    #[derive(Debug)]
    struct EvmMockContext {
        evm_state: evm_state::EvmBackend<evm_state::Incomming>,
        evm_state_account: MutableAccount,
        rest_accounts: BTreeMap<Pubkey, MutableAccount>,
    }

    impl EvmMockContext {
        fn new(evm_balance: u64) -> Self {

            let _logger = simple_logger::SimpleLogger::new().init();
            Self {
                evm_state: evm_state::EvmBackend::default(),
                evm_state_account: Rc::new(RefCell::new(crate::create_state_account(evm_balance))),
                rest_accounts: Default::default()
            }
        }

        fn native_account(&mut self, pubkey: Pubkey) -> MutableAccount {
            if pubkey == solana::evm_state::id() {
                self.evm_state_account.clone()
            } else if pubkey == crate::ID {
                Rc::new(RefCell::new(AccountSharedData::new(1,0, &native_loader::ID)))
            }
            else {
                let entry = self.rest_accounts.entry(pubkey).or_default();
                entry.clone()
            }
        }
        fn process_instruction(&mut self, ix: Instruction) -> Result<(), InstructionError> {
            self.process_transaction(vec![ix])
        }

        fn deposit_evm(&mut self, evm_addr: evm_state::Address, amount: evm_state::U256) {
            let mut account_state = self.evm_state.get_account_state(evm_addr).unwrap_or_default();
            account_state.balance += amount;
            self.evm_state.set_account_state(evm_addr, account_state)
        }


        // Emulate native transaction
        fn process_transaction(&mut self, ixs: Vec<Instruction> ) -> Result<(), InstructionError> {
            let evm_state_clone = self.evm_state.clone();
            let evm_executor = evm_state::Executor::with_config(evm_state_clone, Default::default(), Default::default());

            let evm_program = BuiltinProgram {
                program_id: solana_sdk::evm_loader::id(),
                process_instruction: |acc, data, context| {
                    let processor = EvmProcessor::default();
                    processor.process_instruction(acc,
                        data,
                        context,
                    )
                }
            };
            let builtins = &[evm_program];

            let message = SanitizedMessage::Legacy(Message::new(
                &ixs,
                None,
            ));
            let message_keys: Vec<_> = message
                .account_keys_iter().copied().collect();
            let uniq_keys: BTreeSet<_> = message
                .account_keys_iter().copied().collect();
            assert_eq!(message_keys.len(), uniq_keys.len(), "Message contain dublicate keys.");
            let program_index = message_keys.iter().position(|k| *k == crate::ID).unwrap_or(message_keys.len());
            let keys: Vec<_> = message_keys.into_iter().map(|pubkey|(pubkey, self.native_account(pubkey))).collect();

            let mut invoke_context = InvokeContext::new_mock_evm(&keys, evm_executor, builtins);
            for instruction in message.instructions() {

                if let Err(e) = invoke_context.process_instruction(&message, instruction, &[program_index], &[],
                    &[], &mut ExecuteTimings::default()).result {
                    let executor = invoke_context.deconstruct_evm().expect("Evm executor should exist");
                    self.evm_state.apply_failed_update(&executor.evm_backend);
                    return Err(e)
                }
            }
            let executor = invoke_context.deconstruct_evm().expect("Evm executor should exist");
            self.evm_state = executor.evm_backend;
            Ok(())

        }
    }

    use super::TEST_CHAIN_ID as CHAIN_ID;
    use std::{cell::RefCell, rc::Rc, collections::{BTreeMap, BTreeSet}};

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
        let mut evm_context = EvmMockContext::new(0);
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
            .process_instruction(
                crate::send_raw_tx(Pubkey::new_unique(), tx_create.clone(), None)
            )
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
            .process_instruction(
                crate::send_raw_tx(Pubkey::new_unique(), tx_call, None)
            )
            .is_ok());
        assert!(evm_context.evm_state.find_transaction_receipt(tx_hash).is_some())
    }

    #[test]
    fn deploy_tx_refund_fee() {
        let init_evm_balance = 1000000;
        let mut evm_context = EvmMockContext::new(init_evm_balance);
        let user_id = Pubkey::new_unique();
        evm_context.native_account(user_id).borrow_mut().set_owner(crate::ID);

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
            .process_instruction(
                crate::send_raw_tx(user_id, tx_create , None)
            )
            .is_ok());
        let used_gas_for_hello_world_deploy = 114985;
        let fee = used_gas_for_hello_world_deploy; // price is 1lamport
        assert_eq!(evm_context.native_account(user_id).borrow().lamports(), fee);
        assert_eq!(
            evm_context.native_account(solana::evm_state::id()).borrow().lamports(),
            init_evm_balance + 1 // evm balance is always has 1 lamports reserve, because it is system account
                             - fee
        );
    }

    #[test]
    fn tx_preserve_nonce() {
        let mut evm_context = EvmMockContext::new(0);
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
            .process_instruction(
                crate::send_raw_tx(Pubkey::new_unique(), tx_1_sign.clone(), None)
            )
            .is_err());

        // First tx should execute successfully.

        assert!(evm_context
            .process_instruction(
                crate::send_raw_tx(Pubkey::new_unique(), tx_0_sign.clone(), None)
            )
            .is_ok());

        // Executing copy of first tx with different signature, should not pass too.
        assert!(evm_context
            .process_instruction(
                crate::send_raw_tx(Pubkey::new_unique(), tx_0_shadow_sign.clone(), None)
            )
            .is_err());


        // But executing of second tx now should succeed.
        assert!(evm_context
            .process_instruction(
                crate::send_raw_tx(Pubkey::new_unique(), tx_1_sign.clone(), None)
            )
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
            .process_instruction(
                crate::send_raw_tx(Pubkey::new_unique(), tx_0_sign, None)
            )
            .is_err());

    }

    #[test]
    fn execute_tx_with_state_apply() {
        let mut evm_context = EvmMockContext::new(0);

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
            evm_context.evm_state
                .get_account_state(caller_address)
                .map(|account| account.nonce),
            None,
        );
        assert_eq!(
            evm_context.evm_state
                .get_account_state(tx_address)
                .map(|account| account.nonce),
            None,
        );
        {
            let address = secret_key.to_address();
            evm_context.deposit_evm(address, U256::from(2u32) * 300000u32);

            assert!(evm_context
                .process_instruction(
                    crate::send_raw_tx(Pubkey::new_unique(), tx_create, None)
                )
                .is_ok());
        }

        assert_eq!(
            evm_context.evm_state
                .get_account_state(caller_address)
                .map(|account| account.nonce),
            Some(1u32.into())
        );
        assert_eq!(
            evm_context.evm_state
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
                .process_instruction(
                    crate::send_raw_tx(Pubkey::new_unique(), tx_call, None)
                )
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
        acc.borrow_mut().set_owner(crate::ID);
        acc.borrow_mut().set_lamports(1000);

        let ether_dummy_address = H160::repeat_byte(0x11);

        let lamports_before = evm_context.native_account(solana::evm_state::id()).borrow().lamports();

        assert!(evm_context
            .process_instruction(
                crate::transfer_native_to_evm(user_id, 1000, ether_dummy_address)
            )
            .is_ok());


        assert_eq!(
            evm_context.native_account(solana::evm_state::id()).borrow().lamports(),
            lamports_before + 1000
        );
        assert_eq!(
            evm_context.native_account(user_id).borrow().lamports(),
            0
        );
        assert!(evm_context
            .process_instruction(
                crate::free_ownership(user_id)
            )
            .is_ok());
        assert_eq!(
            *evm_context.native_account(user_id).borrow().owner(),
            solana_sdk::system_program::id()
        );

        assert_eq!(
            evm_context.evm_state
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
        acc.borrow_mut().set_owner(crate::ID);
        acc.borrow_mut().set_lamports(1000);

        let mut rand = evm_state::rand::thread_rng();
        let ether_sc = evm::SecretKey::new(&mut rand);
        let ether_dummy_address = ether_sc.to_address();
        
        let lamports_before = evm_context.native_account(solana::evm_state::id()).borrow().lamports();

        let lamports_to_send = 1000;
        let lamports_to_send_back = 300;

        assert!(evm_context
            .process_instruction(
                crate::transfer_native_to_evm(user_id, lamports_to_send, ether_dummy_address)
            )
            .is_ok());


        assert_eq!(
            evm_context.native_account(solana::evm_state::id()).borrow().lamports(),
            lamports_before + lamports_to_send
        );
        assert_eq!(
            evm_context.native_account(user_id).borrow().lamports(),
            0
        );
        assert!(evm_context
            .process_instruction(
                crate::free_ownership(user_id)
            )
            .is_ok());
        assert_eq!(
            *evm_context.native_account(user_id).borrow().owner(),
            solana_sdk::system_program::id()
        );

        assert_eq!(
            evm_context.evm_state
                .get_account_state(ether_dummy_address)
                .unwrap()
                .balance,
            crate::scope::evm::lamports_to_gwei(1000)
        );

        // Transfer back

        let second_user_id = Pubkey::new_unique();
        let second_user = evm_context.native_account(second_user_id);
        second_user.borrow_mut().set_owner(crate::ID);

        let tx_call = evm::UnsignedTransaction {
            nonce: 0u32.into(),
            gas_price: 1u32.into(),
            gas_limit: 300000u32.into(),
            action: TransactionAction::Call(*precompiles::ETH_TO_VLX_ADDR),
            value: crate::scope::evm::lamports_to_gwei(lamports_to_send_back),
            input: precompiles::ETH_TO_VLX_CODE
                .abi
                .encode_input(&[ethabi::Token::FixedBytes(second_user_id.to_bytes().to_vec())])
                .unwrap(),
        };

        let tx_call = tx_call.sign(&ether_sc, Some(CHAIN_ID));
        {
            let ix = crate::send_raw_tx(Pubkey::new_unique(), tx_call, None);
            // if we don't add second account to account list, insctruction should fail
            let result = evm_context.process_instruction(
                ix
            );

            result.unwrap_err();

            evm_context.evm_state = evm_context.evm_state.commit_block(0, Default::default()).next_incomming(0);
            assert_eq!(
                evm_context.evm_state
                    .get_account_state(*precompiles::ETH_TO_VLX_ADDR)
                    .unwrap()
                    .balance,
                0u32.into()
            )
        }

        // Nothing should change, because of error
        assert_eq!(
            evm_context.native_account(solana::evm_state::id()).borrow().lamports(),
            lamports_before + lamports_to_send
        );
        assert_eq!(
            evm_context.native_account(user_id).borrow().lamports(),
            0
        );
        assert_eq!(
            evm_context.native_account(second_user_id).borrow().lamports(),
            0
        );

        assert_eq!(
            evm_context.evm_state
            .get_account_state(ether_dummy_address)
            .unwrap()
            .balance,
            crate::scope::evm::lamports_to_gwei(lamports_to_send)
        );

    }

    #[test]
    fn execute_transfer_roundtrip() {
        let mut evm_context = EvmMockContext::new(0);

        let user_id = Pubkey::new_unique();
        let acc = evm_context.native_account(user_id);
        acc.borrow_mut().set_owner(crate::ID);
        acc.borrow_mut().set_lamports(1000);

        let mut rand = evm_state::rand::thread_rng();
        let ether_sc = evm::SecretKey::new(&mut rand);
        let ether_dummy_address = ether_sc.to_address();
        
        let lamports_before = evm_context.native_account(solana::evm_state::id()).borrow().lamports();

        let lamports_to_send = 1000;
        let lamports_to_send_back = 300;

        assert!(evm_context
            .process_instruction(
                crate::transfer_native_to_evm(user_id, lamports_to_send, ether_dummy_address)
            )
            .is_ok());


        assert_eq!(
            evm_context.native_account(solana::evm_state::id()).borrow().lamports(),
            lamports_before + lamports_to_send
        );
        assert_eq!(
            evm_context.native_account(user_id).borrow().lamports(),
            0
        );
        assert!(evm_context
            .process_instruction(
                crate::free_ownership(user_id)
            )
            .is_ok());
        assert_eq!(
            *evm_context.native_account(user_id).borrow().owner(),
            solana_sdk::system_program::id()
        );

        assert_eq!(
            evm_context.evm_state
                .get_account_state(ether_dummy_address)
                .unwrap()
                .balance,
            crate::scope::evm::lamports_to_gwei(1000)
        );

        // Transfer back

        let second_user_id = Pubkey::new_unique();
        let second_user = evm_context.native_account(second_user_id);
        second_user.borrow_mut().set_owner(crate::ID);

        let tx_call = evm::UnsignedTransaction {
            nonce: 0u32.into(),
            gas_price: 1u32.into(),
            gas_limit: 300000u32.into(),
            action: TransactionAction::Call(*precompiles::ETH_TO_VLX_ADDR),
            value: crate::scope::evm::lamports_to_gwei(lamports_to_send_back),
            input: precompiles::ETH_TO_VLX_CODE
                .abi
                .encode_input(&[ethabi::Token::FixedBytes(second_user_id.to_bytes().to_vec())])
                .unwrap(),
        };

        let tx_call = tx_call.sign(&ether_sc, Some(CHAIN_ID));
        {
            let mut ix = crate::send_raw_tx(Pubkey::new_unique(), tx_call, None);
            // add second account to account list, because we need account to be able to credit
            ix.accounts.push(AccountMeta::new(second_user_id,false));
            let result = evm_context.process_instruction(
                ix
            );

            dbg!(&evm_context);
            result.unwrap();

            evm_context.evm_state = evm_context.evm_state.commit_block(0, Default::default()).next_incomming(0);
            assert_eq!(
                evm_context.evm_state
                    .get_account_state(*precompiles::ETH_TO_VLX_ADDR)
                    .unwrap()
                    .balance,
                0u32.into()
            )
        }

        assert_eq!(
            evm_context.native_account(solana::evm_state::id()).borrow().lamports(),
            lamports_before + lamports_to_send- lamports_to_send_back
        );
        assert_eq!(
            evm_context.native_account(user_id).borrow().lamports(),
            0
        );
        assert_eq!(
            evm_context.native_account(second_user_id).borrow().lamports(),
            lamports_to_send_back
        );

        assert!(
            evm_context.evm_state
                .get_account_state(ether_dummy_address)
                .unwrap()
                .balance
                < crate::scope::evm::lamports_to_gwei(lamports_to_send - lamports_to_send_back)
                && evm_context.evm_state
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
        acc.borrow_mut().set_owner(crate::ID);
        acc.borrow_mut().set_lamports(1000);

        let mut rand = evm_state::rand::thread_rng();
        let ether_sc = evm::SecretKey::new(&mut rand);
        let ether_dummy_address = ether_sc.to_address();
        
        let lamports_before = evm_context.native_account(solana::evm_state::id()).borrow().lamports();

        let lamports_to_send = 1000;
        let lamports_to_send_back = 1001;

        assert!(evm_context
            .process_instruction(
                crate::transfer_native_to_evm(user_id, lamports_to_send, ether_dummy_address)
            )
            .is_ok());


        assert_eq!(
            evm_context.native_account(solana::evm_state::id()).borrow().lamports(),
            lamports_before + lamports_to_send
        );
        assert_eq!(
            evm_context.native_account(user_id).borrow().lamports(),
            0
        );
        assert!(evm_context
            .process_instruction(
                crate::free_ownership(user_id)
            )
            .is_ok());
        assert_eq!(
            *evm_context.native_account(user_id).borrow().owner(),
            solana_sdk::system_program::id()
        );

        assert_eq!(
            evm_context.evm_state
                .get_account_state(ether_dummy_address)
                .unwrap()
                .balance,
            crate::scope::evm::lamports_to_gwei(1000)
        );

        // Transfer back

        let second_user_id = Pubkey::new_unique();
        let second_user = evm_context.native_account(second_user_id);
        second_user.borrow_mut().set_owner(crate::ID);

        let tx_call = evm::UnsignedTransaction {
            nonce: 0u32.into(),
            gas_price: 1u32.into(),
            gas_limit: 300000u32.into(),
            action: TransactionAction::Call(*precompiles::ETH_TO_VLX_ADDR),
            value: crate::scope::evm::lamports_to_gwei(lamports_to_send_back),
            input: precompiles::ETH_TO_VLX_CODE
                .abi
                .encode_input(&[ethabi::Token::FixedBytes(second_user_id.to_bytes().to_vec())])
                .unwrap(),
        };

        let tx_call = tx_call.sign(&ether_sc, Some(CHAIN_ID));
        {
            let mut ix = crate::send_raw_tx(Pubkey::new_unique(), tx_call, None);
            // add second account to account list, because we need account to be able to credit
            ix.accounts.push(AccountMeta::new(second_user_id,false));
            let result = evm_context.process_instruction(
                ix
            );

            result.unwrap_err();

            evm_context.evm_state = evm_context.evm_state.commit_block(0, Default::default()).next_incomming(0);
            assert_eq!(
                evm_context.evm_state
                    .get_account_state(*precompiles::ETH_TO_VLX_ADDR)
                    .unwrap()
                    .balance,
                0u32.into()
            )
        }

        // Nothing should change, because of error
        assert_eq!(
            evm_context.native_account(solana::evm_state::id()).borrow().lamports(),
            lamports_before + lamports_to_send
        );
        assert_eq!(
            evm_context.native_account(user_id).borrow().lamports(),
            0
        );
        assert_eq!(
            evm_context.native_account(second_user_id).borrow().lamports(),
            0
        );

        assert_eq!(
            evm_context.evm_state
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
            crate::send_raw_tx(signer, tx_call, None),
            crate::authorized_tx(signer, unsigned_tx),
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
            }.into(),
            _rest => solana_sdk::account::Account {
                lamports: 20000000,
                owner: Pubkey::default(), 
                data: vec![0u8],
                executable: false,
                rent_epoch: 0,
            }.into(),
        }
    }

    #[test]
    fn each_solana_tx_should_contain_writeable_evm_state() {

        for ix in all_ixs() {
            // Create clear executor for each run, to avoid state conflicts in instructions (signed and unsigned tx with same nonce).
            let mut evm_context = EvmMockContext::new(0);

            let secret_key = evm::SecretKey::from_slice(&SECRET_KEY_DUMMY).unwrap();
            evm_context.deposit_evm(secret_key.to_address(), U256::from(2u32) * 300000u32); // deposit some small amount for gas payments
                                                                               // insert new accounts, if some missing
            for acc in &ix.accounts {
                // also deposit to instruction callers shadow evm addresses (to allow authorized tx call)
                evm_context.deposit_evm(
                    crate::evm_address_for_program(acc.pubkey),
                    U256::from(2u32) * 300000u32,
                );
                *evm_context.native_account(acc.pubkey).borrow_mut() = account_by_key(acc.pubkey);
            }

            let data: EvmInstruction = limited_deserialize(&ix.data).unwrap();
            match data {
                EvmInstruction::SwapNativeToEther { .. } | EvmInstruction::FreeOwnership { .. } => {
                    let acc = ix.accounts[1].pubkey;
                    // EVM should only operate with accounts that it owns.
                    evm_context.native_account(acc).borrow_mut().set_owner(crate::ID)
                }
                _ => {}
            }

            // First execution without evm state key, should fail.
            let mut ix_clone = ix.clone();
            ix_clone.accounts = ix_clone.accounts[1..].to_vec();
            let err = evm_context
                .process_instruction(
                    ix_clone
                )
                .unwrap_err();
            match err {
                InstructionError::NotEnoughAccountKeys | InstructionError::MissingAccount => {}
                rest => panic!("Unexpected result = {:?}", rest),
            }

            // Because first execution is fail, state didn't changes, and second execution should pass.
            let result = evm_context
                .process_instruction(
                ix
            );
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
            if !revert {
                continue;
            }
            let mut evm_context = EvmMockContext::new(1_000_000_000);
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
                    .process_instruction(crate::send_raw_tx(Pubkey::new_unique(), tx_create, None)  ) .unwrap();
                evm_context.evm_state = evm_context.evm_state.commit_block(0, Default::default()).next_incomming(0);
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
                let mut ix = crate::send_raw_tx(Pubkey::new_unique(), tx_call, None);
                ix.accounts.push(AccountMeta::new(receiver, false));
                let result = evm_context.process_instruction(
                    ix
                );
                if !revert {
                    result.unwrap();
                } else {
                    assert_eq!(result.unwrap_err(), EvmError::RevertTransaction.into())
                }
                
                let tx = evm_context.evm_state.find_transaction_receipt(tx_hash).unwrap();
                if revert {
                    println!("status = {:?}", tx.status);
                    assert!(matches!(tx.status, ExitReason::Revert(_)));
                }

                evm_context.evm_state = evm_context.evm_state.commit_block(1, Default::default()).next_incomming(0);

                let lamports = evm_context.native_account(receiver).borrow().lamports();
                if !revert {
                    assert_eq!(
                        evm_context.evm_state.get_account_state(tx_address).unwrap().balance,
                        0u32.into()
                    );
                    assert_eq!(lamports, 1_000_000_000)
                } else {
                    assert_eq!(
                        evm_context.evm_state.get_account_state(tx_address).unwrap().balance,
                        U256::from(1_000_000_000u64) * U256::from(1_000_000_000u64)
                    );
                    // assert_eq!(lamports, 0); // solana runtime will revert this account
                }
            }
        }
    }

    #[test]
    fn authorized_tx_only_from_signer() {
        let mut evm_context = EvmMockContext::new(0);

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
        
        evm_context.native_account(user_id).borrow_mut().set_lamports(1000);

        let dummy_address = tx_create.address().unwrap();

        evm_context
            .process_instruction(
                crate::send_raw_tx(user_id, tx_create, None)
            )
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
        let ix = crate::authorized_tx(user_id, unsigned_tx);
        let mut ix_clone = ix.clone();
        // remove signer marker from account meta to simulate unsigned tx
        ix_clone.accounts.last_mut().unwrap().is_signer = false;
        
        
        // First execution without signer user key, should fail.
        let err = evm_context.process_instruction(
            ix_clone
        )
            .unwrap_err();

        match err {
            e @ InstructionError::Custom(_) => {
                assert_eq!(e, crate::error::EvmError::MissingRequiredSignature.into())
            } // new_error_handling feature always activated at MockInvokeContext
            rest => panic!("Unexpected result = {:?}", rest),
        }
        // Because first execution is fail, state didn't changes, and second execution should pass.
        evm_context.process_instruction(
            ix
        )
            .unwrap();
    }

    #[test]
    fn big_tx_allocation_error() {
        let mut evm_context = EvmMockContext::new(0);

        let user_id = Pubkey::new_unique();
        let user_acc = evm_context.native_account(user_id);
        user_acc.borrow_mut().set_data(vec![0; evm_state::MAX_TX_LEN as usize]);
        user_acc.borrow_mut().set_owner(crate::ID);
        user_acc.borrow_mut().set_lamports(1000);

        evm_context
            .process_instruction(
                crate::big_tx_allocate(user_id, evm_state::MAX_TX_LEN as usize + 1)
            )
            .unwrap_err();


        evm_context
            .process_instruction(
                crate::big_tx_allocate(user_id, evm_state::MAX_TX_LEN as usize )
            )
            .unwrap();
    }

    #[test]
    fn big_tx_write_out_of_bound() {
        let batch_size: usize = 500;

        
        let mut evm_context = EvmMockContext::new(0);

        let user_id = Pubkey::new_unique();
        let user_acc = evm_context.native_account(user_id);
        user_acc.borrow_mut().set_data(vec![0; batch_size as usize]);
        user_acc.borrow_mut().set_owner(crate::ID);
        user_acc.borrow_mut().set_lamports(1000);


        evm_context
            .process_instruction(
                crate::big_tx_allocate(user_id, batch_size)
            )
            .unwrap();
            

        // out of bound write
        evm_context
            .process_instruction(
                crate::big_tx_write(user_id, batch_size as u64,  vec![1])
            )
            .unwrap_err();

        // out of bound write
        
        evm_context
            .process_instruction(
                crate::big_tx_write(user_id, 0,  vec![1; batch_size + 1])
            )
            .unwrap_err();


        // Write in bounds
        evm_context
            .process_instruction(
                crate::big_tx_write(user_id, 0,  vec![1; batch_size])
            )
            .unwrap();
        // Overlaped writes is allowed
        evm_context
        .process_instruction(
            crate::big_tx_write(user_id, batch_size as u64-1,  vec![1 ])
        )
        .unwrap();
        // make sure that data has been changed
        assert_eq!(evm_context.native_account(user_id).borrow().data(), vec![1;batch_size]);
    }

    #[test]
    fn big_tx_write_without_alloc() {
        let batch_size: usize = 500;
        
        let mut evm_context = EvmMockContext::new(0);

        let user_id = Pubkey::new_unique();
        let user_acc = evm_context.native_account(user_id);
        // skip allocate and assign instruction
        // user_acc.borrow_mut().set_data(vec![0; batch_size as usize]);
        user_acc.borrow_mut().set_owner(crate::ID);
        user_acc.borrow_mut().set_lamports(1000);

        evm_context
        .process_instruction(
            crate::big_tx_write(user_id, 0,  vec![1; batch_size])
        )
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
