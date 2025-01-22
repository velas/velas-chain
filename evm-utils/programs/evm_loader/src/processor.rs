use {
    super::{
        account_structure::AccountStructure,
        error::EvmError,
        evm_state_subchain_account,
        instructions::{
            EvmBigTransaction, EvmInstruction, EvmSubChain, ExecuteTransaction, FeePayerType,
            SubchainConfig, EVM_INSTRUCTION_BORSH_PREFIX,
        },
        precompiles,
        scope::*,
        tx_chunks::TxChunks,
    },
    borsh::BorshDeserialize,
    evm::{wei_to_lamports, Executor, ExitReason},
    evm_state::{ExecutionResult, MemoryAccount, TransactionReceipt, H160, H256, U256},
    log::*,
    serde::de::DeserializeOwned,
    solana_program_runtime::{
        evm_executor_context::{ChainID, ChainParam},
        ic_msg,
        invoke_context::InvokeContext,
    },
    solana_sdk::{
        account::{AccountSharedData, ReadableAccount, WritableAccount},
        instruction::InstructionError,
        keyed_account::KeyedAccount,
        native_token::LAMPORTS_PER_VLX,
        program_utils::limited_deserialize,
        system_instruction,
    },
    std::{cell::RefMut, fmt::Write, ops::DerefMut},
};

pub const BURN_ADDR: evm_state::H160 = evm_state::H160::zero();

pub const SUBCHAIN_CREATION_DEPOSIT_VLX: u64 = 1_000_000;
const SUBCHAIN_MINT_ADDRESS: H160 = H160::repeat_byte(0x11);

/// Return the next AccountInfo or a NotEnoughAccountKeys error
pub fn next_account_info<'a, 'b, I: Iterator<Item = &'a KeyedAccount<'b>>>(
    iter: &mut I,
) -> Result<I::Item, InstructionError> {
    iter.next().ok_or(InstructionError::NotEnoughAccountKeys)
}

//
// Big Tx Storage Account:
// Owner: evm_program
// signer: true (external or internal not evm program)
//
// 2. Custom EvmState PDA account:
// Owner: evm_program
// Seed: ("evm_state", chain_id)
// data: config
// lamports: >= constant (1m) - used for fee
// signer: -
// number: < storage

// priority:
// [ native -> evm_program ] -> evm_state -> custom_evm_state -> signer -> storage_evm_state
// new_calls  (fixed_prefix):
// - execute_subchain:
// chain_id + ..execute_tx
// - create_account:
//

macro_rules! get_executor
{

    // main chain
    ($rc:expr,$refmut:expr => $invoke_context:expr) => {
        get_executor!(@
            $rc,
            $refmut => ChainParam::GetMainChain,
            $invoke_context
        )
    };
    // Create subchain
    ($rc:expr,$refmut:expr => $invoke_context:expr, $chain_id: expr) => {
        get_executor!(@
            $rc,
            $refmut => ChainParam::CreateSubchain {
                chain_id: $chain_id,
            },
            $invoke_context
        )
    };
    // Get subchain
    ($rc:expr,$refmut:expr => $invoke_context:expr, $chain_id: expr, $last_hashes: expr, $gas_price: expr) => {
        get_executor!(@
            $rc,
            $refmut => ChainParam::GetSubchain {
                chain_id: $chain_id,
                subchain_hashes: $last_hashes,
                gas_price: $gas_price
            },
            $invoke_context
        )
    };
    (@ $rc:expr,$refmut:expr => $params: expr, $invoke_context:expr) => {
        {
            $rc = if let Some(evm_executor) =
                // provide: Context for subchain
                $invoke_context.get_evm_executor($params)
            {
                evm_executor
            } else {
                ic_msg!(
                    $invoke_context,
                    "Invoke context didn't provide evm executor."
                );
                return Err(EvmError::EvmExecutorNotFound.into());
            };
            // evm executor cannot be borrowed, because it not exist in invoke context, or borrowing failed.
            let executor = if let Ok(evm_executor) = $rc.try_borrow_mut() {
                $refmut = evm_executor;
                $refmut.deref_mut()
            } else {
                ic_msg!(
                    $invoke_context,
                    "Recursive cross-program evm execution not enabled."
                );
                return Err(EvmError::RecursiveCrossExecution.into());
            };
            executor
        }
    };

}

#[derive(Default, Debug, Clone)]
pub struct EvmProcessor;

impl EvmProcessor {
    pub fn process_instruction(
        &self,
        first_keyed_account: usize,
        data: &[u8],
        invoke_context: &mut InvokeContext,
    ) -> Result<(), InstructionError> {
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
        let subchain_feature = invoke_context
            .feature_set
            .is_active(&solana_sdk::feature_set::velas::evm_subchain::id());

        let cross_execution = invoke_context.get_stack_height() != 1;

        if cross_execution && !cross_execution_enabled {
            ic_msg!(invoke_context, "Cross-Program evm execution not enabled.");
            return Err(EvmError::CrossExecutionNotEnabled.into());
        }

        let mut borsh_serialization_used = false;
        let ix = match (borsh_serialization_enabled, data.split_first()) {
            (true, Some((&prefix, borsh_data))) if prefix == EVM_INSTRUCTION_BORSH_PREFIX => {
                borsh_serialization_used = true;
                BorshDeserialize::deserialize(&mut &*borsh_data)
                    .map_err(|_| InstructionError::InvalidInstructionData)?
            }
            _ => limited_deserialize(data)?,
        };
        let result = match &ix {
            EvmInstruction::EvmSubchain(_) if subchain_feature => {
                self.process_subchain_instruction(invoke_context, first_keyed_account, ix)
            }
            _ => {
                // bind variable to increase lifetime of temporary RefCell borrow.
                let (rc, mut refmut);
                let executor = get_executor!(rc, refmut => invoke_context);
                // TODO(L): reduce Double create in `EvmInstruction::EvmSubchain`.
                let accounts = Self::build_account_structure(first_keyed_account, invoke_context)?;

                trace!("Run evm exec with ix = {:?}.", ix);
                match ix {
                    EvmInstruction::EvmBigTransaction(big_tx) => {
                        self.process_big_tx(invoke_context, accounts, big_tx)
                    }
                    EvmInstruction::FreeOwnership {} => self.process_free_ownership(
                        invoke_context,
                        executor,
                        accounts,
                        free_ownership_require_signer,
                    ),
                    EvmInstruction::SwapNativeToEther {
                        lamports,
                        evm_address,
                    } => self.process_swap_to_evm(
                        invoke_context,
                        executor,
                        accounts,
                        lamports,
                        evm_address,
                        register_swap_tx_in_evm,
                    ),
                    EvmInstruction::ExecuteTransaction { tx, fee_type } => {
                        let result = self.process_execute_tx(
                            executor,
                            invoke_context,
                            accounts,
                            tx,
                            fee_type,
                            borsh_serialization_used,
                            false, // subchain
                        );

                        if register_swap_tx_in_evm {
                            executor.reset_balance(
                                *precompiles::ETH_TO_VLX_ADDR,
                                ignore_reset_on_cleared,
                            )
                        }
                        result
                    }
                    EvmInstruction::EvmSubchain(_) => {
                        ic_msg!(invoke_context, "Instruction is not supported yet.");
                        Err(EvmError::InstructionNotSupportedYet)
                    }
                }
            }
        };

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

    fn process_subchain_instruction(
        &self,
        invoke_context: &mut InvokeContext,
        first_keyed_account: usize,
        ix: EvmInstruction,
    ) -> Result<(), EvmError> {
        match ix {
            EvmInstruction::EvmSubchain(evm_subchain_ix) => match evm_subchain_ix {
                EvmSubChain::CreateAccount { chain_id, config } => self
                    .create_evm_subchain_account(
                        invoke_context,
                        first_keyed_account,
                        chain_id,
                        config,
                    ),
                EvmSubChain::ExecuteTransaction { chain_id, tx } => self
                    .process_execute_subchain_tx(invoke_context, first_keyed_account, chain_id, tx),
            },
            _ => {
                ic_msg!(invoke_context, "BUG: Instruction is not supported yet.");
                Err(EvmError::InstructionNotSupportedYet)
            }
        }
    }

    fn process_execute_tx(
        &self,
        executor: &mut Executor,
        invoke_context: &InvokeContext,
        accounts: AccountStructure,
        tx: ExecuteTransaction,
        fee_type: FeePayerType,
        borsh_used: bool,
        is_subchain: bool,
    ) -> Result<(), EvmError> {
        let is_big = tx.is_big();
        let keep_old_errors = true;
        let subchain_feature = invoke_context
            .feature_set
            .is_active(&solana_sdk::feature_set::velas::evm_subchain::id());

        // Calculate index of sender and fee collector account,
        // they should appear after storage and subchain_evm_state.
        let mut start_idx = if is_big { 1 } else { 0 };

        if is_subchain {
            start_idx += 1;
        }

        // TODO(L): Add logic for fee collector
        let (sender, _fee_collector) = (
            accounts.users.get(start_idx),
            accounts.users.get(start_idx + 1),
        );

        // FeePayerType::Native is possible only in new serialization format
        if fee_type.is_native() && sender.is_none() {
            ic_msg!(invoke_context, "Fee payer is native but no sender provided",);
            return Err(EvmError::MissingRequiredSignature);
        }

        // TODO(C): Remove swap precompile for subchain.
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

        fn assert_native_balance(
            invoke_context: &InvokeContext,
            _executor: &Executor,
            subchain_feature: bool,
            fee_type: &FeePayerType,
            fee_payer: &KeyedAccount,
            tx_gas_price: U256,
            tx_gas_limit: U256,
            is_subchain: bool,
        ) -> Result<(), EvmError> {
            // - work only if feature enabled,
            // - on subchains or native fee payer

            if subchain_feature && (fee_type.is_native() || is_subchain) {
                let (min_gas_price, min_deposit) = if is_subchain {
                    (
                        evm_state::BURN_GAS_PRICE_IN_SUBCHAIN.into(),
                        SUBCHAIN_CREATION_DEPOSIT_VLX * LAMPORTS_PER_VLX,
                    )
                } else {
                    (tx_gas_price, 0)
                };
                // maximum amount of tokens that user can spend during tx execute (in vlx *10E-18)
                let max_fee = min_gas_price * tx_gas_limit;
                let max_fee_in_lamports = wei_to_lamports(max_fee).0;

                let Some(amount) = fee_payer
                    .account
                    .borrow()
                    .lamports()
                    .checked_sub(min_deposit)
                else {
                    ic_msg!(
                        invoke_context,
                        "Fee payer {} don't have min_deposit {}",
                        fee_payer.unsigned_key(),
                        min_deposit
                    );
                    return Err(EvmError::NativeAccountInsufficientFunds);
                };
                if amount < max_fee_in_lamports {
                    if is_subchain {
                        ic_msg!(
                            invoke_context,
                            "Fee payer {} has not enough lamports to pay fee, max_fee:{}, min_deposit:{}, amount:{},",
                            fee_payer.unsigned_key(),
                            max_fee_in_lamports,
                            min_deposit,
                            amount
                        );
                    } else {
                        ic_msg!(
                            invoke_context,
                            "Fee payer {} has not enough lamports to pay fee, max_fee:{}, amount:{},",
                            fee_payer.unsigned_key(),
                            max_fee_in_lamports,
                            amount
                        );
                    }
                    return Err(EvmError::NativeAccountInsufficientFunds);
                }
            }
            Ok(())
        }

        let native_fee_payer = if is_subchain {
            accounts.users.first().ok_or(EvmError::MissingAccount)?
        } else {
            // error is copied from old implementation in handle_transaction_result
            sender.as_ref().ok_or(EvmError::MissingRequiredSignature)?
        };

        let withdraw_fee_from_evm = fee_type.is_evm();
        let mut tx_gas_price;
        let result = match tx {
            ExecuteTransaction::Signed { tx } => {
                let tx = match tx {
                    Some(tx) => tx,
                    None => Self::get_tx_from_storage(
                        invoke_context,
                        accounts,
                        borsh_used,
                        is_subchain,
                    )?,
                };
                ic_msg!(
                    invoke_context,
                    "Executing transaction: gas_limit:{}, gas_price:{}, value:{}, action:{:?},",
                    tx.gas_limit,
                    tx.gas_price,
                    tx.value,
                    tx.action
                );
                assert_native_balance(
                    invoke_context,
                    &executor,
                    subchain_feature,
                    &fee_type,
                    native_fee_payer,
                    tx.gas_price,
                    tx.gas_limit,
                    is_subchain,
                )?;

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
                    precompiles::entrypoint(
                        accounts,
                        activate_precompile,
                        keep_old_errors,
                        is_subchain,
                    ),
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
                    None => Self::get_tx_from_storage(
                        invoke_context,
                        accounts,
                        borsh_used,
                        is_subchain,
                    )?,
                };
                ic_msg!(
                    invoke_context,
                    "Executing authorized transaction: gas_limit:{}, gas_price:{}, value:{}, action:{:?},",
                    tx.gas_limit,
                    tx.gas_price,
                    tx.value,
                    tx.action
                );

                assert_native_balance(
                    invoke_context,
                    &executor,
                    subchain_feature,
                    &fee_type,
                    native_fee_payer,
                    tx.gas_price,
                    tx.gas_limit,
                    is_subchain,
                )?;
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
                    precompiles::entrypoint(
                        accounts,
                        activate_precompile,
                        keep_old_errors,
                        is_subchain,
                    ),
                )
            }
        };

        if executor.feature_set.is_unsigned_tx_fix_enabled() && is_big {
            let storage =
                Self::get_big_transaction_storage(invoke_context, &accounts, is_subchain)?;
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

        if is_subchain {
            self.handle_subchain_transaction_result(
                executor,
                invoke_context,
                accounts,
                native_fee_payer,
                tx_gas_price,
                result,
            )
        } else {
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
    }

    fn process_free_ownership(
        &self,
        invoke_context: &InvokeContext,
        _executor: &mut Executor,
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
        invoke_context: &InvokeContext,
        executor: &mut Executor,
        accounts: AccountStructure,
        lamports: u64,
        evm_address: evm::Address,
        register_swap_tx_in_evm: bool,
    ) -> Result<(), EvmError> {
        let wei = evm::lamports_to_wei(lamports);
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
        executor.deposit(evm_address, wei);
        if register_swap_tx_in_evm {
            executor.register_swap_tx_in_evm(*precompiles::ETH_TO_VLX_ADDR, evm_address, wei)
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

        let mut storage = Self::get_big_transaction_storage(
            invoke_context,
            &accounts,
            false, /* is_subchain */
        )?;
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
        subchain: bool,
    ) -> Result<T, EvmError>
    where
        T: BorshDeserialize + DeserializeOwned,
    {
        let mut storage = Self::get_big_transaction_storage(invoke_context, &accounts, subchain)?;
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
        subchain: bool,
    ) -> Result<RefMut<'a, AccountSharedData>, EvmError> {
        let idx = if subchain { 1 } else { 0 };
        let storage_account = accounts.users.get(idx).ok_or_else(|| {
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
        // evm_subchain_state is PDA with evm_program owner, so it should not be signer.
        // And we can assume that this account is storage.

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
            let (fee, _) = wei_to_lamports(fee);

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

    // hangle EVM logs
    pub fn handle_subchain_transaction_result(
        &self,
        executor: &mut Executor,
        invoke_context: &InvokeContext,
        accounts: AccountStructure,
        fee_payer: &KeyedAccount,
        tx_gas_price: evm_state::U256,
        result: Result<evm_state::ExecutionResult, evm_state::error::Error>,
    ) -> Result<(), EvmError> {
        let result = result.map_err(|e| {
            ic_msg!(invoke_context, "Transaction execution error: {}", e);
            EvmError::InternalExecutorError
        })?;

        if let Some(receipt) = executor.get_tx_receipt_by_hash(result.tx_id).cloned() {
            if receipt.status.is_succeed() {
                Self::mint_burn_eth_in_subchain(executor, invoke_context, receipt)?;
            }
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

        let burn_fee: U256 = U256::from(evm_state::BURN_GAS_PRICE_IN_SUBCHAIN) * result.used_gas;

        let charge_from_native = burn_fee;
        let return_to_zero_addr = full_fee;
        ic_msg!(
                invoke_context,
                "Transaction executed with fee: in vlx {charge_from_native}, in subchain currency {return_to_zero_addr}",
        );
        // on subchain logic is different,
        // Burn_fee is charged from the deposit address, and full_fee is burned in evm_account.

        // 1. Fee can be charged from evm account or native. (evm part is done in Executor::transaction_execute* methods.)
        Self::charge_native_account(&result, charge_from_native, fee_payer, accounts.evm)?;

        // 2. Then we should burn some part of it.
        // This if only register burn to the deposit address, withdrawal is done in 1.
        if return_to_zero_addr > U256::zero() {
            trace!("Burning fee {}", return_to_zero_addr);
            // we already withdraw gas_price during transaction_execute,
            // if burn_fixed_fee is activated, we should deposit to burn addr (0x00..00)
            executor.deposit(BURN_ADDR, return_to_zero_addr);
        };

        // if subchain - skip all logic related to fee refund and native swap.
        return Ok(());
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
        let result = result.map_err(|e| {
            ic_msg!(invoke_context, "Transaction execution error: {}", e);
            EvmError::InternalExecutorError
        })?;

        if remove_native_logs_after_swap {
            executor.modify_tx_logs(result.tx_id, |logs| {
                if let Some(logs) = logs {
                    precompiles::post_handle_logs(accounts, logs).map_err(|e| {
                        ic_msg!(invoke_context, "Filter native logs error: {}", e);
                        EvmError::PrecompileError
                    })?;
                } else {
                    ic_msg!(invoke_context, "Unable to find tx by txid");
                    return Err(EvmError::PrecompileError);
                }
                Ok(())
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

        let charge_from_native = full_fee;
        let return_to_zero_addr = burn_fee;

        let (refund_native_fee, _) = wei_to_lamports(refund_fee);

        // 1. Fee can be charged from evm account or native. (evm part is done in Executor::transaction_execute* methods.)
        if !withdraw_fee_from_evm {
            let fee_payer = sender.ok_or(EvmError::MissingRequiredSignature)?;
            Self::charge_native_account(&result, charge_from_native, fee_payer, accounts.evm)?;
        }

        // 2. Then we should burn some part of it.
        // This if only register burn to the deposit address, withdrawal is done in 1.
        if return_to_zero_addr > U256::zero() {
            trace!("Burning fee {}", return_to_zero_addr);
            // we already withdraw gas_price during transaction_execute,
            // if burn_fixed_fee is activated, we should deposit to burn addr (0x00..00)
            executor.deposit(BURN_ADDR, return_to_zero_addr);
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

    // check that chain id is prefixed with 0x56
    // can be any arbitrary hex value, but should be prefixed with 0x56
    fn check_prefixed_chain_id(chain_id: u64) -> bool {
        const PREFIX: u64 = b'V' as u64; // 0x56
        let prefix_zeros = PREFIX.leading_zeros();

        let num_zeros = chain_id.leading_zeros();

        if num_zeros >= prefix_zeros {
            return false;
        }

        // number of bits after prefix
        let num_bits = prefix_zeros - num_zeros;
        let prefix = chain_id >> num_bits;

        // check that we found prefix at start, and make sure that we shift our prefix by 1 hex digit.
        prefix == PREFIX && num_bits % 4 == 0
    }

    fn create_evm_subchain_account(
        &self,
        invoke_context: &mut InvokeContext,
        first_keyed_account: usize,
        subchain_id: u64,
        config: SubchainConfig,
    ) -> Result<(), EvmError> {
        let main_chain_id = invoke_context.get_main_chain_id();
        if main_chain_id.is_none()
            || subchain_id == main_chain_id.unwrap()
            || !Self::check_prefixed_chain_id(subchain_id)
        {
            ic_msg!(
                invoke_context,
                "Subchain ID is equal to main chain ID, or not prefixed with 0x56."
            );
            return Err(EvmError::InvalidSubchainId);
        }
        if config.network_name.len() > 32 {
            ic_msg!(
                invoke_context,
                "Network name is too long, max 32 bytes allowed."
            );
            return Err(EvmError::InvalidSubchainConfig);
        }
        if config.token_name.len() > 10 {
            ic_msg!(
                invoke_context,
                "Token name is too long, max 10 bytes allowed."
            );
            return Err(EvmError::InvalidSubchainConfig);
        }

        let evm_subchain_state_pda = evm_state_subchain_account(subchain_id);

        let accounts = Self::build_account_structure(first_keyed_account, invoke_context).unwrap();

        // Check if `evm_subchain_state` is in `keyed_accounts`
        let evm_subchain_state = accounts.users.get(0).ok_or_else(|| {
            ic_msg!(
                invoke_context,
                "EVM Subchain State Account is not found in Meta"
            );
            EvmError::MissingAccount
        })?;

        // check `evm_subchain_state` is from pda
        if evm_subchain_state.unsigned_key() != &evm_subchain_state_pda {
            ic_msg!(
                invoke_context,
                "Wrong EVM Subchain State Account provided, expected PDA = {}, got = {}",
                evm_subchain_state_pda,
                evm_subchain_state.unsigned_key()
            );
            return Err(EvmError::MissingAccount);
        }

        // Check if account is already created
        let evm_subchain_state_borrow = evm_subchain_state
            .try_account_ref()
            .map_err(|_| EvmError::BorrowingFailed)?;

        if !evm_subchain_state_borrow.data().is_empty() || evm_subchain_state_borrow.lamports() > 0
        {
            ic_msg!(
                invoke_context,
                "EVM Subchain State Account is already created for Chain ID = {}",
                subchain_id
            );
            Err(EvmError::EvmSubchainConfigAlreadyExists)?
        }

        // Check if signer has enough balance to create subchain account.
        let whale = accounts.users.get(1).ok_or_else(|| {
            ic_msg!(invoke_context, "Signer is required");
            EvmError::MissingRequiredSignature
        })?;

        if whale
            .try_account_ref()
            .map_err(|_| EvmError::BorrowingFailed)?
            .lamports()
            < SUBCHAIN_CREATION_DEPOSIT_VLX * LAMPORTS_PER_VLX
        {
            ic_msg!(
                invoke_context,
                "Deposit of {} VLX is required to create EVM Subchain",
                SUBCHAIN_CREATION_DEPOSIT_VLX
            );
            Err(EvmError::EvmSubchainDepositRequired)?
        }

        let whale_pubkey = *whale.unsigned_key();
        let evm_subchain_state_pubkey = *evm_subchain_state.unsigned_key();

        drop(evm_subchain_state_borrow);

        let alloc: Vec<(H160, MemoryAccount)> = config
            .alloc
            .iter()
            .map(|(evm_address, account)| (*evm_address, MemoryAccount::from(account.clone())))
            .collect();

        // write config into subchain state, and save owner.
        let state = crate::subchain::SubchainState::new(config, whale_pubkey, subchain_id);

        // Create subchain account
        let create_account_ix = system_instruction::create_account(
            &whale_pubkey,
            &evm_subchain_state_pubkey,
            SUBCHAIN_CREATION_DEPOSIT_VLX * LAMPORTS_PER_VLX,
            state.len()? as u64,
            &solana_sdk::evm_loader::ID,
        );

        ic_msg!(
            invoke_context,
            "Creating subchain account, with transfering {SUBCHAIN_CREATION_DEPOSIT_VLX} VLX from {} to {}",
            whale_pubkey,
            evm_subchain_state_pubkey
        );
        invoke_context
            .native_invoke(create_account_ix, &[evm_subchain_state_pubkey])
            .map_err(|e| {
                ic_msg!(
                    invoke_context,
                    "Failed to allocate Subchain State Account: {}",
                    e
                );
                EvmError::SubchainStateAllocationFailed
            })?;

        let (rc, mut refmut);
        let executor = get_executor!(rc, refmut => invoke_context, subchain_id);

        // Load pre-seed
        executor.evm_backend.set_initial(alloc.clone());

        for (evm_address, account) in alloc {
            executor.register_swap_tx_in_evm(SUBCHAIN_MINT_ADDRESS, evm_address, account.balance);
        }

        let accounts = Self::build_account_structure(first_keyed_account, invoke_context).unwrap();
        // serialize data into account.
        state.save(accounts)
    }

    // Accounts:
    // 0. evm_loader
    // 1. evm_state
    // 2. evm_state_pda (custom)
    // 3. Optional(storage)
    // 4. Sender <- Bridge
    fn process_execute_subchain_tx(
        &self,
        invoke_context: &mut InvokeContext,
        first_keyed_account: usize,
        chain_id: ChainID,
        tx: ExecuteTransaction,
    ) -> Result<(), EvmError> {
        let (rc, mut refmut);
        let accounts = Self::build_account_structure(first_keyed_account, invoke_context).unwrap();
        let sender_idx = if tx.is_big() { 2 } else { 1 };
        let sender = &accounts.users[sender_idx];
        let mut state = crate::subchain::SubchainState::load(accounts)?;

        if !state.whitelisted.is_empty() && !state.whitelisted.contains(sender.unsigned_key()) {
            ic_msg!(
                invoke_context,
                "EVM Subchain Execution is forbidden for sender {:?}",
                sender.unsigned_key()
            );
            return Err(EvmError::EVMSubchainExecutionForbidden);
        }
        let last_hashes = Box::new(state.last_hashes().get_hashes().clone());
        // TODO(L): How to deal with reborrowing?? (we neeed last hashes from account to create executor, but to get it we need to borrow invoke context.)
        let executor =
            get_executor!(rc, refmut => invoke_context, chain_id, last_hashes, state.min_gas_price);
        let accounts = Self::build_account_structure(first_keyed_account, invoke_context).unwrap();
        let Some(slot) = invoke_context.get_slot_from_evm_context() else {
            ic_msg!(invoke_context, "Evm context is empty.");
            return Err(EvmError::InternalExecutorError);
        };
        trace!(
            "last_block_hash = {:?}",
            executor.evm_backend.state.last_block_hash
        );
        state.update(|blocks| blocks.push(executor.evm_backend.state.last_block_hash, slot));

        let result = self.process_execute_tx(
            executor,
            invoke_context,
            accounts,
            tx,
            FeePayerType::Evm,
            true,
            true,
        );
        state.save(accounts)?;
        result
    }

    /// Ensure that first account is program itself, and it's locked for writes.
    fn build_account_structure<'a>(
        first_keyed_account: usize,
        invoke_context: &'a InvokeContext,
    ) -> Result<AccountStructure<'a>, InstructionError> {
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

        let users = &keyed_accounts[(first_keyed_account + 1)..];
        Ok(AccountStructure::new(first, users))
    }

    fn mint_burn_eth_in_subchain(
        executor: &mut Executor,
        invoke_context: &InvokeContext,
        receipt: TransactionReceipt,
    ) -> Result<(), EvmError> {
        const MINT_BURN_CONTRACT: H160 = H160::zero();

        fn transfer_event() -> &'static H256 {
            lazy_static::lazy_static! {
                static ref TRANSFER_EVENT: H256 = {
                    ethabi::Event {
                        name: "Transfer".into(),
                        inputs: vec![
                            ethabi::EventParam {
                                name: "from".into(),
                                kind: ethabi::ParamType::Address,
                                indexed: true,
                            },
                            ethabi::EventParam {
                                name: "to".into(),
                                kind: ethabi::ParamType::Address,
                                indexed: true,
                            },
                            ethabi::EventParam {
                                name: "value".into(),
                                kind: ethabi::ParamType::Uint(256),
                                indexed: false,
                            },
                        ],
                        anonymous: false,
                    }
                    .signature()
                };
            }
            &TRANSFER_EVENT
        }

        for log in receipt.logs.iter() {
            if log.address == MINT_BURN_CONTRACT {
                // skip non-transfer events
                if log.topics.first() != Some(&transfer_event()) {
                    continue;
                }

                // skip malformed transfer events
                fn is_valid_address(address: H256) -> bool {
                    &address[0..12] != &[0; 12]
                }

                if log.topics.len() != 3 || log.data.len() != 32 {
                    ic_msg!(invoke_context, "Transfer event argument is malformed");
                    continue;
                }

                if !is_valid_address(log.topics[1]) || !is_valid_address(log.topics[2]) {
                    ic_msg!(invoke_context, "Transfer event argument is malformed");
                    continue;
                }

                // at this point transfer arguments must be valid
                let from = H160::from_slice(&log.topics[1].as_fixed_bytes()[12..]);
                let to = H160::from_slice(&log.topics[2].as_fixed_bytes()[12..]);
                let value = U256::from(log.data.as_slice());

                match (from.is_zero(), to.is_zero()) {
                    (true, false) => {
                        ic_msg!(invoke_context, "Minting {} wei to {:?}", value, to);
                        executor.deposit(to, value);
                    }
                    (false, true) => {
                        executor.withdraw(from, value).map_err(|err| {
                            // could it be anything else than ExitError::OutOfFund? clarify error message?
                            ic_msg!(
                                invoke_context,
                                "Transfer event `burn` failed to execute: {:?}",
                                err
                            );
                            EvmError::MintBurnInSubchainFailed
                        })?;
                        ic_msg!(invoke_context, "Burning {} wei from {:?}", value, from);
                    }
                    (true, true) => {
                        ic_msg!(invoke_context, "Exaclty one of the `from` or `to` arguments must be set to zero. From: {:?}, to: {:?}", from, to);
                    }
                    (false, false) => {}
                }
            }
        }

        Ok(())
    }
}

const SECRET_KEY_DUMMY: [u8; 32] = [1; 32];

const TEST_CHAIN_ID: u64 = 0xdead;
#[doc(hidden)]
pub fn dummy_call(nonce: usize) -> (evm::Transaction, evm::UnsignedTransaction) {
    dummy_call_with_chain_id(nonce, TEST_CHAIN_ID)
}

pub fn dummy_call_with_chain_id(
    nonce: usize,
    chain_id: u64,
) -> (evm::Transaction, evm::UnsignedTransaction) {
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

    (tx_call.clone().sign(&secret_key, Some(chain_id)), tx_call)
}

#[cfg(test)]
mod test {
    use {
        super::*,
        crate::instructions::AllocAccount,
        evm::lamports_to_wei,
        evm_state::{
            transactions::{TransactionAction, TransactionSignature},
            AccountProvider, AccountState, ExitReason, ExitSucceed, FromKey, BURN_GAS_PRICE,
            BURN_GAS_PRICE_IN_SUBCHAIN,
        },
        hex_literal::hex,
        num_traits::Zero,
        primitive_types::{H160, H256, U256},
        solana_program_runtime::{
            compute_budget::ComputeBudget,
            evm_executor_context::{self, EvmBank, EvmExecutorContext},
            invoke_context::{BuiltinProgram, InvokeContext},
            timings::ExecuteTimings,
        },
        solana_sdk::{
            account::Account,
            feature_set::{self},
            instruction::{AccountMeta, Instruction},
            keyed_account::{get_signers, keyed_account_at_index},
            native_loader,
            program_utils::limited_deserialize,
            pubkey::Pubkey,
            system_program,
            sysvar::rent::Rent,
            transaction_context::{InstructionAccount, TransactionContext},
        },
        system_instruction::{SystemError, SystemInstruction, MAX_PERMITTED_DATA_LENGTH},
    };
    type MutableAccount = AccountSharedData;

    use {
        super::TEST_CHAIN_ID as CHAIN_ID,
        borsh::BorshSerialize,
        std::{
            collections::{BTreeMap, HashMap, HashSet},
            sync::Arc,
        },
    };

    // Testing object that emulate Bank work, and can execute transactions.
    // Emulate batch of native transactions.
    #[derive(Debug, Clone)]
    struct EvmMockContext {
        evm_state: evm_state::EvmBackend<evm_state::Incomming>,
        evm_state_account: AccountSharedData,

        subchains: HashMap<ChainID, evm_state::EvmBackend<evm_state::Incomming>>,
        evm_program_account: AccountSharedData,
        rest_accounts: BTreeMap<Pubkey, MutableAccount>,
        feature_set: solana_sdk::feature_set::FeatureSet,
        evm_bank_slot: u64,
        evm_bank_unix_timestamp: i64,
    }

    impl EvmMockContext {
        fn new(lamports: u64) -> Self {
            let _logger = simple_logger::SimpleLogger::new()
                .with_utc_timestamps()
                .init();
            Self {
                evm_state: evm_state::EvmBackend::default(),
                evm_state_account: crate::create_state_account(lamports),
                evm_program_account: AccountSharedData::new(1, 0, &native_loader::ID),
                subchains: HashMap::new(),
                rest_accounts: [(
                    solana_sdk::system_program::ID,
                    Account {
                        lamports: 1,
                        data: vec![],
                        owner: solana_sdk::native_loader::id(),
                        executable: true,
                        rent_epoch: 0,
                    }
                    .into(),
                )]
                .into_iter()
                .collect(),
                feature_set: solana_sdk::feature_set::FeatureSet::all_enabled(),
                evm_bank_slot: 10_000,
                evm_bank_unix_timestamp: 1_000_000,
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

        fn commit_state(&mut self) {
            let native_blockhash = H256::from_slice(
                &solana_sdk::hash::hashv(&[
                    &self.evm_bank_slot.to_be_bytes(),
                    &self.evm_bank_unix_timestamp.to_be_bytes(),
                ])
                .to_bytes(),
            );
            self.evm_bank_slot += 1;
            self.evm_bank_unix_timestamp += 1000;
            if self.evm_state.state.is_active_changes() {
                self.evm_state = self
                    .evm_state
                    .take()
                    .commit_block(self.evm_bank_slot, native_blockhash)
                    .next_incomming(self.evm_bank_unix_timestamp as u64);
            }

            for (_, state) in self.subchains.iter_mut() {
                if state.state.is_active_changes() {
                    *state = state
                        .take()
                        .commit_block(self.evm_bank_slot, native_blockhash)
                        .next_incomming(self.evm_bank_unix_timestamp as u64);
                }
            }
        }

        fn deposit_evm(&mut self, recipient: evm_state::Address, wei: evm_state::U256) {
            let mut account_state = self
                .evm_state
                .get_account_state(recipient)
                .unwrap_or_default();
            account_state.balance += wei;
            self.evm_state.set_account_state(recipient, account_state)
        }

        // Used only for create_and_assign_account
        fn mock_system_process_instruction_cpi(
            first_instruction_account: usize,
            instruction_data: &[u8],
            invoke_context: &mut InvokeContext,
        ) -> Result<(), InstructionError> {
            // represents an address that may or may not have been generated
            //  from a seed
            #[derive(PartialEq, Default, Debug)]
            struct Address {
                address: Pubkey,
                base: Option<Pubkey>,
            }

            impl Address {
                fn is_signer(&self, signers: &HashSet<Pubkey>) -> bool {
                    if let Some(base) = self.base {
                        signers.contains(&base)
                    } else {
                        signers.contains(&self.address)
                    }
                }
                fn create(
                    address: &Pubkey,
                    with_seed: Option<(&Pubkey, &str, &Pubkey)>,
                    invoke_context: &InvokeContext,
                ) -> Result<Self, InstructionError> {
                    let base = if let Some((base, seed, owner)) = with_seed {
                        let address_with_seed = Pubkey::create_with_seed(base, seed, owner)?;
                        // re-derive the address, must match the supplied address
                        if *address != address_with_seed {
                            ic_msg!(
                                invoke_context,
                                "Create: address {} does not match derived address {}",
                                address,
                                address_with_seed
                            );
                            return Err(SystemError::AddressWithSeedMismatch.into());
                        }
                        Some(*base)
                    } else {
                        None
                    };

                    Ok(Self {
                        address: *address,
                        base,
                    })
                }
            }

            let keyed_accounts = invoke_context.get_keyed_accounts()?;
            let instruction = limited_deserialize(instruction_data)?;
            match instruction {
                SystemInstruction::CreateAccount {
                    lamports,
                    space,
                    owner,
                } => {
                    let from = keyed_account_at_index(keyed_accounts, first_instruction_account)?;
                    let to = keyed_account_at_index(keyed_accounts, first_instruction_account + 1)?;
                    let to_address = Address::create(to.unsigned_key(), None, invoke_context)?;
                    let signers = get_signers(&keyed_accounts[first_instruction_account..]);
                    fn allocate(
                        account: &mut AccountSharedData,
                        address: &Address,
                        space: u64,
                        signers: &HashSet<Pubkey>,
                        invoke_context: &InvokeContext,
                    ) -> Result<(), InstructionError> {
                        if !address.is_signer(signers) {
                            ic_msg!(
                                invoke_context,
                                "Allocate: 'to' account {:?} must sign",
                                address
                            );
                            return Err(InstructionError::MissingRequiredSignature);
                        }

                        // if it looks like the `to` account is already in use, bail
                        //   (note that the id check is also enforced by message_processor)
                        if !account.data().is_empty() || !system_program::check_id(account.owner())
                        {
                            ic_msg!(
                                invoke_context,
                                "Allocate: account {:?} already in use",
                                address
                            );
                            return Err(SystemError::AccountAlreadyInUse.into());
                        }

                        if space > MAX_PERMITTED_DATA_LENGTH {
                            ic_msg!(
                                invoke_context,
                                "Allocate: requested {}, max allowed {}",
                                space,
                                MAX_PERMITTED_DATA_LENGTH
                            );
                            return Err(SystemError::InvalidAccountDataLength.into());
                        }

                        account.set_data(vec![0; space as usize]);

                        Ok(())
                    }

                    fn assign(
                        account: &mut AccountSharedData,
                        address: &Address,
                        owner: &Pubkey,
                        signers: &HashSet<Pubkey>,
                        invoke_context: &InvokeContext,
                    ) -> Result<(), InstructionError> {
                        // no work to do, just return
                        if account.owner() == owner {
                            return Ok(());
                        }

                        if !address.is_signer(signers) {
                            ic_msg!(invoke_context, "Assign: account {:?} must sign", address);
                            return Err(InstructionError::MissingRequiredSignature);
                        }

                        account.set_owner(*owner);
                        Ok(())
                    }

                    fn allocate_and_assign(
                        to: &mut AccountSharedData,
                        to_address: &Address,
                        space: u64,
                        owner: &Pubkey,
                        signers: &HashSet<Pubkey>,
                        invoke_context: &InvokeContext,
                    ) -> Result<(), InstructionError> {
                        allocate(to, to_address, space, signers, invoke_context)?;
                        assign(to, to_address, owner, signers, invoke_context)
                    }

                    fn transfer_verified(
                        from: &KeyedAccount,
                        to: &KeyedAccount,
                        lamports: u64,
                        invoke_context: &InvokeContext,
                    ) -> Result<(), InstructionError> {
                        if !from.data_is_empty()? {
                            ic_msg!(invoke_context, "Transfer: `from` must not carry data");
                            return Err(InstructionError::InvalidArgument);
                        }
                        if lamports > from.lamports()? {
                            ic_msg!(
                                invoke_context,
                                "Transfer: insufficient lamports {}, need {}",
                                from.lamports()?,
                                lamports
                            );
                            return Err(SystemError::ResultWithNegativeLamports.into());
                        }

                        from.try_account_ref_mut()?.checked_sub_lamports(lamports)?;
                        to.try_account_ref_mut()?.checked_add_lamports(lamports)?;
                        Ok(())
                    }

                    fn transfer(
                        from: &KeyedAccount,
                        to: &KeyedAccount,
                        lamports: u64,
                        invoke_context: &InvokeContext,
                    ) -> Result<(), InstructionError> {
                        if !invoke_context
                            .feature_set
                            .is_active(&feature_set::system_transfer_zero_check::id())
                            && lamports == 0
                        {
                            return Ok(());
                        }

                        if from.signer_key().is_none() {
                            ic_msg!(
                                invoke_context,
                                "Transfer: `from` account {} must sign",
                                from.unsigned_key()
                            );
                            return Err(InstructionError::MissingRequiredSignature);
                        }

                        transfer_verified(from, to, lamports, invoke_context)
                    }
                    {
                        let to = &mut to.try_account_ref_mut()?;
                        if to.lamports() > 0 {
                            ic_msg!(
                                invoke_context,
                                "Create Account: account {:?} already in use",
                                to_address
                            );
                            return Err(SystemError::AccountAlreadyInUse.into());
                        }

                        allocate_and_assign(
                            to,
                            &to_address,
                            space,
                            &owner,
                            &signers,
                            invoke_context,
                        )?;
                    }
                    transfer(from, to, lamports, invoke_context)
                }
                _ => panic!("Unsupported system instruction"),
            }
        }
        // we cant create method like this because system_instruction_processor is in rutime
        fn get_solana_builtins() -> [BuiltinProgram; 1] {
            [BuiltinProgram {
                program_id: solana_sdk::system_program::id(),
                process_instruction: Self::mock_system_process_instruction_cpi,
            }]
        }

        // Emulate native transaction
        fn process_transaction(&mut self, ixs: Vec<Instruction>) -> Result<(), InstructionError> {
            let feature_set = evm_state::executor::FeatureSet::new(
                self.feature_set
                    .is_active(&solana_sdk::feature_set::velas::unsigned_tx_fix::id()),
                self.feature_set
                    .is_active(&solana_sdk::feature_set::velas::clear_logs_on_error::id()),
                self.feature_set.is_active(
                    &solana_sdk::feature_set::velas::accept_zero_gas_price_with_native_fee::id(),
                ),
            );
            let subchains = self
                .subchains
                .iter()
                .map(|(k, v)| (*k, v.clone().into()))
                .collect();
            let evm_bank = EvmBank::new(
                evm::TEST_CHAIN_ID,
                Default::default(),
                self.evm_state.clone().into(),
                subchains,
            );
            let clear_logs = self
                .feature_set
                .is_active(&solana_sdk::feature_set::velas::clear_logs_on_native_error::id());
            let is_evm_burn_fee_activated = self
                .feature_set
                .is_active(&solana_sdk::feature_set::velas::burn_fee::id());
            let evm_new_error_handling = self
                .feature_set
                .is_active(&solana_sdk::feature_set::velas::evm_new_error_handling::id());
            let mut evm_executor_context = EvmExecutorContext::new(
                evm_bank,
                feature_set,
                self.evm_bank_unix_timestamp,
                self.evm_bank_slot,
                false,
                is_evm_burn_fee_activated,
                evm_new_error_handling,
                clear_logs,
                evm_executor_context::EvmExecutorContextType::Execution,
            );

            let evm_program = BuiltinProgram {
                program_id: solana_sdk::evm_loader::id(),
                process_instruction: |acc, data, context| {
                    let processor = EvmProcessor::default();
                    processor.process_instruction(acc, data, context)
                },
            };
            let builtins = &Self::get_solana_builtins()
                .into_iter()
                .chain(Some(evm_program))
                .collect::<Vec<_>>();
            let mut accs = vec![(crate::ID, self.native_account_cloned(crate::ID))];
            let mut keys = vec![crate::ID];
            for ix in &ixs {
                for acc in ix.accounts.clone() {
                    accs.push((acc.pubkey, self.native_account_cloned(acc.pubkey)));
                    keys.push(acc.pubkey);
                }
            }
            // keys.dedup();

            let mut transaction_context = TransactionContext::new(
                accs,
                ComputeBudget::default().max_invoke_depth.saturating_add(1),
                ixs.len(),
            );
            let mut invoke_context = InvokeContext::new_mock_evm(
                &mut transaction_context,
                builtins,
                &mut evm_executor_context,
            );
            invoke_context.feature_set = Arc::new(self.feature_set.clone());

            let program_index = keys
                .iter()
                .position(|k: &Pubkey| *k == crate::ID)
                .unwrap_or(keys.len());

            for instruction in ixs {
                let accounts = instruction.accounts.clone();

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
                    let Some((chain_id, executor)) = invoke_context.deconstruct_evm() else {
                        // skip apply
                        return Err(e);
                    };

                    if let Some(_chain_id) = chain_id {
                        warn!("Skiping update on error on empty subchain.")
                    } else {
                        self.evm_state
                            .apply_failed_update(&executor.evm_backend, clear_logs);
                    };
                    return Err(e);
                }
            }

            // invoke context will apply native accounts chages, but evm should be applied manually.
            if let Some((chain_id, executor)) = invoke_context.deconstruct_evm() {
                let evm_state = if let Some(chain_id) = chain_id {
                    let main = &self.evm_state;

                    info!("Updating subchain state {}", chain_id);
                    self.subchains
                        .entry(chain_id)
                        .or_insert_with(|| main.clone())
                } else {
                    &mut self.evm_state
                };

                *evm_state = executor.evm_backend;
            }

            let (accs, _contexts) = transaction_context.deconstruct();
            for acc in accs {
                *self.native_account(acc.0) = acc.1
            }
            Ok(())
        }
    }

    pub fn authorized_tx(
        sender: solana::Address,
        unsigned_tx: evm::UnsignedTransaction,
        fee_type: FeePayerType,
    ) -> solana::Instruction {
        let account_metas = vec![
            AccountMeta::new(solana::evm_state::ID, false),
            AccountMeta::new(sender, true),
        ];

        let from = crate::evm_address_for_program(sender);
        crate::create_evm_instruction_with_borsh(
            crate::ID,
            &EvmInstruction::ExecuteTransaction {
                tx: ExecuteTransaction::ProgramAuthorized {
                    tx: Some(unsigned_tx),
                    from,
                },
                fee_type,
            },
            account_metas,
        )
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
        evm_context.deposit_evm(address, lamports_to_wei(300000));
        let tx_create = evm::UnsignedTransaction {
            nonce: 0u32.into(),
            gas_price: crate::evm::WEI_PER_LAMPORT.into(),
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

        // TODO(L): Assert that tx executed with result. Check storage, receipt?
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
            lamports_to_wei(1000)
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
            lamports_to_wei(1000)
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
            value: lamports_to_wei(lamports_to_send_back),
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
            lamports_to_wei(lamports_to_send)
        );
    }

    #[test]
    fn swap_evm_to_vlx_within_different_chains() {
        // prepare context
        let mut evm_context = EvmMockContext::new(12_000_000);

        // create accounts
        let mut rand: evm_state::rand::prelude::ThreadRng = evm_state::rand::thread_rng();
        let subchain_owner = Pubkey::new_unique();
        let subchain_owner_acc = evm_context.native_account(subchain_owner);
        let alice = Pubkey::new_unique();
        let bob = evm::SecretKey::new(&mut rand); // SECRET_KEY_DUMMY
        let bob_addr = bob.to_address();
        subchain_owner_acc.set_lamports(SUBCHAIN_CREATION_DEPOSIT_VLX * LAMPORTS_PER_VLX + 777);
        evm_context.deposit_evm(bob_addr, lamports_to_wei(10_000_000));

        // create subchain
        let subchain_id = 0x5677;
        let alloc = BTreeMap::from_iter([(
            bob_addr,
            AllocAccount::new_with_balance(lamports_to_wei(20_000_000)),
        )]);
        let subchain_config = SubchainConfig {
            hardfork: crate::instructions::Hardfork::Istanbul,
            alloc,
            ..Default::default()
        };

        setup_chain(
            &mut evm_context,
            subchain_owner,
            subchain_id,
            subchain_config,
            42_000_000,
        );

        // empty native balance after subchain cration fee
        let subchain_owner_acc = evm_context.native_account(subchain_owner);
        assert_eq!(subchain_owner_acc.lamports(), 777);

        // check EVM balances
        let bobs_subchain_acc = evm_context
            .subchains
            .get(&subchain_id)
            .unwrap()
            .get_account_state(bob_addr)
            .unwrap();

        let bobs_mainchain_acc = evm_context.evm_state.get_account_state(bob_addr).unwrap();
        assert_eq!(bobs_subchain_acc.balance, lamports_to_wei(20_000_000));
        assert_eq!(bobs_mainchain_acc.balance, lamports_to_wei(10_000_000));

        // try to swap from EVM mainchain and assert successful swap
        let swap_within_mainchain = evm::UnsignedTransaction {
            nonce: 0u32.into(),
            gas_price: BURN_GAS_PRICE.into(),
            gas_limit: 300_000u32.into(),
            action: TransactionAction::Call(*precompiles::ETH_TO_VLX_ADDR),
            value: lamports_to_wei(4_000_000),
            input: precompiles::ETH_TO_VLX_CODE
                .abi
                .encode_input(&[ethabi::Token::FixedBytes(alice.to_bytes().to_vec())])
                .unwrap(),
        }
        .sign(&bob, Some(TEST_CHAIN_ID));

        let mut ix = crate::send_raw_tx(
            subchain_owner,
            swap_within_mainchain,
            None,
            FeePayerType::Evm,
        );
        ix.accounts.push(AccountMeta {
            pubkey: alice,
            is_signer: false,
            is_writable: true,
        });
        evm_context.process_instruction(ix).unwrap();

        let alice_acc = evm_context.native_account(alice);
        assert_eq!(alice_acc.lamports(), 4_000_000);

        // try to swap from EVM subchain and assert unsuccessful swap
        let swap_within_subchain = evm::UnsignedTransaction {
            nonce: 0u32.into(),
            gas_price: BURN_GAS_PRICE_IN_SUBCHAIN.into(),
            gas_limit: 300000u32.into(),
            action: TransactionAction::Call(*precompiles::ETH_TO_VLX_ADDR),
            value: lamports_to_wei(3_000_000),
            input: precompiles::ETH_TO_VLX_CODE
                .abi
                .encode_input(&[ethabi::Token::FixedBytes(alice.to_bytes().to_vec())])
                .unwrap(),
        }
        .sign(&bob, Some(subchain_id));

        // TODO(L): extract into separate test
        assert_eq!(
            swap_within_subchain.input,
            [177, 214, 146, 122]
                .into_iter()
                .chain(alice.to_bytes())
                .collect::<Vec<_>>()
        );

        let mut ix =
            crate::send_raw_tx_subchain(subchain_owner, swap_within_subchain, None, subchain_id);

        ix.accounts.push(AccountMeta {
            pubkey: alice,
            is_signer: false,
            is_writable: true,
        });

        evm_context.process_instruction(ix).unwrap();

        let alice_acc = evm_context.native_account(alice);
        assert_eq!(alice_acc.lamports(), 4_000_000);
        let subchain_state = evm_context.subchains.get(&subchain_id).unwrap();
        let bob_acc = subchain_state.get_account_state(bob_addr).unwrap();
        let native_pseudoswap_acc = subchain_state
            .get_account_state(*precompiles::ETH_TO_VLX_ADDR)
            .unwrap();

        assert_eq!(native_pseudoswap_acc.balance, lamports_to_wei(3_000_000));

        let fee_lamports = 848160;
        assert_eq!(bob_acc.balance, lamports_to_wei(17_000_000 - fee_lamports));
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
            lamports_to_wei(1000)
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
            value: lamports_to_wei(lamports_to_send_back),
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
                < lamports_to_wei(lamports_to_send - lamports_to_send_back)
                && evm_context
                    .evm_state
                    .get_account_state(ether_dummy_address)
                    .unwrap()
                    .balance
                    > lamports_to_wei(lamports_to_send - lamports_to_send_back) - 300000u32 //(max_fee)
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
            lamports_to_wei(1000)
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
            value: lamports_to_wei(lamports_to_send_back),
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
            lamports_to_wei(lamports_to_send)
        );
    }

    fn all_ixs() -> Vec<solana_sdk::instruction::Instruction> {
        let (tx_call, unsigned_tx) = dummy_call(0);

        let signer = solana::Address::new_unique();
        vec![
            crate::transfer_native_to_evm(signer, 1, tx_call.address().unwrap()),
            crate::free_ownership(signer),
            crate::send_raw_tx(signer, tx_call, None, FeePayerType::Evm),
            authorized_tx(signer, unsigned_tx, FeePayerType::Evm),
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
        let ix = authorized_tx(user_id, unsigned_tx, FeePayerType::Evm);
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
            wei_to_lamports(U256::from(300000u64 * evm_state::BURN_GAS_PRICE * 2)).0,
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

        let ix = authorized_tx(user_id, unsigned_tx, FeePayerType::Evm);

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
            user_balance_before + wei_to_lamports(evm_balance_difference).0 / 2
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

        let ix = authorized_tx(user_id, unsigned_tx, FeePayerType::Native);

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
            wei_to_lamports(U256::from(tx.used_gas) * U256::from(evm_state::BURN_GAS_PRICE));

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
        evm_context.disable_feature(&solana_sdk::feature_set::velas::evm_subchain::id());

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
        use solana_sdk::{
            hash::hash,
            message::Message,
            signature::{Keypair, Signer},
            transaction::Transaction,
        };

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

    #[test]
    fn subchain_create() {
        let mut evm_context = EvmMockContext::new(0);
        let user_id = Pubkey::new_unique();
        let user_acc = evm_context.native_account(user_id);
        let chain_id = 0x561;
        user_acc.set_owner(system_program::ID);
        user_acc.set_lamports(10000000000000000);

        evm_context
            .feature_set
            .deactivate(&solana_sdk::feature_set::velas::evm_subchain::id());
        let err = evm_context
            .process_instruction(crate::create_evm_subchain_account(
                user_id,
                chain_id,
                SubchainConfig::default(),
            ))
            .unwrap_err();
        assert_eq!(err, InstructionError::Custom(16)); // InstructionNotSupportedYet
        evm_context
            .feature_set
            .activate(&solana_sdk::feature_set::velas::evm_subchain::id(), 0);
        // failed because of invalid chain id
        let err = evm_context
            .process_instruction(crate::create_evm_subchain_account(
                user_id,
                TEST_CHAIN_ID,
                SubchainConfig::default(),
            ))
            .unwrap_err();
        assert_eq!(err, InstructionError::Custom(24)); // InvalidCustomChainId

        let mut config = SubchainConfig::default();
        let evm_address = crate::evm_address_for_program(user_id);
        config.alloc.insert(
            evm_address,
            AllocAccount::new_with_balance(lamports_to_wei(10000)),
        );

        setup_chain(&mut evm_context, user_id, chain_id, config, 0);

        let evm_acc = evm_context
            .evm_state
            .get_account_state(evm_address)
            .unwrap_or_default();
        assert_eq!(evm_acc.balance, U256::from(0));

        // TODO(L): Check account state in native chain. (Deserialize state and check fields)
        // failed because already exist
        let err = evm_context
            .process_instruction(crate::create_evm_subchain_account(
                user_id,
                chain_id,
                SubchainConfig::default(),
            ))
            .unwrap_err();

        assert_eq!(err, InstructionError::Custom(20));
    }

    #[test]
    fn subchain_transfer() {
        let mut evm_context = EvmMockContext::new(0);
        let user_id = Pubkey::new_unique();
        let user_acc = evm_context.native_account(user_id);
        user_acc.set_owner(system_program::ID);
        user_acc.set_lamports(10000000000000000); // 1_000_000 VLX

        let secret_key = evm::SecretKey::from_slice(&SECRET_KEY_DUMMY).unwrap();
        let address = secret_key.to_address();

        let to = crate::evm_address_for_program(user_id);
        let mut config = SubchainConfig::default();
        config.alloc.insert(
            address,
            AllocAccount::new_with_balance(lamports_to_wei(10000)),
        );

        let chain_id = 0x561;
        setup_chain(&mut evm_context, user_id, chain_id, config, 840000);
        transfer_on_subchain(
            &mut evm_context,
            chain_id,
            secret_key,
            to,
            10.into(),
            user_id,
        );
        assert!(evm_context.evm_state.get_account_state(address).is_none());
        assert!(evm_context.evm_state.get_account_state(to).is_none());
    }

    #[test]
    fn subchain_transfer_with_invalid_gasprice() {
        let mut evm_context = EvmMockContext::new(100_000_000_000);
        let owner_pub = Pubkey::new_unique();
        let owner_acc = evm_context.native_account(owner_pub);
        owner_acc.set_owner(system_program::ID);
        owner_acc.set_lamports(10_000_000_000_000_000);

        let alice = evm::SecretKey::from_slice(&SECRET_KEY_DUMMY).unwrap();
        let alice_pub = alice.to_address();
        let bob = evm::SecretKey::from_slice(&[2; 32]).unwrap();
        let bob_pub = bob.to_address();

        let subchain_min_gas_gwei = 42;
        let mut config = SubchainConfig {
            min_gas_price: U256::from(subchain_min_gas_gwei) * U256::exp10(9),
            ..Default::default()
        };
        config.alloc.insert(
            alice_pub,
            AllocAccount::new_with_balance(lamports_to_wei(100_000_000_000)), // 100 VLX
        );

        let chain_id = 0x561;

        setup_chain(
            &mut evm_context,
            owner_pub,
            chain_id,
            config,
            100_000_000_000,
        );

        let mut try_transfer = |min_gas_gwei: u64| -> Result<(), InstructionError> {
            let gas_price = U256::from(min_gas_gwei) * U256::exp10(9);
            let nonce = {
                let subchain_evm = evm_context.subchains.get(&chain_id).unwrap();
                let from_state_before = subchain_evm
                    .get_account_state(alice_pub)
                    .expect("Sender should exist on blockchain");
                from_state_before.nonce
            };

            let tx_transfer = evm::UnsignedTransaction {
                nonce,
                gas_price,
                gas_limit: 21000.into(),
                action: TransactionAction::Call(bob_pub),
                value: lamports_to_wei(100),
                input: vec![],
            };
            let tx_transfer = tx_transfer.sign(&alice, Some(chain_id));

            evm_context.process_instruction(crate::send_raw_tx_subchain(
                owner_pub,
                tx_transfer.clone(),
                None,
                chain_id,
            ))
        };

        assert_eq!(
            try_transfer(subchain_min_gas_gwei - 1).unwrap_err(),
            InstructionError::Custom(3) // EvmError::InternalExecutorError
        );

        assert!(try_transfer(subchain_min_gas_gwei + 1).is_ok(),);
    }

    #[test]
    #[should_panic(expected = "Result::unwrap()` on an `Err` value: Custom(18)")] // NativeAccountInsufficientFunds
    fn subchain_transfer_no_extra_deposit() {
        let mut evm_context = EvmMockContext::new(0);
        let user_id = Pubkey::new_unique();
        let user_acc = evm_context.native_account(user_id);
        user_acc.set_owner(system_program::ID);
        user_acc.set_lamports(10000000000000000);

        let secret_key = evm::SecretKey::from_slice(&SECRET_KEY_DUMMY).unwrap();
        let address = secret_key.to_address();

        let to = crate::evm_address_for_program(user_id);
        let mut config = SubchainConfig::default();
        config.alloc.insert(
            address,
            AllocAccount::new_with_balance(lamports_to_wei(10000)),
        );

        let chain_id = 0x561;
        setup_chain(&mut evm_context, user_id, chain_id, config, 1);
        transfer_on_subchain(
            &mut evm_context,
            chain_id,
            secret_key,
            to,
            10.into(),
            user_id,
        );
    }

    fn setup_chain(
        evm_context: &mut EvmMockContext,
        owner: solana::Address,
        chain_id: u64,
        config: SubchainConfig,
        extra_lamports: u64,
    ) {
        evm_context.feature_set.activate(
            &solana_sdk::feature_set::velas::evm_subchain::id(),
            evm_context.evm_bank_slot,
        );
        evm_context
            .process_instruction(crate::create_evm_subchain_account(
                owner,
                chain_id,
                config.clone(),
            ))
            .unwrap();

        let subchain_pubkey = crate::evm_state_subchain_account(chain_id);
        let subchain_state_account = evm_context.native_account(subchain_pubkey);
        subchain_state_account.set_lamports(subchain_state_account.lamports() + extra_lamports);

        let subchain_evm = evm_context.subchains.get(&chain_id).unwrap();

        assert_eq!(
            subchain_evm.get_executed_transactions().len(),
            config.alloc.len()
        );
        for (evm_address, account) in config.alloc {
            let evm_acc_on_sub = subchain_evm.get_account_state(evm_address).unwrap();
            assert_eq!(evm_acc_on_sub.balance, account.balance);
        }
    }

    fn transfer_on_subchain(
        evm_context: &mut EvmMockContext,
        chain_id: u64,
        sender: evm::SecretKey,
        receiver: evm::Address,
        amount: U256,
        bridge: solana::Address,
    ) -> H256 {
        let transfer_gas_used = 21000;

        let subchain_pubkey = crate::evm_state_subchain_account(chain_id);

        let subchain_state_account_before = evm_context.native_account_cloned(subchain_pubkey);
        let mut state_before =
            crate::subchain::SubchainState::try_from_slice(subchain_state_account_before.data())
                .expect("Subchain state should be correct");

        assert!(
            subchain_state_account_before.lamports()
                > LAMPORTS_PER_VLX * SUBCHAIN_CREATION_DEPOSIT_VLX,
            "Subchain account should have enough lamports"
        );

        let subchain_evm = evm_context.subchains.get(&chain_id).unwrap();
        let address = sender.to_address();
        let from_state_before = subchain_evm
            .get_account_state(address)
            .expect("Sender should exist on blockchain");
        let tx_transfer = evm::UnsignedTransaction {
            nonce: from_state_before.nonce,
            gas_price: state_before.min_gas_price,
            gas_limit: transfer_gas_used.into(),
            action: TransactionAction::Call(receiver),
            value: amount,
            input: vec![],
        };
        let gas = tx_transfer.gas_price * transfer_gas_used;
        let total = amount + gas;
        let tx_transfer = tx_transfer.sign(&sender, Some(chain_id));

        let tx_hash = tx_transfer.tx_id_hash();
        let before = subchain_evm.get_executed_transactions().len();

        let to_state_before = subchain_evm.get_account_state(receiver).unwrap_or_default();
        evm_context
            .process_instruction(crate::send_raw_tx_subchain(
                bridge,
                tx_transfer.clone(),
                None,
                chain_id,
            ))
            .unwrap();
        let subchain_evm = evm_context.subchains.get(&chain_id).unwrap();
        assert!(subchain_evm.find_transaction_receipt(tx_hash).is_some());

        let after = subchain_evm.get_executed_transactions().len();
        assert_eq!(after, before + 1);

        let to_state = subchain_evm.get_account_state(receiver).unwrap();
        assert_eq!(to_state.balance, to_state_before.balance + amount);
        let from_state = subchain_evm.get_account_state(address).unwrap();
        assert_eq!(from_state.balance, from_state_before.balance - total);

        let subchain_state_account = evm_context.native_account(subchain_pubkey);
        assert!(
            subchain_state_account.lamports() >= LAMPORTS_PER_VLX * SUBCHAIN_CREATION_DEPOSIT_VLX
        );

        let state_after =
            crate::subchain::SubchainState::try_from_slice(subchain_state_account.data())
                .expect("Subchain state should be correct");

        state_before.last_hashes = state_after.last_hashes.clone();
        assert_eq!(state_before, state_after);

        let burn_fee = transfer_gas_used * evm::BURN_GAS_PRICE_IN_SUBCHAIN;
        let burn_fee = wei_to_lamports(burn_fee.into()).0;
        assert_eq!(
            subchain_state_account_before.lamports() - subchain_state_account.lamports(),
            burn_fee
        );

        tx_hash
    }

    // 1. test that sequence of transactions will set hash after successfull processing tx
    #[test]
    fn subchain_finalize() {
        let mut evm_context = EvmMockContext::new(0);
        let user_id = Pubkey::new_unique();
        let user_acc = evm_context.native_account(user_id);
        user_acc.set_owner(system_program::ID);
        user_acc.set_lamports(10000000000000000);

        let secret_key = evm::SecretKey::from_slice(&SECRET_KEY_DUMMY).unwrap();
        let address = secret_key.to_address();

        let to = crate::evm_address_for_program(user_id);
        let mut config = SubchainConfig::default();
        config.alloc.insert(
            address,
            AllocAccount::new_with_balance(lamports_to_wei(10000)),
        );

        let chain_id = 0x561;
        setup_chain(&mut evm_context, user_id, chain_id, config, 840000 * 3);

        // multiple finalize should not create multiple blocks
        evm_context.commit_state();
        evm_context.commit_state();

        let subchain_evm = evm_context.subchains.get(&chain_id).unwrap();
        assert_eq!(subchain_evm.get_executed_transactions().len(), 0);
        assert_eq!(subchain_evm.block_number(), 1);
        assert_eq!(evm_context.evm_state.block_number(), 0);

        let subchain_pubkey = crate::evm_state_subchain_account(chain_id);
        let state = crate::subchain::SubchainState::try_from_slice(
            evm_context.native_account(subchain_pubkey).data(),
        )
        .unwrap();

        assert_eq!(num_non_empty_hashes(state.last_hashes().get_hashes()), 0);

        let _tx_hash = transfer_on_subchain(
            &mut evm_context,
            chain_id,
            secret_key,
            to,
            10.into(),
            user_id,
        );

        let state = crate::subchain::SubchainState::try_from_slice(
            evm_context.native_account(subchain_pubkey).data(),
        )
        .unwrap();

        assert_eq!(num_non_empty_hashes(state.last_hashes().get_hashes()), 1);
        // second transfer on same block should not create new blockshash
        let _tx_hash = transfer_on_subchain(
            &mut evm_context,
            chain_id,
            secret_key,
            to,
            10.into(),
            user_id,
        );

        let state = crate::subchain::SubchainState::try_from_slice(
            evm_context.native_account(subchain_pubkey).data(),
        )
        .unwrap();

        assert_eq!(num_non_empty_hashes(state.last_hashes().get_hashes()), 1);

        // Finalize can't create new blockshash
        evm_context.commit_state();

        let state = crate::subchain::SubchainState::try_from_slice(
            evm_context.native_account(subchain_pubkey).data(),
        )
        .unwrap();

        assert_eq!(num_non_empty_hashes(state.last_hashes().get_hashes()), 1);
        // but new transaction will
        let _tx_hash = transfer_on_subchain(
            &mut evm_context,
            chain_id,
            secret_key,
            to,
            10.into(),
            user_id,
        );
        let state = crate::subchain::SubchainState::try_from_slice(
            evm_context.native_account(subchain_pubkey).data(),
        )
        .unwrap();

        assert_eq!(num_non_empty_hashes(state.last_hashes().get_hashes()), 2);
    }

    fn num_non_empty_hashes(hashes: &[H256]) -> usize {
        hashes.iter().filter(|h| !h.is_zero()).count()
    }

    #[test]
    fn test_prefixes_checker() {
        assert!(EvmProcessor::check_prefixed_chain_id(0x561));
        assert!(EvmProcessor::check_prefixed_chain_id(0x56f));
        assert!(EvmProcessor::check_prefixed_chain_id(0x562));
        assert!(EvmProcessor::check_prefixed_chain_id(0x5623));
        assert!(EvmProcessor::check_prefixed_chain_id(0x56235));
        assert!(EvmProcessor::check_prefixed_chain_id(0x562356));
        assert!(!EvmProcessor::check_prefixed_chain_id(0x1562356));
        assert!(!EvmProcessor::check_prefixed_chain_id(0x156235));
        assert!(!EvmProcessor::check_prefixed_chain_id(0x15623));
        assert!(!EvmProcessor::check_prefixed_chain_id(0x1562));
        assert!(!EvmProcessor::check_prefixed_chain_id(0x156));
        assert!(!EvmProcessor::check_prefixed_chain_id(0x10562));
        assert!(!EvmProcessor::check_prefixed_chain_id(0x1056));
        assert!(!EvmProcessor::check_prefixed_chain_id(0x105));
        assert!(!EvmProcessor::check_prefixed_chain_id(0x1));
        assert!(!EvmProcessor::check_prefixed_chain_id(0x0));
        assert!(!EvmProcessor::check_prefixed_chain_id(0x56));

        assert!(!EvmProcessor::check_prefixed_chain_id(0x53));

        assert!(!EvmProcessor::check_prefixed_chain_id(0x5f));

        assert!(!EvmProcessor::check_prefixed_chain_id(0x50));

        assert!(!EvmProcessor::check_prefixed_chain_id(0x50));

        assert!(!EvmProcessor::check_prefixed_chain_id(0x100));
        assert!(!EvmProcessor::check_prefixed_chain_id(0xAC00000000000000));
    }

    #[quickcheck_macros::quickcheck]
    fn qc_prefixes_checker(chain_id: u64) -> bool {
        let res = EvmProcessor::check_prefixed_chain_id(chain_id);
        let str_res = format!("{:x}", chain_id);
        (str_res.starts_with("56") && str_res.len() > 2) == res
    }
}
