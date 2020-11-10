use super::instructions::{Deposit, EvmInstruction};
use super::scope::*;
use evm::TransactionAction;
use log::*;
use primitive_types::U256;
use solana_sdk::instruction::InstructionError;
use solana_sdk::pubkey::Pubkey;
use solana_sdk::{
    account::KeyedAccount,
    account_info::AccountInfo,
    entrypoint_native::{InvokeContext, Logger},
    program_utils::limited_deserialize,
    sysvar::{rent::Rent, Sysvar},
};

macro_rules! log{
    ($logger:ident, $message:expr) => {
        if let Ok(mut logger) = $logger.try_borrow_mut() {
            if logger.log_enabled() {
                logger.log($message);
            }
        }
    };
    ($logger:ident, $fmt:expr, $($arg:tt)*) => {
        if let Ok(mut logger) = $logger.try_borrow_mut() {
            logger.log(&format!($fmt, $($arg)*));
        }
    };
}

const LAMPORTS_TO_GWEI_PRICE: u64 = 1_000_000_000; // Lamports is 1/10^9 of SOLs while GWEI is 1/10^18

/// Return the next AccountInfo or a NotEnoughAccountKeys error
pub fn next_account_info<'a, 'b, I: Iterator<Item = &'a KeyedAccount<'b>>>(
    iter: &mut I,
) -> Result<I::Item, InstructionError> {
    iter.next().ok_or(InstructionError::NotEnoughAccountKeys)
}

pub fn process_initialize_deposit(
    accounts: &[KeyedAccount],
    pubkey: Pubkey,
) -> Result<(), InstructionError> {
    let account_info_iter = &mut accounts.iter();
    let deposit_info = next_account_info(account_info_iter)?;
    let deposit_info_len = deposit_info.data_len()?;
    let rent = &Rent::from_account(&*next_account_info(account_info_iter)?.try_account_ref()?)
        .ok_or(InstructionError::InvalidArgument)?;

    let mut deposit: Deposit =
        limited_deserialize(&deposit_info.try_account_ref()?.data).unwrap_or_default();
    if deposit.is_initialized {
        return Err(InstructionError::AccountAlreadyInitialized.into());
    }

    if !rent.is_exempt(deposit_info.lamports()?, deposit_info_len) {
        return Err(InstructionError::ExecutableAccountNotRentExempt.into());
    }

    deposit.deposit_authority = Option::Some(pubkey);
    deposit.is_initialized = true;
    deposit.locked_lamports = 0;

    bincode::serialize_into(&mut *deposit_info.try_account_ref_mut()?.data, &deposit)
        .map_err(|_| InstructionError::InvalidArgument)?;

    Ok(())
}

pub fn process_instruction(
    program_id: &Pubkey,
    keyed_accounts: &[KeyedAccount],
    data: &[u8],
    cx: &mut dyn InvokeContext,
) -> Result<(), InstructionError> {
    let logger = cx.get_logger();
    let evm_executor = cx.get_evm_executor();
    let mut evm_executor = evm_executor.borrow_mut();
    let evm_executor = evm_executor.rent_executor();

    let ix = limited_deserialize(data)?;
    log!(logger, "Run evm exec with ix = {:?}.", ix);
    match ix {
        EvmInstruction::EvmTransaction { evm_tx } => {
            // TODO: Handle gas price
            // TODO: Handle nonce
            // TODO: validate tx signature

            let result = match evm_tx.action {
                TransactionAction::Call(addr) => evm_executor.transact_call(
                    evm_tx
                        .caller()
                        .map_err(|_| InstructionError::InvalidArgument)?,
                    addr,
                    evm_tx.value,
                    evm_tx.input,
                    evm_tx.gas_limit.as_usize(),
                ),
                TransactionAction::Create => (
                    evm_executor.transact_create(
                        evm_tx
                            .caller()
                            .map_err(|_| InstructionError::InvalidArgument)?,
                        evm_tx.value,
                        evm_tx.input,
                        evm_tx.gas_limit.as_usize(),
                    ),
                    vec![],
                ),
            };
            // TODO: Map evm errors on solana.
            log!(logger, "Exit status = {:?}", result);
        }
        EvmInstruction::CreateDepositAccount { pubkey } => {
            process_initialize_deposit(keyed_accounts, pubkey)?
        }
        EvmInstruction::SwapNativeToEther {
            lamports,
            ether_address,
        } => {
            let accounts_iter = &mut keyed_accounts.iter();
            let signer_account = next_account_info(accounts_iter)?;
            let authority_account = next_account_info(accounts_iter)?;
            let gweis = U256::from(lamports) * U256::from(LAMPORTS_TO_GWEI_PRICE);
            log!(
                logger,
                "Sending lamports to Gwei tokens from={},to={}",
                authority_account.unsigned_key(),
                ether_address
            );

            if keyed_accounts.len() < 1 {
                error!("Not enough accounts");
                return Err(InstructionError::InvalidArgument);
            }

            if lamports == 0 {
                return Ok(());
            }

            let mut deposit: Deposit =
                limited_deserialize(&authority_account.account.borrow().data).unwrap_or_default();

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
        _ => todo!("Do other staff later"),
    }
    Ok(())
}
#[cfg(test)]
mod test {
    use super::*;
    use crate::evm_tx;
    use evm_state::transactions::{TransactionAction, TransactionSignature};
    use primitive_types::{H160, H256, U256};
    use solana_sdk::program_utils::limited_deserialize;

    use solana_sdk::{
        account::Account,
        entrypoint_native::{ComputeBudget, ComputeMeter, Logger, ProcessInstruction},
        instruction::CompiledInstruction,
        message::Message,
    };
    use std::{cell::RefCell, rc::Rc};

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
        let sol_ix = evm_tx(tx);
        let ser = bincode::serialize(&sol_ix).unwrap();
        assert_eq!(sol_ix, limited_deserialize(&ser).unwrap());
    }

    #[derive(Debug, Default, Clone)]
    pub struct MockComputeMeter {
        pub remaining: u64,
    }
    impl ComputeMeter for MockComputeMeter {
        fn consume(&mut self, amount: u64) -> Result<(), InstructionError> {
            self.remaining = self.remaining.saturating_sub(amount);
            if self.remaining == 0 {
                return Err(InstructionError::ComputationalBudgetExceeded);
            }
            Ok(())
        }
        fn get_remaining(&self) -> u64 {
            self.remaining
        }
    }
    #[derive(Debug, Default, Clone)]
    pub struct MockLogger {
        pub log: Rc<RefCell<Vec<String>>>,
    }
    impl Logger for MockLogger {
        fn log_enabled(&self) -> bool {
            true
        }
        fn log(&mut self, message: &str) {
            self.log.borrow_mut().push(message.to_string());
        }
    }
    #[derive(Debug)]
    pub struct MockInvokeContext {
        pub key: Pubkey,
        pub logger: MockLogger,
        pub compute_meter: MockComputeMeter,
        pub evm_executor: Rc<RefCell<evm_state::StaticExecutor<evm_state::EvmState>>>,
    }
    impl Default for MockInvokeContext {
        fn default() -> Self {
            MockInvokeContext {
                key: Pubkey::default(),
                logger: MockLogger::default(),
                compute_meter: MockComputeMeter {
                    remaining: std::u64::MAX,
                },
                evm_executor: Rc::new(RefCell::new(evm_state::StaticExecutor::with_config(
                    evm_state::EvmState::default(),
                    evm_state::Config::istanbul(),
                    10000000,
                ))),
            }
        }
    }
    impl InvokeContext for MockInvokeContext {
        fn push(&mut self, _key: &Pubkey) -> Result<(), InstructionError> {
            Ok(())
        }
        fn pop(&mut self) {}
        fn verify_and_update(
            &mut self,
            _message: &Message,
            _instruction: &CompiledInstruction,
            _accounts: &[Rc<RefCell<Account>>],
        ) -> Result<(), InstructionError> {
            Ok(())
        }
        fn get_caller(&self) -> Result<&Pubkey, InstructionError> {
            Ok(&self.key)
        }
        fn get_programs(&self) -> &[(Pubkey, ProcessInstruction)] {
            &[]
        }
        fn get_logger(&self) -> Rc<RefCell<dyn Logger>> {
            Rc::new(RefCell::new(self.logger.clone()))
        }
        fn is_cross_program_supported(&self) -> bool {
            true
        }
        fn get_compute_budget(&self) -> ComputeBudget {
            ComputeBudget::default()
        }
        fn get_compute_meter(&self) -> Rc<RefCell<dyn ComputeMeter>> {
            Rc::new(RefCell::new(self.compute_meter.clone()))
        }
        fn get_evm_executor(&self) -> Rc<RefCell<evm_state::StaticExecutor<evm_state::EvmState>>> {
            self.evm_executor.clone()
        }
    }

    const SECRET_KEY_DUMMY: [u8; 32] = [1; 32];

    #[test]
    fn execute_tx() {
        let mut cx = MockInvokeContext::default();
        let secret_key = evm::SecretKey::from_slice(&SECRET_KEY_DUMMY).unwrap();
        let tx_create = evm::UnsignedTransaction {
            nonce: 0.into(),
            gas_price: 0.into(),
            gas_limit: 300000.into(),
            action: TransactionAction::Create,
            value: 0.into(),
            input: hex::decode(evm_state::HELLO_WORLD_CODE).unwrap().to_vec(),
        };
        let tx_create = tx_create.sign(&secret_key, None);

        assert!(process_instruction(
            &crate::ID,
            &[],
            &bincode::serialize(&EvmInstruction::EvmTransaction {
                evm_tx: tx_create.clone()
            })
            .unwrap(),
            &mut cx
        )
        .is_ok());
        println!("cx = {:?}", cx);
        // cx.evm_executor.borrow_mut().deconstruct();
        let tx_address = tx_create.address().unwrap();
        let tx_call = evm::UnsignedTransaction {
            nonce: 0.into(),
            gas_price: 0.into(),
            gas_limit: 300000.into(),
            action: TransactionAction::Call(tx_address),
            value: 0.into(),
            input: hex::decode(evm_state::HELLO_WORLD_ABI).unwrap().to_vec(),
        };

        let tx_call = tx_call.sign(&secret_key, None);
        assert!(process_instruction(
            &crate::ID,
            &[],
            &bincode::serialize(&EvmInstruction::EvmTransaction { evm_tx: tx_call }).unwrap(),
            &mut cx
        )
        .is_ok());
        println!("cx = {:?}", cx);
        // TODO: Assert that tx executed successfull.
        panic!();
        // assert!(process_instruction(&crate::ID, &[], tx_call, &mut cx).is_ok());
    }
}
