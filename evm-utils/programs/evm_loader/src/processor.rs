use solana_sdk::instruction::InstructionError;
use solana_sdk::{
    entrypoint_native::{Logger, InvokeContext},
    program_utils::limited_deserialize,
    account::{KeyedAccount},
};
use solana_sdk::pubkey::Pubkey;


use super::scope::*;
use evm::{TransactionAction};
use super::instructions::EvmInstruction;

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

pub fn process_instruction(
    _program_id: &Pubkey,
    _keyed_accounts: &[KeyedAccount],
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
        EvmInstruction::EvmTransaction {
            evm_tx
        } => {
            // TODO: Handle gas price
            // TODO: Handle nonce
            // TODO: validate tx signature

            let result = match evm_tx.action {
                TransactionAction::Call(addr) => {
                    evm_executor.transact_call(evm_tx.caller().map_err(|_| InstructionError::InvalidArgument)?,
                    addr,
                     evm_tx.value,
                     evm_tx.input,
                     evm_tx.gas_limit.as_usize())
                },
                TransactionAction::Create => {
                    (evm_executor.transact_create(evm_tx.caller().map_err(|_| InstructionError::InvalidArgument)?,
                    evm_tx.value,
                    evm_tx.input,
                    evm_tx.gas_limit.as_usize()),
                    vec![])
                }
            };
            log!(logger, "Exit status = {:?}", result);
        }
        _ => todo!("Do other staff later")
    }
    Ok(())
}
#[cfg(test)]
mod test {
    use super::*;
    use primitive_types::{H256, H160, U256};
    use evm_state::transactions::{ TransactionAction, TransactionSignature};
    use crate::evm_tx;
    use solana_sdk::program_utils::limited_deserialize;

    use solana_runtime::message_processor::ThisInvokeContext;
    use solana_sdk::{
        account::Account,
        entrypoint_native::{ComputeMeter, ComputeBudget, Logger, ProcessInstruction},
        instruction::CompiledInstruction,
        message::Message,
        rent::Rent,
    };
    use std::{cell::RefCell, fs::File, io::Read, ops::Range, rc::Rc};


    fn dummy_eth_tx() -> evm_state::transactions::Transaction{
        evm_state::transactions::Transaction {
            nonce: U256::zero(),
            gas_price: U256::zero(),
            gas_limit: U256::zero(),
            action: TransactionAction::Call(H160::zero()),
            value: U256::zero(),
            signature: TransactionSignature{
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
        pub evm_executor: Rc<RefCell<evm_state::StaticExecutor<evm_state::backend::MemoryBackend>>>
    }
    impl Default for MockInvokeContext {
        fn default() -> Self {
            MockInvokeContext {
                key: Pubkey::default(),
                logger: MockLogger::default(),
                compute_meter: MockComputeMeter {
                    remaining: std::u64::MAX,
                },
                evm_executor: Rc::new(RefCell::new(evm_state::StaticExecutor::with_config(evm_state::backend::MemoryBackend::default(), evm_state::Config::istanbul(), 10000000)))
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
        fn get_evm_executor(&self) -> Rc<RefCell<evm_state::StaticExecutor<evm_state::backend::MemoryBackend>>> {
            self.evm_executor.clone()
        }
    }

    const SECRET_KEY_DUMMY:[u8;32] = [1;32];
    #[test]
    fn execute_tx()
    {
        let mut cx = MockInvokeContext::default();
        let secret_key = evm::SecretKey::from_slice(&SECRET_KEY_DUMMY).unwrap();
        let tx_create = evm::UnsignedTransaction {
            nonce: 0.into(),
            gas_price: 0.into(),
            gas_limit: 300000.into(),
            action: TransactionAction::Create,
            value: 0.into(),
            input: hex::decode(evm_state::HELLO_WORLD_CODE).unwrap().to_vec()
        };
        let tx_create = tx_create.sign(&secret_key, None);

        assert!(process_instruction(&crate::ID, &[], &bincode::serialize(&EvmInstruction::EvmTransaction{evm_tx: tx_create.clone()}).unwrap(), &mut cx).is_ok());
        println!("cx = {:?}", cx);
        // cx.evm_executor.borrow_mut().deconstruct();
        let tx_address = tx_create.address().unwrap();
        let tx_call = evm::UnsignedTransaction {
            nonce: 0.into(),
            gas_price: 0.into(),
            gas_limit: 300000.into(),
            action: TransactionAction::Call(tx_address),
            value: 0.into(),
            input: hex::decode(evm_state::HELLO_WORLD_ABI).unwrap().to_vec()
        };

        let tx_call = tx_call.sign(&secret_key, None);
        assert!(process_instruction(&crate::ID, &[], &bincode::serialize(&EvmInstruction::EvmTransaction{evm_tx: tx_call}).unwrap(), &mut cx).is_ok());
        println!("cx = {:?}", cx);
        panic!();
        // assert!(process_instruction(&crate::ID, &[], tx_call, &mut cx).is_ok());
    }
}