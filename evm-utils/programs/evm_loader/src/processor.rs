
use std::collections::BTreeMap;
use solana_sdk::instruction::InstructionError;
use solana_sdk::{
    entrypoint_native::{Logger, InvokeContext},
    program_utils::limited_deserialize,
    account::{is_executable, next_keyed_account, KeyedAccount},
    loader_instruction::LoaderInstruction,
};
use solana_sdk::pubkey::Pubkey;
use primitive_types::{H160, H256, U256};
use evm::backend::{MemoryVicinity, Apply};
use evm_state::backend::{MemoryAccount, MemoryBackend};
use evm::executor::{StackExecutor};
use evm::Handler;
use evm::{Transfer, Context, Capture, CreateScheme};
use std::cell::{RefCell};
use std::rc::Rc;
use block::{Transaction as ETransaction, TransactionAction as ETransactionAction};
use rlp;


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
    keyed_accounts: &[KeyedAccount],
    data: &[u8],
    cx: &mut dyn InvokeContext,
) -> Result<(), InstructionError> {

    let logger = cx.get_logger();
    let evm_executor = cx.get_evm_executor();
    let mut evm_executor = evm_executor.borrow_mut();
    let evm_executor = evm_executor.rent_executor();

    let tx: ETransaction = rlp::decode(data);
    log!(logger, "Run evm exec with tx = {:?}.", tx);
    EVMProcessor::do_invoke_main(evm_executor, keyed_accounts, &data, logger)
    // } else {
    //     log!(logger, "Write evm code.");
    //     match limited_deserialize(data)? {
    //         LoaderInstruction::Write { offset, bytes } =>
    //             EVMProcessor::do_write(keyed_accounts, offset, &bytes),
    //         LoaderInstruction::Finalize =>
    //             EVMProcessor::do_finalize(evm_executor, keyed_accounts, logger),
    //     }
    // }
}

pub struct EVMProcessor;

impl EVMProcessor {
    fn read_account(bytes: &[u8]) -> Result<(H160, MemoryAccount), InstructionError> {
        limited_deserialize(bytes)
    }

    pub fn write_account(address: H160, account: MemoryAccount) -> Result<Vec<u8>, InstructionError> {
        bincode::serialize(&(address, account)).map_err(|_| InstructionError::InvalidAccountData)
    }
    pub fn add_or_open<'a>(logger: &Rc<RefCell<dyn Logger>>,
        state: &mut BTreeMap<H160, MemoryAccount>,
        accounts: &mut BTreeMap<H160, &'a KeyedAccount<'a>>,
        keyed_account: &'a KeyedAccount<'a>) -> Result<(), InstructionError> 
        {
        let ref mut account_data = keyed_account.account.borrow_mut().data;
        let (address, account) = match Self::read_account(&account_data) {
            Ok(a) => a,
            Err(_) => {
                let keyed_address = keyed_account.signer_key().map(|k| Self::pubkey_to_address(k))
                .ok_or(InstructionError::MissingRequiredSignature)?;
                let memory_account = MemoryAccount::default();
                *account_data =
                Self::write_account(keyed_address, memory_account.clone())?;
                (keyed_address, memory_account)
            }
        };
        // let address = Self::pubkey_to_address(keyed_account.unsigned_key());
        // let account = MemoryAccount::default();
        log!(logger, "reading account = {}, sol_key = {}", address, keyed_account.unsigned_key());
        accounts.insert(address, keyed_account);
        state.insert(address, account);
        Ok(())
    }

    pub fn add_account<'a>(logger: &Rc<RefCell<dyn Logger>>,
        state: &mut BTreeMap<H160, MemoryAccount>,
        accounts: &mut BTreeMap<H160, &'a KeyedAccount<'a>>,
        keyed_account: &'a KeyedAccount<'a>,
    ) -> Result<(), InstructionError> 
    {
        let (address, account) = Self::read_account(&keyed_account.account.borrow().data)?;

        log!(logger, "reading account = {}, sol_key = {}", address, keyed_account.unsigned_key());
        accounts.insert(address, keyed_account);
        state.insert(address, account);
        Ok(())
    }

    fn apply_accounts(
        applies: impl IntoIterator<Item=Apply<impl IntoIterator<Item=(H256, H256)>>>,
        keyed_accounts: BTreeMap<H160, &KeyedAccount>,
        logger: Rc<RefCell<dyn Logger>>,
    ) -> Result<(), InstructionError> {
        for apply in applies {
            match apply {
                Apply::Modify {
                    address,
                    basic,
                    code,
                    storage,
                    reset_storage,
                } => {
                    log!(logger, "Apply::Modify address = {}, basic = {:?}", address, basic);
                    if let Some(state_account) = keyed_accounts.get(&address) {
                        let (_, mut keyed_account) = Self::read_account(&state_account.account.borrow().data)?;
                        keyed_account.nonce = basic.nonce;
                        keyed_account.balance = basic.balance;

                        if reset_storage {
                            keyed_account.storage = Default::default();
                        }

                        for (key, value) in storage {
                            keyed_account.storage.insert(key, value);
                        }

                        if let Some(code) = code {
                            keyed_account.code = code;
                        }

                        state_account.account.borrow_mut().data =
                            Self::write_account(address, keyed_account)?;
                    }
                    else {
                        log!(logger, "Account is out of scope = {}.", address);
                        return Err(InstructionError::NotEnoughAccountKeys)
                    }
                },
                Apply::Delete {
                    address
                } => {
                    log!(logger, "Apply::Delete address = {}", address);
                    if let Some(state_account) = keyed_accounts.get(&address) {
                        let (keyed_address, _) =
                            Self::read_account(&state_account.account.borrow().data)?;

                        if keyed_address == address {
                            let keyed_account = Default::default();

                            state_account.account.borrow_mut().data =
                                Self::write_account(keyed_address, keyed_account)?;
                        }
                    }
                    else {
                        log!(logger, "Account is out of scope = {}.", address);
                        return Err(InstructionError::NotEnoughAccountKeys)
                    }

                },
            }
        }

        Ok(())
    }

    fn pubkey_to_address(key: &Pubkey) -> H160 {
        H256::from_slice(key.as_ref()).into()
    }

    // pub fn do_write(
    //     keyed_accounts: &[KeyedAccount],
    //     offset: u32,
    //     bytes: &[u8],
    // ) -> Result<(), InstructionError> {
    //     let mut keyed_accounts_iter = keyed_accounts.iter();
    //     let keyed_account = next_keyed_account(&mut keyed_accounts_iter)?;

    //     if keyed_account.signer_key().is_none() {
    //         // debug!("Error: key[0] did not sign the transaction");
    //         return Err(InstructionError::MissingRequiredSignature);
    //     }
    //     let offset = offset as usize;
    //     let len = bytes.len();
    //     // trace!("Write: offset={} length={}", offset, len);
    //     if keyed_account.account.borrow().data.len() < offset + len {
    //         // debug!(
    //         //     "Error: Write overflow: {} < {}",
    //         //     keyed_account.account.borrow().data.len(),
    //         //     offset + len
    //         // );
    //         return Err(InstructionError::AccountDataTooSmall);
    //     }
    //     keyed_account.account.borrow_mut().data[offset..offset + len].copy_from_slice(&bytes);
    //     Ok(())
    // }

    // pub fn do_finalize(
    //     evm_executor: &mut StackExecutor<MemoryBackend>,
    //     keyed_accounts: &[KeyedAccount],
    //     logger: Rc<RefCell<dyn Logger>>
    // ) -> Result<(), InstructionError> {
    //     log!(logger, "keyed_accounts num = {}", keyed_accounts.len());
    //     let mut accounts = BTreeMap::new();
    //     let mut state = BTreeMap::new();
    //     let mut keyed_accounts_iter = keyed_accounts.iter();

    //     let keyed_account = next_keyed_account(&mut keyed_accounts_iter)?;
    //     log!(logger, "contract account = {}", keyed_account.unsigned_key());

    //     // Init contract account in evm account
    //     let keyed_address = keyed_account.signer_key().map(|k| Self::pubkey_to_address(k))
    //         .ok_or(InstructionError::MissingRequiredSignature)?;
    //     let code = keyed_account.account.borrow().data.clone();
    //     let memory_account = MemoryAccount {
    //         code: code.clone(),
    //         .. Default::default()
    //     };
    //     keyed_account.account.borrow_mut().data =
    //     Self::write_account(keyed_address, memory_account)?;
    //     log!(logger, "reading account = {}, sol_key = {}", keyed_address, keyed_account.unsigned_key());
    //     accounts.insert(keyed_address, keyed_account);
    //     // EVMProcessor::add_account(&logger, &mut state, &mut accounts, keyed_account)?;

    //     // Skip system account
    //     let skip_sysvar_acc = keyed_accounts_iter.next().unwrap();
    //     // Init caller account
    //     let caller_account = keyed_accounts_iter.next().unwrap();
    //     log!(logger, "user account = {}", caller_account.unsigned_key());
    //     let caller_account_evm = caller_account.signer_key().map(|k| Self::pubkey_to_address(k)).ok_or(InstructionError::MissingRequiredSignature)?;
    //     caller_account.account.borrow_mut().data =
    //     Self::write_account(caller_account_evm, MemoryAccount::default())?;
    //     EVMProcessor::add_account(&logger, &mut state, &mut accounts,  caller_account)?;
        
    //     // Init evm  executor
    //     let vicinity = MemoryVicinity {
    //         gas_price: U256::zero(),
    //         origin: H160::default(),
    //         chain_id: U256::zero(),
    //         block_hashes: Vec::new(),
    //         block_number: U256::zero(),
    //         block_coinbase: H160::default(),
    //         block_timestamp: U256::zero(),
    //         block_difficulty: U256::zero(),
    //         block_gas_limit: U256::zero(),
    //     };

    //     log!(logger, "Found account = {}", keyed_address);
    //     for state_account in keyed_accounts_iter {
    //         let key = Self::pubkey_to_address(state_account.unsigned_key());
    //         state_account.account.borrow_mut().data =
    //         Self::write_account(key, MemoryAccount::default())?;
    //         EVMProcessor::add_account(&logger, &mut state, &mut accounts, state_account)?;
    //     }

    //     let backend = MemoryBackend::new(&vicinity, state);
    //     let config = evm::Config::istanbul();
    //     let mut executor = StackExecutor::new(&backend, usize::max_value(), &config);
    //     let exit_reason = match 
    //         executor.create(caller_account_evm, CreateScheme::Fixed(keyed_address), U256::zero(), code, None) {
    //             Capture::Exit((s, _, _)) => s,
    //             Capture::Trap(_) => unreachable!(),
    //         };

    //     let (applies, _logs) = executor.deconstruct();

    //     if !exit_reason.is_succeed() {
    //         log!(logger, "exit reason = {:?}", exit_reason);
    //         return Ok(())
    //     }
    //     keyed_account.account.borrow_mut().executable = true;
    

    //     Self::apply_accounts(applies, accounts, logger)?;
    //     Ok(())
    // }

    pub fn do_invoke_main(
        evm_executor: &mut StackExecutor<MemoryBackend>,
        keyed_accounts: &[KeyedAccount],
        data: &[u8],
        logger: Rc<RefCell<dyn Logger>>,
    ) -> Result<(), InstructionError> {

        let mut accounts = BTreeMap::new();
        let mut state = BTreeMap::new();
        let ref mut keyed_accounts_iter =  keyed_accounts.iter();
        // Init caller account
        let caller_account = next_keyed_account(keyed_accounts_iter)?;
        // let caller_address = caller_account
        //     .signer_key().map(|k| Self::pubkey_to_address(k))
        //     .ok_or(InstructionError::MissingRequiredSignature)?;

        let caller_address = Self::pubkey_to_address(caller_account.unsigned_key());
        EVMProcessor::add_or_open(&logger, &mut state, &mut accounts,  caller_account)?;

        // Init program account
        let keyed_account = next_keyed_account(keyed_accounts_iter)?;

        let keyed_address = keyed_account.signer_key().map(|k| Self::pubkey_to_address(k))
            .ok_or(InstructionError::MissingRequiredSignature)?;
        // let keyed_address = Self::pubkey_to_address(keyed_account.unsigned_key());
        EVMProcessor::add_or_open(&logger, &mut state, &mut accounts,  keyed_account)?;


        for state_account in keyed_accounts_iter {
            EVMProcessor::add_or_open(&logger, &mut state, &mut accounts,  state_account)?;
        }

        let value = U256::from(10000000);
        state.get_mut(&keyed_address).unwrap().balance = value;
        let context = Context {
			caller: keyed_address,
			address: caller_address,
			apparent_value: value / 2,
        };
        let transfer = Transfer {
			source: keyed_address,
			target: caller_address,
			value: value / 2
		};
        let result = evm_executor.call(
            caller_address,
            transfer.into(),
            data.to_vec(),
            None,
            false,
            context,
        );

        log!(logger, "exit reason = {:?}", result);

        // let (applies, _logs) = executor.deconstruct();

        // Self::apply_accounts(applies, accounts, logger)?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
use primitive_types::{H256, H160, U256};
use evm_state::transactions::{ TransactionAction, TransactionSignature};

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
    fn serialize_deserialize_eth_tx() {
        let tx = 

    }
}