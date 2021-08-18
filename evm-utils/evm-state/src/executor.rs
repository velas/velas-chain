use evm::executor::{MemoryStackState, StackState, StackSubstateMetadata};
pub use evm::{
    backend::{Apply, ApplyBackend, Backend, Log, MemoryAccount, MemoryVicinity},
    executor::StackExecutor,
    Config, Context, Handler, Transfer,
    {ExitError, ExitFatal, ExitReason, ExitRevert, ExitSucceed},
};

use log::*;
pub use primitive_types::{H256, U256};
pub use secp256k1::rand;
use snafu::ensure;

use crate::types::H160;
use crate::{
    context::{ChainContext, EvmConfig, ExecutorContext, TransactionContext},
    state::{AccountProvider, EvmBackend, Incomming},
    transactions::{
        Transaction, TransactionAction, TransactionInReceipt, TransactionReceipt,
        UnsignedTransaction, UnsignedTransactionWithCaller,
    },
};
use crate::{error::*, BlockVersion};

pub use triedb::empty_trie_hash;

pub const MAX_TX_LEN: u64 = 3 * 1024 * 1024; // Limit size to 3 MB
pub const TX_MTU: usize = 908;

// NOTE: value must not overflow i32::MAX at least
pub const TEST_CHAIN_ID: u64 = 0xDEAD;

/// Exit result, if succeed, returns `ExitSucceed` - info about execution, Vec<u8> - output data, u64 - gas cost
pub type PrecompileCallResult = Result<(ExitSucceed, Vec<u8>, u64), ExitError>;

#[derive(Clone, Debug)]
pub struct ExecutionResult {
    pub exit_reason: evm::ExitReason,
    pub exit_data: Vec<u8>,
    pub used_gas: u64,
    pub tx_logs: Vec<Log>,
    pub tx_id: H256,
}

#[derive(Debug)]
pub struct Executor {
    pub evm_backend: EvmBackend<Incomming>,
    chain_context: ChainContext,
    config: EvmConfig,
}

impl Executor {
    // Return new default executor, with empty state stored in temporary dirrectory
    pub fn testing() -> Self {
        Self::with_config(Default::default(), Default::default(), Default::default())
    }
    pub fn default_configs(state: EvmBackend<Incomming>) -> Self {
        Self::with_config(state, Default::default(), Default::default())
    }

    pub fn with_config(
        evm_backend: EvmBackend<Incomming>,
        chain_context: ChainContext,
        config: EvmConfig,
    ) -> Self {
        Executor {
            evm_backend,
            chain_context,
            config,
        }
    }

    pub fn support_precompile(&self) -> bool {
        self.evm_backend.state.block_version >= BlockVersion::VersionConsistentHashes
    }

    #[allow(clippy::too_many_arguments)]
    fn transaction_execute_raw<F>(
        &mut self,
        caller: H160,
        nonce: U256,
        gas_price: U256,
        gas_limit: U256,
        action: TransactionAction,
        input: Vec<u8>,
        value: U256,
        tx_chain_id: Option<u64>,
        tx_hash: H256,
        mut precompiles: F,
    ) -> Result<ExecutionResult, Error>
    where
        F: FnMut(H160, &[u8], Option<u64>, &Context) -> Option<PrecompileCallResult>,
    {
        let state_account = self
            .evm_backend
            .get_account_state(caller)
            .unwrap_or_default();

        let chain_id = self.config.chain_id;

        ensure!(
            tx_chain_id == Some(chain_id),
            WrongChainId {
                chain_id,
                tx_chain_id,
            }
        );

        ensure!(
            self.evm_backend.find_transaction_receipt(tx_hash).is_none(),
            DuplicateTx { tx_hash }
        );

        ensure!(
            nonce == state_account.nonce,
            NonceNotEqual {
                tx_nonce: nonce,
                state_nonce: state_account.nonce,
            }
        );

        ensure!(
            gas_price <= U256::from(u64::MAX),
            GasPriceOutOfBounds { gas_price }
        );

        ensure!(
            gas_limit <= U256::from(u64::MAX),
            GasLimitOutOfBounds { gas_limit }
        );

        let max_fee = gas_limit * gas_price;
        ensure!(
            max_fee + value <= state_account.balance,
            CantPayTheBills {
                value,
                max_fee,
                state_balance: state_account.balance,
            }
        );

        let config = self.config.to_evm_params();
        let transaction_context = TransactionContext::new(gas_price.as_u64(), caller);
        let execution_context = ExecutorContext::new(
            &mut self.evm_backend,
            self.chain_context,
            transaction_context,
            self.config,
        );

        let block_gas_limit_left = execution_context.gas_left();
        let metadata = StackSubstateMetadata::new(block_gas_limit_left, &config);
        let state = MemoryStackState::new(metadata, &execution_context);
        let mut executor = StackExecutor::new_with_precompile(state, &config, &mut precompiles);
        let (exit_reason, exit_data) = match action {
            TransactionAction::Call(addr) => {
                debug!(
                    "TransactionAction::Call caller  = {}, to = {}.",
                    caller, addr
                );
                executor.transact_call(caller, addr, value, input, gas_limit.as_u64())
            }
            TransactionAction::Create => {
                let addr = TransactionAction::Create.address(caller, nonce);
                debug!(
                    "TransactionAction::Create caller  = {}, to = {:?}.",
                    caller, addr
                );
                (
                    executor.transact_create(caller, value, input, gas_limit.as_u64()),
                    vec![],
                )
            }
        };
        let used_gas = executor.used_gas();
        let fee = executor.fee(gas_price);
        let mut executor_state = executor.into_state();

        let burn_fee = matches!(exit_reason, ExitReason::Succeed(_));
        if burn_fee {
            // Burn the fee, if transaction executed correctly
            executor_state
                .withdraw(caller, fee)
                .map_err(|_| Error::CantPayTheBills {
                    value,
                    max_fee: fee,
                    state_balance: state_account.balance,
                })?;
        }
        // This was assert before, but at some point evm executor waste more gas than exist (on solidty assert opcode).
        ensure!(
            used_gas < block_gas_limit_left,
            GasUsedOutOfBounds {
                used_gas,
                gas_limit: block_gas_limit_left
            }
        );
        let (updates, logs) = executor_state.deconstruct();

        let tx_logs: Vec<_> = logs.into_iter().collect();
        execution_context.apply(updates, used_gas);

        Ok(ExecutionResult {
            exit_reason,
            exit_data,
            used_gas,
            tx_logs,
            tx_id: tx_hash,
        })
    }

    /// Perform transaction execution without verify signature.
    pub fn transaction_execute_unsinged<F>(
        &mut self,
        caller: H160,
        tx: UnsignedTransaction,
        calculate_tx_hash_with_caller: bool,
        precompiles: F,
    ) -> Result<ExecutionResult, Error>
    where
        F: FnMut(H160, &[u8], Option<u64>, &Context) -> Option<PrecompileCallResult>,
    {
        let chain_id = self.config.chain_id;

        let unsigned_tx = UnsignedTransactionWithCaller {
            unsigned_tx: tx.clone(),
            caller,
            chain_id,
            signed_compatible: calculate_tx_hash_with_caller,
        };
        let tx_hash = unsigned_tx.tx_id_hash();
        let result = self.transaction_execute_raw(
            caller,
            tx.nonce,
            tx.gas_price,
            tx.gas_limit,
            tx.action,
            tx.input.clone(),
            tx.value,
            Some(chain_id),
            tx_hash,
            precompiles,
        )?;

        self.register_tx_with_receipt(TransactionInReceipt::Unsigned(unsigned_tx), result.clone());
        Ok(result)
    }

    pub fn transaction_execute<F>(
        &mut self,
        evm_tx: Transaction,
        precompiles: F,
    ) -> Result<ExecutionResult, Error>
    where
        F: FnMut(H160, &[u8], Option<u64>, &Context) -> Option<PrecompileCallResult>,
    {
        let caller = evm_tx.caller()?; // This method verify signature.

        let nonce = evm_tx.nonce;
        let gas_price = evm_tx.gas_price;
        let gas_limit = evm_tx.gas_limit;
        let action = evm_tx.action;
        let input = evm_tx.input.clone();
        let value = evm_tx.value;

        let tx_hash = evm_tx.tx_id_hash();
        let result = self.transaction_execute_raw(
            caller,
            nonce,
            gas_price,
            gas_limit,
            action,
            input,
            value,
            evm_tx.signature.chain_id(),
            tx_hash,
            precompiles,
        )?;

        self.register_tx_with_receipt(TransactionInReceipt::Signed(evm_tx), result.clone());

        Ok(result)
    }

    /// Do lowlevel operation with executor, without storing transaction into logs.
    /// Usefull for testing and transfering tokens from evm to solana and back.
    // Used for:
    // 1. deposit
    // 2. withdrawal? - currently unused
    // 3. executing transaction without commit
    pub fn with_executor<'a, F, U, P>(&'a mut self, mut precompiles: P, func: F) -> U
    where
        F: for<'r> FnOnce(
            &mut StackExecutor<'r, 'r, MemoryStackState<'r, 'r, ExecutorContext<'a, Incomming>>>,
        ) -> U,

        P: FnMut(H160, &[u8], Option<u64>, &Context) -> Option<PrecompileCallResult>,
    {
        let transaction_context = TransactionContext::default();
        let config = self.config.to_evm_params();
        let execution_context = ExecutorContext::new(
            &mut self.evm_backend,
            self.chain_context,
            transaction_context,
            self.config,
        );

        let gas_limit = execution_context.gas_left();
        let metadata = StackSubstateMetadata::new(gas_limit, &config);
        let state = MemoryStackState::new(metadata, &execution_context);
        let mut executor = StackExecutor::new_with_precompile(state, &config, &mut precompiles);
        let result = func(&mut executor);
        let used_gas = executor.used_gas();
        let (updates, _logs) = executor.into_state().deconstruct();

        execution_context.apply(updates, used_gas);

        result
    }

    // TODO: Handle duplicates, statuses.
    fn register_tx_with_receipt(&mut self, tx: TransactionInReceipt, result: ExecutionResult) {
        let tx_hash = match &tx {
            TransactionInReceipt::Signed(tx) => tx.tx_id_hash(),
            TransactionInReceipt::Unsigned(tx) => tx.tx_id_hash(),
        };

        debug!(
            "Register tx = {} in EVM block = {}",
            tx_hash,
            self.evm_backend.block_number()
        );

        let tx_hashes = self.evm_backend.get_executed_transactions();

        assert!(!tx_hashes.contains(&tx_hash));

        let receipt = TransactionReceipt::new(
            tx,
            result.used_gas,
            self.evm_backend.block_number(),
            tx_hashes.len() as u64 + 1,
            result.tx_logs,
            (result.exit_reason, result.exit_data),
        );

        self.evm_backend.push_transaction_receipt(tx_hash, receipt);
    }

    /// Mint evm tokens to some address.
    ///
    /// Internally just mint token, and create system transaction (not implemented):
    /// 1. Type: Call
    /// 2. from: EVM_MINT_ADDRESS
    /// 3. to: recipient (some address specified by method caller)
    /// 4. data: empty,
    /// 5. value: amount (specified by method caller)
    ///
    pub fn deposit(&mut self, recipient: H160, amount: U256) {
        self.with_executor(
            |_, _, _, _| None,
            |e| e.state_mut().deposit(recipient, amount),
        );
    }

    pub fn register_swap_tx_in_evm(
        &mut self,
        mint_address: H160,
        recipient: H160,
        amount: U256,
        signed_compatible: bool,
    ) {
        let nonce = self.with_executor(
            |_, _, _, _| None,
            |e| {
                let nonce = e.nonce(mint_address);
                e.state_mut().inc_nonce(mint_address);
                nonce
            },
        );
        let tx = UnsignedTransaction {
            nonce,
            gas_limit: 0.into(),
            gas_price: 0.into(),
            value: amount,
            input: Vec::new(),
            action: TransactionAction::Call(recipient),
        };
        let unsigned_tx = UnsignedTransactionWithCaller {
            unsigned_tx: tx,
            caller: mint_address,
            chain_id: self.config.chain_id,
            signed_compatible,
        };
        let result = ExecutionResult {
            tx_logs: Vec::new(),
            used_gas: 0,
            exit_data: Vec::new(),
            exit_reason: ExitReason::Succeed(ExitSucceed::Returned),
            tx_id: unsigned_tx.tx_id_hash(),
        };
        self.register_tx_with_receipt(TransactionInReceipt::Unsigned(unsigned_tx), result)
    }

    /// After "swap from evm" transaction EVM_MINT_ADDRESS will cleanup. Using this method.
    pub fn reset_balance(&mut self, balance: H160) {
        self.with_executor(|_, _, _, _| None, |e| e.state_mut().reset_balance(balance));
    }

    //  /// Burn some tokens on address:
    //  ///
    //  ///
    //  /// Internally just burn address, and create system transaction (not implemented):
    //  /// 1. Type: Call
    //  /// 2. from: from (some address specified by method caller)
    //  /// 3. to: EVM_MINT_ADDRESS
    //  /// 4. data: empty,
    //  /// 5. value: amount (specified by method caller)
    //  ///
    //  /// Note: This operation is failable, and can return error in case, when user has no enough tokens on his account.
    // pub fn burn(&mut self, from: H160, amount: U256) -> ExecutionResult {
    //     match self.with_executor(|e| e.state_mut().withdraw(evm_address, gweis)) {
    //         Ok(_) => {},
    //         Err(e) => return ExecutionResult {
    //             exit_reason: ExitReason::Error(e), // Error - should be rollbacked.
    //             exit_data: vec![],
    //             used_gas: 0,
    //             tx_logs: vec![]
    //         }
    //     }

    //     let unsigned_tx = UnsignedTransactionWithCaller {
    //         unsigned_tx: tx,
    //         caller,
    //         chain_id,
    //     };

    //     self.register_tx_with_receipt(TransactionInReceipt::Unsigned(unsigned_tx), result.clone());

    // }

    pub fn get_tx_receipt_by_hash(&mut self, tx: H256) -> Option<&TransactionReceipt> {
        self.evm_backend.find_transaction_receipt(tx)
    }

    pub fn deconstruct(self) -> EvmBackend<Incomming> {
        self.evm_backend
    }
}

// TODO: move out these blobs to test files
pub const HELLO_WORLD_CODE:&str = "608060405234801561001057600080fd5b5061011e806100206000396000f3fe6080604052348015600f57600080fd5b506004361060285760003560e01c8063942ae0a714602d575b600080fd5b603360ab565b6040518080602001828103825283818151815260200191508051906020019080838360005b8381101560715780820151818401526020810190506058565b50505050905090810190601f168015609d5780820380516001836020036101000a031916815260200191505b509250505060405180910390f35b60606040518060400160405280600a81526020017f68656c6c6f576f726c640000000000000000000000000000000000000000000081525090509056fea2646970667358221220fa787b95ca91ffe90fdb780b8ee8cb11c474bc63cb8217112c88bc465f7ea7d364736f6c63430007020033";
pub const HELLO_WORLD_ABI: &str = "942ae0a7";
pub const HELLO_WORLD_RESULT:&str = "0000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000a68656c6c6f576f726c6400000000000000000000000000000000000000000000";
pub const HELLO_WORLD_CODE_SAVED:&str = "6080604052348015600f57600080fd5b506004361060285760003560e01c8063942ae0a714602d575b600080fd5b603360ab565b6040518080602001828103825283818151815260200191508051906020019080838360005b8381101560715780820151818401526020810190506058565b50505050905090810190601f168015609d5780820380516001836020036101000a031916815260200191505b509250505060405180910390f35b60606040518060400160405280600a81526020017f68656c6c6f576f726c640000000000000000000000000000000000000000000081525090509056fea2646970667358221220fa787b95ca91ffe90fdb780b8ee8cb11c474bc63cb8217112c88bc465f7ea7d364736f6c63430007020033";

#[cfg(test)]
mod tests {
    use evm::{Capture, CreateScheme, ExitReason, ExitSucceed, Handler};
    use primitive_types::{H160, H256, U256};
    use sha3::{Digest, Keccak256};

    use super::{
        ExecutionResult, Executor, HELLO_WORLD_ABI, HELLO_WORLD_CODE, HELLO_WORLD_CODE_SAVED,
        HELLO_WORLD_RESULT,
    };
    use crate::context::EvmConfig;
    use crate::*;
    use error::*;

    #[allow(clippy::type_complexity)]
    fn noop_precompile(
        _: H160,
        _: &[u8],
        _: Option<u64>,
        _: &Context,
    ) -> Option<Result<(ExitSucceed, Vec<u8>, u64), ExitError>> {
        None
    }

    fn name_to_key(name: &str) -> H160 {
        let hash = H256::from_slice(Keccak256::digest(name.as_bytes()).as_slice());
        hash.into()
    }

    const METACOIN_CODE: &str = include_str!("../tests/MetaCoin.bin");
    const INITIAL_BALANCE: u64 = 100_000;

    #[derive(Clone)]
    struct Persona {
        nonce: u64,
        secret: secp256k1::key::SecretKey,
    }

    impl Persona {
        fn new() -> Self {
            let mut rng = secp256k1::rand::thread_rng();
            let secret = secp256k1::key::SecretKey::new(&mut rng);
            let nonce = 0;
            Self { nonce, secret }
        }

        fn address(&self) -> Address {
            self.secret.to_address()
        }

        fn unsigned(
            &self,
            action: TransactionAction,
            bytes: impl AsRef<[u8]>,
        ) -> UnsignedTransaction {
            UnsignedTransaction {
                nonce: self.nonce.into(),
                gas_price: U256::zero(),
                gas_limit: U256::from(u64::MAX),
                action,
                value: U256::zero(),
                input: bytes.as_ref().to_vec(),
            }
        }

        // tx_create
        fn create(&self, bytes: impl AsRef<[u8]>) -> Transaction {
            self.unsigned(TransactionAction::Create, bytes)
                .sign(&self.secret, Some(TEST_CHAIN_ID))
        }

        // tx_call
        fn call(&self, address: Address, bytes: impl AsRef<[u8]>) -> Transaction {
            self.unsigned(TransactionAction::Call(address), bytes)
                .sign(&self.secret, Some(TEST_CHAIN_ID))
        }
    }

    mod metacoin {
        use ethabi::{Function, Param, ParamType};
        use once_cell::sync::Lazy;

        pub static GET_BALANCE: Lazy<Function> = Lazy::new(|| Function {
            name: "getBalance".to_string(),
            inputs: vec![Param {
                name: "addr".to_string(),
                kind: ParamType::Address,
            }],
            outputs: vec![Param {
                name: "".to_string(),
                kind: ParamType::Uint(256),
            }],
            constant: true,
        });

        pub static SEND_COIN: Lazy<Function> = Lazy::new(|| Function {
            name: "sendCoin".to_string(),
            inputs: vec![
                Param {
                    name: "receiver".to_string(),
                    kind: ParamType::Address,
                },
                Param {
                    name: "amount".to_string(),
                    kind: ParamType::Uint(256),
                },
            ],
            outputs: vec![Param {
                name: "sufficient".to_string(),
                kind: ParamType::Bool,
            }],
            constant: false,
        });
    }

    #[test]
    fn handle_duplicate_txs() {
        let _logger = simple_logger::SimpleLogger::new().init();

        let chain_id = 0xeba;
        let evm_config = EvmConfig {
            chain_id,
            ..EvmConfig::default()
        };
        let mut executor =
            Executor::with_config(EvmBackend::default(), Default::default(), evm_config);

        let code = hex::decode(METACOIN_CODE).unwrap();

        let alice = Persona::new();
        let create_tx = alice.unsigned(TransactionAction::Create, &code);

        let create_tx = create_tx.sign(&alice.secret, Some(chain_id));
        assert!(matches!(
            executor
                .transaction_execute(create_tx.clone(), noop_precompile)
                .unwrap()
                .exit_reason,
            ExitReason::Succeed(ExitSucceed::Returned)
        ));

        let hash = create_tx.tx_id_hash();
        assert!(matches!(
            executor
                .transaction_execute(create_tx, noop_precompile)
                .unwrap_err(),
            Error::DuplicateTx { tx_hash } if tx_hash == hash
        ));
    }

    #[test]
    fn handle_duplicate_txs_unsigned() {
        let _logger = simple_logger::SimpleLogger::new().init();

        let chain_id = 0xeba;
        let evm_config = EvmConfig {
            chain_id,
            ..EvmConfig::default()
        };
        let mut executor =
            Executor::with_config(EvmBackend::default(), Default::default(), evm_config);

        let code = hex::decode(METACOIN_CODE).unwrap();

        let alice = Persona::new();
        let create_tx = alice.unsigned(TransactionAction::Create, &code);

        assert!(matches!(
            executor
                .transaction_execute_unsinged(
                    alice.address(),
                    create_tx.clone(),
                    false,
                    noop_precompile
                )
                .unwrap()
                .exit_reason,
            ExitReason::Succeed(ExitSucceed::Returned)
        ));

        let hash = create_tx.signing_hash(Some(chain_id));
        assert!(matches!(
            executor
            .transaction_execute_unsinged(alice.address(), create_tx, false, noop_precompile)
                .unwrap_err(),
            Error::DuplicateTx { tx_hash } if tx_hash == hash
        ));
    }

    #[test]
    fn handle_duplicate_txs_unsigned_new_hash() {
        let _logger = simple_logger::SimpleLogger::new().init();

        let chain_id = 0xeba;
        let evm_config = EvmConfig {
            chain_id,
            ..EvmConfig::default()
        };
        let mut executor =
            Executor::with_config(EvmBackend::default(), Default::default(), evm_config);

        let code = hex::decode(METACOIN_CODE).unwrap();

        let alice = Persona::new();
        let create_tx = alice.unsigned(TransactionAction::Create, &code);

        let address = alice.address();
        assert_eq!(
            executor
                .transaction_execute_unsinged(address, create_tx.clone(), true, noop_precompile)
                .unwrap()
                .exit_reason,
            ExitReason::Succeed(ExitSucceed::Returned)
        );

        let create_tx_with_caller = UnsignedTransactionWithCaller {
            unsigned_tx: create_tx.clone(),
            caller: address,
            chain_id,
            signed_compatible: true,
        };
        let hash = create_tx_with_caller.tx_id_hash();
        println!("tx = {:?}", create_tx_with_caller);
        println!("hash = {}", hash);

        assert_eq!(
            executor
                .transaction_execute_unsinged(address, create_tx, true, noop_precompile)
                .unwrap_err(),
            Error::DuplicateTx { tx_hash: hash }
        );
    }

    #[test]
    fn it_execute_only_txs_with_correct_chain_id() {
        let _logger = simple_logger::SimpleLogger::new().init();

        let chain_id = 0xeba;
        let another_chain_id = 0xb0ba;
        let evm_config = EvmConfig {
            chain_id,
            ..EvmConfig::default()
        };
        let mut executor =
            Executor::with_config(EvmBackend::default(), Default::default(), evm_config);

        let code = hex::decode(METACOIN_CODE).unwrap();

        let alice = Persona::new();
        let create_tx = alice.unsigned(TransactionAction::Create, &code);

        let wrong_tx = create_tx.clone().sign(&alice.secret, None);
        assert!(matches!(
            dbg!(executor
                .transaction_execute(wrong_tx, noop_precompile)
                .unwrap_err()),
            Error::WrongChainId {
                chain_id: err_chain_id,
                tx_chain_id,
            } if (err_chain_id, tx_chain_id) == (chain_id, None)
        ));

        let wrong_tx = create_tx
            .clone()
            .sign(&alice.secret, Some(another_chain_id));
        assert!(matches!(
            executor
                .transaction_execute(wrong_tx, noop_precompile)
                .unwrap_err(),
            Error::WrongChainId {
                chain_id: err_chain_id,
                tx_chain_id,
            } if (err_chain_id, tx_chain_id) == (chain_id, Some(another_chain_id))
        ));

        let create_tx = create_tx.sign(&alice.secret, Some(chain_id));
        assert!(matches!(
            executor
                .transaction_execute(create_tx, noop_precompile)
                .unwrap()
                .exit_reason,
            ExitReason::Succeed(ExitSucceed::Returned)
        ));
    }

    #[test]
    fn it_handles_metacoin() {
        use ethabi::Token;

        let _logger = simple_logger::SimpleLogger::new().init();

        let code = hex::decode(METACOIN_CODE).unwrap();

        let mut executor = Executor::with_config(
            EvmBackend::default(),
            Default::default(),
            Default::default(),
        );

        let mut alice = Persona::new();
        let create_tx = alice.create(&code);
        let contract = create_tx.address().unwrap();

        assert!(matches!(
            executor
                .transaction_execute(create_tx, noop_precompile)
                .unwrap()
                .exit_reason,
            ExitReason::Succeed(ExitSucceed::Returned)
        ));

        alice.nonce += 1;

        let call_tx = alice.call(
            contract,
            &metacoin::GET_BALANCE
                .encode_input(&[Token::Address(alice.address())])
                .unwrap(),
        );

        let ExecutionResult {
            exit_reason,
            exit_data: bytes,
            ..
        } = executor
            .transaction_execute(call_tx, noop_precompile)
            .unwrap();

        assert_eq!(exit_reason, ExitReason::Succeed(ExitSucceed::Returned));
        assert_eq!(
            metacoin::GET_BALANCE.decode_output(&bytes).unwrap(),
            vec![Token::Uint(U256::from(INITIAL_BALANCE))]
        );

        alice.nonce += 1;

        let mut bob = Persona::new();

        // Alice sends coin to Bob

        let send_tx = alice.call(
            contract,
            &metacoin::SEND_COIN
                .encode_input(&[
                    Token::Address(bob.address()),
                    Token::Uint(U256::from(INITIAL_BALANCE / 4)),
                ])
                .unwrap(),
        );

        let ExecutionResult {
            exit_reason,
            exit_data: bytes,
            ..
        } = executor
            .transaction_execute(send_tx, noop_precompile)
            .unwrap();
        assert_eq!(exit_reason, ExitReason::Succeed(ExitSucceed::Returned));
        assert_eq!(
            metacoin::SEND_COIN.decode_output(&bytes).unwrap(),
            vec![Token::Bool(true)]
        );

        alice.nonce += 1;

        // Alice checks Bob balance

        let call_tx = alice.call(
            contract,
            &metacoin::GET_BALANCE
                .encode_input(&[Token::Address(bob.address())])
                .unwrap(),
        );

        let ExecutionResult {
            exit_reason,
            exit_data: bytes,
            ..
        } = executor
            .transaction_execute(call_tx, noop_precompile)
            .unwrap();
        assert_eq!(exit_reason, ExitReason::Succeed(ExitSucceed::Returned));
        assert_eq!(
            metacoin::GET_BALANCE.decode_output(&bytes).unwrap(),
            vec![Token::Uint(U256::from(INITIAL_BALANCE / 4))]
        );

        alice.nonce += 1;

        // Bob checks Alice balance

        let call_tx = bob.call(
            contract,
            &metacoin::GET_BALANCE
                .encode_input(&[Token::Address(alice.address())])
                .unwrap(),
        );

        let ExecutionResult {
            exit_reason,
            exit_data: bytes,
            ..
        } = executor
            .transaction_execute(call_tx, noop_precompile)
            .unwrap();
        assert_eq!(exit_reason, ExitReason::Succeed(ExitSucceed::Returned));
        assert_eq!(
            metacoin::GET_BALANCE.decode_output(&bytes).unwrap(),
            vec![Token::Uint(U256::from(INITIAL_BALANCE * 3 / 4))]
        );

        bob.nonce += 1;

        let state = executor.deconstruct();

        let committed = state.commit_block(0, Default::default());
        // In this realm Bob returns coins to Alice
        {
            let mut alice = alice.clone();
            let mut bob = bob.clone();

            let state = committed.next_incomming(0);
            let mut executor = Executor::with_config(state, Default::default(), Default::default());

            let send_tx = bob.call(
                contract,
                &metacoin::SEND_COIN
                    .encode_input(&[
                        Token::Address(alice.address()),
                        Token::Uint(U256::from(INITIAL_BALANCE / 4)),
                    ])
                    .unwrap(),
            );

            let ExecutionResult {
                exit_reason,
                exit_data: bytes,
                ..
            } = executor
                .transaction_execute(send_tx, noop_precompile)
                .unwrap();
            assert_eq!(exit_reason, ExitReason::Succeed(ExitSucceed::Returned));
            assert_eq!(
                metacoin::SEND_COIN.decode_output(&bytes).unwrap(),
                vec![Token::Bool(true)]
            );

            bob.nonce += 1;

            // Alice check self balance

            let call_tx = alice.call(
                contract,
                &metacoin::GET_BALANCE
                    .encode_input(&[Token::Address(alice.address())])
                    .unwrap(),
            );

            let ExecutionResult {
                exit_reason,
                exit_data: bytes,
                ..
            } = executor
                .transaction_execute(call_tx, noop_precompile)
                .unwrap();
            assert_eq!(exit_reason, ExitReason::Succeed(ExitSucceed::Returned));
            assert_eq!(
                metacoin::GET_BALANCE.decode_output(&bytes).unwrap(),
                vec![Token::Uint(U256::from(INITIAL_BALANCE))]
            );

            alice.nonce += 1;

            // Alice checks Bob balance

            let call_tx = alice.call(
                contract,
                &metacoin::GET_BALANCE
                    .encode_input(&[Token::Address(bob.address())])
                    .unwrap(),
            );

            let ExecutionResult {
                exit_reason,
                exit_data: bytes,
                ..
            } = executor
                .transaction_execute(call_tx, noop_precompile)
                .unwrap();
            assert_eq!(exit_reason, ExitReason::Succeed(ExitSucceed::Returned));
            assert_eq!(
                metacoin::GET_BALANCE.decode_output(&bytes).unwrap(),
                vec![Token::Uint(U256::zero())]
            );
        }

        // In this realm Alice sends all coins to Bob
        {
            // NOTE: ensure blockss are different
            let state = committed.next_incomming(0);
            let mut executor = Executor::with_config(state, Default::default(), Default::default());

            let send_tx = alice.call(
                contract,
                &metacoin::SEND_COIN
                    .encode_input(&[
                        Token::Address(bob.address()),
                        Token::Uint(U256::from(INITIAL_BALANCE * 3 / 4)),
                    ])
                    .unwrap(),
            );

            let ExecutionResult {
                exit_reason,
                exit_data: bytes,
                ..
            } = executor
                .transaction_execute(send_tx, noop_precompile)
                .unwrap();
            assert_eq!(exit_reason, ExitReason::Succeed(ExitSucceed::Returned));
            assert_eq!(
                metacoin::SEND_COIN.decode_output(&bytes).unwrap(),
                vec![Token::Bool(true)]
            );

            alice.nonce += 1;

            // Alice check self balance

            let call_tx = alice.call(
                contract,
                &metacoin::GET_BALANCE
                    .encode_input(&[Token::Address(alice.address())])
                    .unwrap(),
            );

            let ExecutionResult {
                exit_reason,
                exit_data: bytes,
                ..
            } = executor
                .transaction_execute(call_tx, noop_precompile)
                .unwrap();
            assert_eq!(exit_reason, ExitReason::Succeed(ExitSucceed::Returned));
            assert_eq!(
                metacoin::GET_BALANCE.decode_output(&bytes).unwrap(),
                vec![Token::Uint(U256::zero())]
            );

            alice.nonce += 1;

            // Alice checks Bob balance

            let call_tx = alice.call(
                contract,
                &metacoin::GET_BALANCE
                    .encode_input(&[Token::Address(bob.address())])
                    .unwrap(),
            );

            let ExecutionResult {
                exit_reason,
                exit_data: bytes,
                ..
            } = executor
                .transaction_execute(call_tx, noop_precompile)
                .unwrap();
            assert_eq!(exit_reason, ExitReason::Succeed(ExitSucceed::Returned));
            assert_eq!(
                metacoin::GET_BALANCE.decode_output(&bytes).unwrap(),
                vec![Token::Uint(U256::from(INITIAL_BALANCE))]
            );
        }
    }

    #[test]
    fn test_evm_bytecode() {
        let _logger_error = simple_logger::SimpleLogger::new().init();

        let code = hex::decode(HELLO_WORLD_CODE).unwrap();
        let data = hex::decode(HELLO_WORLD_ABI).unwrap();

        let mut executor = Executor::with_config(
            EvmBackend::default(),
            Default::default(),
            Default::default(),
        );

        let exit_reason = match executor.with_executor(noop_precompile, |e| {
            e.create(
                name_to_key("caller"),
                CreateScheme::Fixed(name_to_key("contract")),
                U256::zero(),
                code,
                None,
            )
        }) {
            Capture::Exit((s, _, v)) => (s, v),
            Capture::Trap(_) => unreachable!(),
        };

        assert!(matches!(
            exit_reason,
            (ExitReason::Succeed(ExitSucceed::Returned), _)
        ));

        let exit_reason = executor.with_executor(noop_precompile, |e| {
            e.transact_call(
                name_to_key("caller"),
                name_to_key("contract"),
                U256::zero(),
                data.to_vec(),
                300000,
            )
        });

        let result = hex::decode(HELLO_WORLD_RESULT).unwrap();
        match exit_reason {
            (ExitReason::Succeed(ExitSucceed::Returned), res) if res == result => {}
            any_other => panic!("Not expected result={:?}", any_other),
        }

        let state = executor.deconstruct();

        let contract_before = Vec::<u8>::from(
            state
                .get_account_state(name_to_key("contract"))
                .map(|acc| acc.code)
                .unwrap(),
        );
        assert_eq!(
            &contract_before,
            &hex::decode(HELLO_WORLD_CODE_SAVED).unwrap()
        );

        // ensure that after commit state remain the same
        let committed = state.commit_block(0, Default::default());
        let contract = Vec::<u8>::from(
            committed
                .get_account_state(name_to_key("contract"))
                .map(|acc| acc.code)
                .unwrap(),
        );

        assert_eq!(&contract, &hex::decode(HELLO_WORLD_CODE_SAVED).unwrap());
    }
}
