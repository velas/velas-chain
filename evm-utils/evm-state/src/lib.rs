use evm::executor::{MemoryStackState, StackSubstateMetadata};
pub use evm::{
    backend::{Apply, ApplyBackend, Backend, Log, MemoryVicinity},
    executor::StackExecutor,
    Config, Context, Handler, Transfer,
    {ExitError, ExitFatal, ExitReason, ExitRevert, ExitSucceed},
};

pub use primitive_types::{H256, U256};
pub use secp256k1::rand;
use snafu::ensure;

pub mod error;
pub mod transactions;
pub mod types;

pub use transactions::*;
pub use types::*;
pub use {evm_backend::EvmBackend, layered_backend::EvmState, storage::Storage};

pub use triedb::empty_trie_hash;

mod evm_backend;
mod layered_backend;
mod storage;

use error::*;
use log::*;

use std::fmt;

pub const MAX_TX_LEN: u64 = 3 * 1024 * 1024; // Limit size to 3 MB
pub const TX_MTU: usize = 908;
pub const CHAIN_ID: u64 = 0x77;

/// Exit result, if succeed, returns `ExitSucceed` - info about execution, Vec<u8> - output data, u64 - gas cost
pub type PrecompileCallResult = Result<(ExitSucceed, Vec<u8>, u64), ExitError>;

pub trait FromKey {
    fn to_public_key(&self) -> secp256k1::PublicKey;
    fn to_address(&self) -> crate::Address;
}

impl FromKey for secp256k1::SecretKey {
    fn to_public_key(&self) -> secp256k1::PublicKey {
        secp256k1::PublicKey::from_secret_key(&secp256k1::SECP256K1, self)
    }
    fn to_address(&self) -> crate::Address {
        addr_from_public_key(&secp256k1::PublicKey::from_secret_key(
            &secp256k1::SECP256K1,
            self,
        ))
    }
}

pub struct Executor {
    evm: EvmBackend,
    config: Config,
    used_gas: u64,
}

impl fmt::Debug for Executor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Executor")
            .field("config", &self.config)
            .finish()
    }
}

impl Executor {
    pub fn with_config(
        state: EvmState,
        config: Config,
        gas_limit: u64,
        chain_id: u64,
        block_number: u64,
    ) -> Self {
        let vicinity = MemoryVicinity {
            chain_id: chain_id.into(),
            block_gas_limit: gas_limit.into(),
            block_number: block_number.into(),
            ..default_vicinity()
        };

        assert_eq!(
            state.slot as u64, block_number,
            "Fork state before execute on them"
        );

        Executor {
            evm: EvmBackend::new_from_state(state, vicinity),
            config,
            used_gas: 0,
        }
    }
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
        mut precompiles: F,
    ) -> Result<
        (
            (evm::ExitReason, Vec<u8>),
            u64,
            impl IntoIterator<Item = Log>,
        ),
        Error,
    >
    where
        F: FnMut(H160, &[u8], Option<u64>, &Context) -> Option<PrecompileCallResult>,
    {
        let state_nonce = self.evm.basic(caller).nonce;
        ensure!(
            nonce == state_nonce,
            NonceNotEqual {
                tx_nonce: nonce,
                state_nonce,
            }
        );

        let chain_id = self.evm.chain_id().as_u64();

        ensure!(
            tx_chain_id == Some(chain_id),
            WrongChainId {
                chain_id,
                tx_chain_id,
            }
        );

        self.evm.tx_info.origin = caller;
        self.evm.tx_info.gas_price = gas_price;

        let block_gas_limit_left = self.evm.block_gas_limit().as_u64() - self.used_gas;
        let metadata = StackSubstateMetadata::new(block_gas_limit_left, &self.config);
        let state = MemoryStackState::new(metadata, &self.evm);
        let mut executor =
            StackExecutor::new_with_precompile(state, &self.config, &mut precompiles);
        let result = match action {
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

        assert!(used_gas + self.used_gas <= self.evm.tx_info.block_gas_limit.as_u64());
        let (updates, logs) = executor.into_state().deconstruct();

        self.evm.apply(updates, false);

        self.used_gas += used_gas;

        Ok((result, used_gas, logs))
    }

    /// Perform transaction execution without verify signature.
    pub fn transaction_execute_unsinged<F>(
        &mut self,
        caller: H160,
        tx: UnsignedTransaction,
        precompiles: F,
    ) -> Result<(evm::ExitReason, Vec<u8>), Error>
    where
        F: FnMut(H160, &[u8], Option<u64>, &Context) -> Option<PrecompileCallResult>,
    {
        // TODO use u64 for chain_id
        let chain_id = Some(self.evm.chain_id().as_u64());
        let (result, used_gas, logs) = self.transaction_execute_raw(
            caller,
            tx.nonce,
            tx.gas_price,
            tx.gas_limit,
            tx.action,
            tx.input.clone(),
            tx.value,
            chain_id,
            precompiles,
        )?;
        let unsigned_tx = UnsignedTransactionWithCaller {
            unsigned_tx: tx,
            caller,
            chain_id: chain_id,
        };

        self.register_tx_with_receipt(
            TransactionInReceipt::Unsigned(unsigned_tx),
            used_gas.into(),
            result.clone(),
            logs,
        );
        Ok(result)
    }

    pub fn transaction_execute<F>(
        &mut self,
        evm_tx: Transaction,
        precompiles: F,
    ) -> Result<(evm::ExitReason, Vec<u8>), Error>
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

        let (result, used_gas, logs) = self.transaction_execute_raw(
            caller,
            nonce,
            gas_price,
            gas_limit,
            action,
            input,
            value,
            evm_tx.signature.chain_id(),
            precompiles,
        )?;
        self.register_tx_with_receipt(
            TransactionInReceipt::Signed(evm_tx),
            used_gas.into(),
            result.clone(),
            logs,
        );

        Ok(result)
    }

    /// Do lowlevel operation with executor, without storing transaction into logs.
    /// Usefull for testing and transfering tokens from evm to solana and back.
    pub fn with_executor<F, U>(&mut self, func: F) -> U
    where
        F: for<'a> FnOnce(&mut StackExecutor<'a, 'a, MemoryStackState<'a, 'a, EvmBackend>>) -> U,
    {
        let ((updates, _logs), result) = {
            let gas_limit = self.evm.block_gas_limit().as_u64() - self.used_gas;
            let metadata = StackSubstateMetadata::new(gas_limit, &self.config);
            let state = MemoryStackState::new(metadata, &self.evm);
            let mut executor = StackExecutor::new(state, &self.config);
            let result = func(&mut executor);
            // let used_gas = executor.used_gas();
            let state = executor.into_state();
            (state.deconstruct(), result)
        };
        self.evm.apply(updates, false);
        result
    }

    pub fn used_gas(&self) -> u64 {
        self.used_gas
    }

    // TODO: Handle duplicates, statuses.
    fn register_tx_with_receipt(
        &mut self,
        tx: TransactionInReceipt,
        used_gas: U256,
        result: (evm::ExitReason, Vec<u8>),
        logs: impl IntoIterator<Item = Log>,
    ) {
        let block_num = self.evm.tx_info.block_number.as_u64();
        let tx_hash = match &tx {
            TransactionInReceipt::Signed(tx) => tx.signing_hash(),
            TransactionInReceipt::Unsigned(tx) => tx.unsigned_tx.signing_hash(Some(CHAIN_ID)),
        };

        assert_eq!(block_num, self.evm.evm_state.slot);

        debug!("Register tx = {} in EVM block = {}", tx_hash, block_num);

        let tx_hashes = self
            .evm
            .evm_state
            .get_transactions_in_block(block_num)
            .expect("The block must be the same as in state and contains some transactions");

        assert!(!tx_hashes.contains(&tx_hash));

        let receipt = TransactionReceipt::new(
            tx,
            used_gas,
            block_num,
            tx_hashes.len() as u64 + 1,
            logs.into_iter().collect(),
            result,
        );

        self.evm.evm_state.set_transaction_receipt(tx_hash, receipt);
    }

    pub fn get_tx_receipt_by_hash(&mut self, tx: H256) -> Option<TransactionReceipt> {
        self.evm.evm_state.get_transaction_receipt(tx)
    }

    pub fn deconstruct(self) -> EvmState {
        self.evm.evm_state
    }
}

// TODO: mark as test only,
//  there is only one place where MemoryVicinity instantiates
pub(crate) fn default_vicinity() -> MemoryVicinity {
    MemoryVicinity {
        gas_price: U256::zero(),
        origin: H160::default(),
        chain_id: U256::zero(),
        block_hashes: Vec::new(),
        block_number: U256::zero(),
        block_coinbase: H160::default(),
        block_timestamp: U256::zero(),
        block_difficulty: U256::zero(),
        block_gas_limit: U256::max_value(),
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

    use super::Executor;
    use super::*;

    // NOTE: value must not overflow i32::MAX at least
    static TEST_CHAIN_ID: u64 = 0x42;

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
    fn it_execute_only_txs_with_correct_chain_id() {
        let _logger = simple_logger::SimpleLogger::new().init();

        let chain_id = 0xeba;
        let another_chain_id = 0xb0ba;

        let mut executor = Executor::with_config(
            EvmState::default(),
            evm::Config::istanbul(),
            u64::MAX,
            chain_id,
            0,
        );

        let code = hex::decode(METACOIN_CODE).unwrap();

        let alice = Persona::new();
        let create_tx = alice.unsigned(TransactionAction::Create, &code);

        let wrong_tx = create_tx.clone().sign(&alice.secret, None);
        assert!(matches!(
            executor
                .transaction_execute(wrong_tx, noop_precompile)
                .unwrap_err(),
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
                .unwrap(),
            (ExitReason::Succeed(ExitSucceed::Returned), _)
        ));
    }

    #[test]
    fn it_handles_metacoin() {
        use ethabi::Token;

        let _logger = simple_logger::SimpleLogger::new().init();

        let code = hex::decode(METACOIN_CODE).unwrap();

        let mut executor = Executor::with_config(
            EvmState::default(),
            evm::Config::istanbul(),
            u64::MAX,
            TEST_CHAIN_ID,
            0,
        );

        let mut alice = Persona::new();
        let create_tx = alice.create(&code);
        let contract = create_tx.address().unwrap();

        assert!(matches!(
            executor
                .transaction_execute(create_tx, noop_precompile)
                .unwrap(),
            (ExitReason::Succeed(ExitSucceed::Returned), _)
        ));

        alice.nonce += 1;

        let call_tx = alice.call(
            contract,
            &metacoin::GET_BALANCE
                .encode_input(&[Token::Address(alice.address())])
                .unwrap(),
        );

        let (exit_reason, bytes) = executor
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

        let (exit_reason, bytes) = executor
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

        let (exit_reason, bytes) = executor
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

        let (exit_reason, bytes) = executor
            .transaction_execute(call_tx, noop_precompile)
            .unwrap();
        assert_eq!(exit_reason, ExitReason::Succeed(ExitSucceed::Returned));
        assert_eq!(
            metacoin::GET_BALANCE.decode_output(&bytes).unwrap(),
            vec![Token::Uint(U256::from(INITIAL_BALANCE * 3 / 4))]
        );

        bob.nonce += 1;

        let mut state = executor.deconstruct();
        state.commit();

        // In this realm Bob returns coins to Alice
        {
            let mut alice = alice.clone();
            let mut bob = bob.clone();

            let new_slot = state.slot + 1;
            let state = state.fork(new_slot);
            let mut executor = Executor::with_config(
                state,
                evm::Config::istanbul(),
                u64::MAX,
                TEST_CHAIN_ID,
                new_slot,
            );

            let send_tx = bob.call(
                contract,
                &metacoin::SEND_COIN
                    .encode_input(&[
                        Token::Address(alice.address()),
                        Token::Uint(U256::from(INITIAL_BALANCE / 4)),
                    ])
                    .unwrap(),
            );

            let (exit_reason, bytes) = executor
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

            let (exit_reason, bytes) = executor
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

            let (exit_reason, bytes) = executor
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
            // NOTE: ensure slots are different
            let new_slot = state.slot + 2;
            let state = state.fork(new_slot);
            let mut executor = Executor::with_config(
                state,
                evm::Config::istanbul(),
                u64::MAX,
                TEST_CHAIN_ID,
                new_slot,
            );

            let send_tx = alice.call(
                contract,
                &metacoin::SEND_COIN
                    .encode_input(&[
                        Token::Address(bob.address()),
                        Token::Uint(U256::from(INITIAL_BALANCE * 3 / 4)),
                    ])
                    .unwrap(),
            );

            let (exit_reason, bytes) = executor
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

            let (exit_reason, bytes) = executor
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

            let (exit_reason, bytes) = executor
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
            EvmState::default(),
            evm::Config::istanbul(),
            u64::MAX,
            TEST_CHAIN_ID,
            0,
        );

        let exit_reason = match executor.with_executor(|e| {
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

        let exit_reason = executor.with_executor(|e| {
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

        let mut state = executor.deconstruct();
        state.commit();

        let contract = Vec::<u8>::from(
            state
                .get_account_state(name_to_key("contract"))
                .map(|acc| acc.code)
                .unwrap(),
        );

        assert_eq!(&contract, &hex::decode(HELLO_WORLD_CODE_SAVED).unwrap());
    }
}
