use {
    crate::{
        context::{ChainContext, EvmConfig, ExecutorContext, TransactionContext},
        error::*,
        state::{AccountProvider, EvmBackend, Incomming},
        transactions::{
            Transaction, TransactionAction, TransactionInReceipt, TransactionReceipt,
            UnsignedTransaction, UnsignedTransactionWithCaller,
        },
        types::H160,
        BlockVersion, CallScheme,
    },
    log::*,
    snafu::ensure,
    std::{collections::BTreeMap, fmt},
};
pub use {
    evm::{
        backend::{Apply, ApplyBackend, Backend, Log, MemoryAccount, MemoryVicinity},
        executor::{
            stack::{
                MemoryStackState, Precompile, PrecompileFailure, PrecompileOutput,
                PrecompileResult, StackExecutor, StackState, StackSubstateMetadata,
            },
            traces::*,
        },
        Config, Context, ExitError, ExitFatal, ExitReason, ExitRevert, ExitSucceed, Handler,
        Transfer,
    },
    primitive_types::{H256, U256},
    secp256k1::rand,
    triedb::empty_trie_hash,
};

pub const MAX_TX_LEN: u64 = 3 * 1024 * 1024; // Limit size to 3 MB
pub const TX_MTU: usize = 908;

// NOTE: value must not overflow i32::MAX at least
pub const TEST_CHAIN_ID: u64 = 0xDEAD;

/// Exit result, if succeed, returns `ExitSucceed` - info about execution, Vec<u8> - output data, u64 - gas cost
pub type PrecompileCallResult = Result<(ExitSucceed, Vec<u8>, u64), ExitError>;

pub type LogEntry = Vec<(Vec<H256>, Vec<u8>)>;
#[derive(Default)]
#[allow(clippy::type_complexity)]
pub struct OwnedPrecompile<'precompile> {
    pub precompiles: BTreeMap<
        H160,
        Box<
            dyn Fn(
                    &[u8],
                    Option<u64>,
                    Option<CallScheme>,
                    &Context,
                    bool,
                ) -> Result<(PrecompileOutput, u64, LogEntry), PrecompileFailure>
                + 'precompile,
        >,
    >,
}

use evm::executor::stack::{PrecompileHandle, PrecompileSet};

impl<'precompile> PrecompileSet for OwnedPrecompile<'precompile> {
    fn execute(&self, handle: &mut impl PrecompileHandle) -> Option<PrecompileResult> {
        let address = handle.code_address();

        self.get(&address).map(|precompile| {
            let input = handle.input();
            let gas_limit = handle.gas_limit();
            let call_scheme = handle.call_scheme();
            let context = handle.context();
            let is_static = handle.is_static();

            match (*precompile)(input, gas_limit, call_scheme, context, is_static) {
                Ok((output, cost, logs)) => {
                    handle.record_cost(cost)?;
                    for (log_topics, log_data) in logs {
                        handle.log(address, log_topics, log_data)?;
                    }
                    Ok(output)
                }
                Err(err) => Err(err),
            }
        })
    }
    fn is_precompile(&self, address: H160) -> bool {
        self.contains_key(&address)
    }
}

impl<'precompile> std::ops::Deref for OwnedPrecompile<'precompile> {
    type Target = BTreeMap<
        H160,
        Box<
            dyn Fn(
                    &[u8],
                    Option<u64>,
                    Option<CallScheme>,
                    &Context,
                    bool,
                ) -> Result<(PrecompileOutput, u64, LogEntry), PrecompileFailure>
                + 'precompile,
        >,
    >;

    fn deref(&self) -> &Self::Target {
        &self.precompiles
    }
}

#[derive(Clone, Debug)]
pub struct ExecutionResult {
    pub exit_reason: evm::ExitReason,
    pub exit_data: Vec<u8>,
    pub used_gas: u64,
    pub tx_logs: Vec<Log>,
    pub tx_id: H256,
    pub traces: Vec<Trace>,
}

impl fmt::Display for ExecutionResult {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "Execution result:")?;
        writeln!(f, "->Used gas: {}", self.used_gas)?;
        if !self.exit_data.is_empty() {
            writeln!(f, "->Output data: {}", hex::encode(&self.exit_data))?;
        }
        writeln!(f, "->Status: {:?}", self.exit_reason)?;
        if !self.tx_logs.is_empty() {
            writeln!(f, "->Logs:")?;
            for (id, l) in self.tx_logs.iter().enumerate() {
                writeln!(f, "-{}>Address: {:?}", id, l.address)?;
                writeln!(f, "-{}>Data: {:?}", id, l.data)?;
                writeln!(f, "-{}>Topics:", id,)?;
                for (id, topic) in l.topics.iter().enumerate() {
                    writeln!(f, "--{}>{:?}", id, topic)?;
                }
                writeln!(f)?;
            }
        }
        if !self.traces.is_empty() {
            writeln!(f, "->Traces:")?;
            for (id, trace) in self.traces.iter().enumerate() {
                writeln!(f, "-{}>Action: {:?}", id, trace.action)?;
                writeln!(f, "-{}>Result: {:?}", id, trace.result)?;
                writeln!(f, "-{}>Subtraces: {}", id, trace.subtraces)?;
                writeln!(f, "-{}>TraceAddress: {:?}", id, trace.trace_address)?;
            }
        }

        writeln!(f, "->Native EVM TXID: {:?}", self.tx_id)
    }
}

#[derive(Debug, Clone, Default)]
pub struct FeatureSet {
    unsigned_tx_fix: bool,
    clear_logs_on_error: bool,
    accept_zero_gas_price_with_native_fee: bool,
}

impl FeatureSet {
    pub fn new(
        unsigned_tx_fix: bool,
        clear_logs_on_error: bool,
        accept_zero_gas_price_with_native_fee: bool,
    ) -> Self {
        FeatureSet {
            unsigned_tx_fix,
            clear_logs_on_error,
            accept_zero_gas_price_with_native_fee,
        }
    }

    pub fn new_with_all_enabled() -> Self {
        FeatureSet {
            unsigned_tx_fix: true,
            clear_logs_on_error: true,
            accept_zero_gas_price_with_native_fee: true,
        }
    }

    pub fn is_unsigned_tx_fix_enabled(&self) -> bool {
        self.unsigned_tx_fix
    }

    pub fn is_clear_logs_on_error_enabled(&self) -> bool {
        self.clear_logs_on_error
    }

    pub fn is_accept_zero_gas_price_with_native_fee_enabled(&self) -> bool {
        self.accept_zero_gas_price_with_native_fee
    }
}

#[derive(Debug, Clone)]
pub struct Executor {
    pub evm_backend: EvmBackend<Incomming>,
    chain_context: ChainContext,
    config: EvmConfig,

    pub feature_set: FeatureSet,
}

impl Executor {
    // Return new default executor, with empty state stored in temporary dirrectory
    pub fn testing() -> Self {
        Self::with_config(
            Default::default(),
            Default::default(),
            Default::default(),
            Default::default(),
        )
    }
    pub fn default_configs(state: EvmBackend<Incomming>) -> Self {
        Self::with_config(
            state,
            Default::default(),
            Default::default(),
            Default::default(),
        )
    }

    pub fn with_config(
        evm_backend: EvmBackend<Incomming>,
        chain_context: ChainContext,
        config: EvmConfig,
        feature_set: FeatureSet,
    ) -> Self {
        Executor {
            evm_backend,
            chain_context,
            config,
            feature_set,
        }
    }

    pub fn support_precompile(&self) -> bool {
        self.evm_backend.state.block_version >= BlockVersion::VersionConsistentHashes
    }

    pub fn config(&self) -> &EvmConfig {
        &self.config
    }

    #[allow(clippy::too_many_arguments)]
    pub fn transaction_execute_raw(
        &mut self,
        caller: H160,
        nonce: U256,
        mut gas_price: U256,
        gas_limit: U256,
        action: TransactionAction,
        input: Vec<u8>,
        value: U256,
        tx_chain_id: Option<u64>,
        tx_hash: H256,
        withdraw_fee: bool,
        precompiles: OwnedPrecompile,
    ) -> Result<ExecutionResult, Error> {
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

        if self
            .feature_set
            .is_accept_zero_gas_price_with_native_fee_enabled()
            && !withdraw_fee
            && gas_price.is_zero()
        {
            gas_price = self.config.burn_gas_price;
        } else {
            ensure!(
                gas_price >= self.config.burn_gas_price,
                GasPriceOutOfBounds { gas_price }
            );
        }

        ensure!(
            gas_limit <= U256::from(u64::MAX),
            GasLimitOutOfBounds { gas_limit }
        );

        ensure!(
            self.config.gas_limit >= self.evm_backend.state.used_gas,
            GasLimitConfigAssert {
                gas_limit: self.config.gas_limit,
                gas_used: self.evm_backend.state.used_gas
            }
        );

        let max_fee = gas_limit * gas_price;
        if withdraw_fee {
            ensure!(
                max_fee + value <= state_account.balance,
                CantPayTheBills {
                    value,
                    max_fee,
                    state_balance: state_account.balance,
                }
            );
        }

        let clear_logs_on_error_enabled = self.feature_set.is_clear_logs_on_error_enabled();
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
        let state =
            MemoryStackState::new(metadata, &execution_context, clear_logs_on_error_enabled);
        let mut executor = StackExecutor::new_with_precompiles(state, &config, &precompiles);
        let (exit_reason, exit_data) = match action {
            TransactionAction::Call(addr) => {
                debug!(
                    "TransactionAction::Call caller  = {}, to = {}.",
                    caller, addr
                );
                executor.transact_call(caller, addr, value, input, gas_limit.as_u64(), vec![])
            }
            TransactionAction::Create => {
                let addr = TransactionAction::Create.address(caller, nonce);
                debug!(
                    "TransactionAction::Create caller  = {}, to = {:?}.",
                    caller, addr
                );
                executor.transact_create(caller, value, input, gas_limit.as_u64(), vec![])
            }
        };
        let traces = executor.take_traces();
        let used_gas = executor.used_gas();
        let fee = executor.fee(gas_price);
        let mut executor_state = executor.into_state();

        if withdraw_fee && matches!(exit_reason, ExitReason::Succeed(_)) {
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

        let tx_logs = match clear_logs_on_error_enabled && !exit_reason.is_succeed() {
            true => vec![],
            false => logs.into_iter().collect(),
        };
        execution_context.apply(updates, used_gas);

        Ok(ExecutionResult {
            exit_reason,
            exit_data,
            used_gas,
            tx_logs,
            tx_id: tx_hash,
            traces,
        })
    }

    /// Perform transaction execution without verify signature.
    pub fn transaction_execute_unsinged(
        &mut self,
        caller: H160,
        tx: UnsignedTransaction,
        withdraw_fee: bool,
        precompiles: OwnedPrecompile,
    ) -> Result<ExecutionResult, Error> {
        let chain_id = self.config.chain_id;

        let unsigned_tx = UnsignedTransactionWithCaller {
            unsigned_tx: tx.clone(),
            caller,
            chain_id,
            signed_compatible: self.feature_set.is_unsigned_tx_fix_enabled(),
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
            withdraw_fee,
            precompiles,
        )?;

        self.register_tx_with_receipt(TransactionInReceipt::Unsigned(unsigned_tx), result.clone());
        Ok(result)
    }

    pub fn transaction_execute(
        &mut self,
        evm_tx: Transaction,
        withdraw_fee: bool,
        precompiles: OwnedPrecompile,
    ) -> Result<ExecutionResult, Error> {
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
            withdraw_fee,
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
    pub fn with_executor<'a, F, U>(&'a mut self, precompiles: OwnedPrecompile, func: F) -> U
    where
        F: for<'r> FnOnce(
            &mut StackExecutor<
                'r,
                'r,
                MemoryStackState<'r, 'r, ExecutorContext<'a, Incomming>>,
                OwnedPrecompile,
            >,
        ) -> U,
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
        let state = MemoryStackState::new(
            metadata,
            &execution_context,
            self.feature_set.is_clear_logs_on_error_enabled(),
        );
        let mut executor = StackExecutor::new_with_precompiles(state, &config, &precompiles);
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

    // TODO: Make it cleaner - don't modify logs after storing, handle callback before push_transaction_receipt.
    pub fn modify_tx_logs<F, R>(&mut self, txid: H256, func: F) -> R
    where
        F: Fn(Option<&mut Vec<Log>>) -> R,
    {
        let mut tx = self
            .evm_backend
            .state
            .executed_transactions
            .iter_mut()
            .find(|(h, _)| *h == txid)
            .map(|(_, tx)| tx);
        let result = func(tx.as_mut().map(|tx| &mut tx.logs));
        if let Some(tx) = tx {
            tx.recalculate_bloom()
        };
        result
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
        self.with_executor(OwnedPrecompile::default(), |e| {
            e.state_mut().deposit(recipient, amount)
        });
    }

    pub fn register_swap_tx_in_evm(&mut self, mint_address: H160, recipient: H160, amount: U256) {
        let nonce = self.with_executor(OwnedPrecompile::default(), |e| {
            let nonce = e.nonce(mint_address);
            e.state_mut().inc_nonce(mint_address);
            nonce
        });
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
            signed_compatible: self.feature_set.is_unsigned_tx_fix_enabled(),
        };
        let result = ExecutionResult {
            tx_logs: Vec::new(),
            used_gas: 0,
            exit_data: Vec::new(),
            exit_reason: ExitReason::Succeed(ExitSucceed::Returned),
            tx_id: unsigned_tx.tx_id_hash(),
            traces: Vec::new(),
        };
        self.register_tx_with_receipt(TransactionInReceipt::Unsigned(unsigned_tx), result)
    }

    /// After "swap from evm" transaction EVM_MINT_ADDRESS will cleanup. Using this method.
    pub fn reset_balance(&mut self, swap_addr: H160, ignore_reset_on_cleared: bool) {
        self.with_executor(OwnedPrecompile::default(), |e| {
            if !ignore_reset_on_cleared || e.state().basic(swap_addr).balance != U256::zero() {
                e.state_mut().reset_balance(swap_addr)
            }
        });
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
    pub fn chain_id(&self) -> u64 {
        self.config.chain_id
    }

    pub fn balance(&self, addr: H160) -> U256 {
        self.evm_backend
            .get_account_state(addr)
            .unwrap_or_default()
            .balance
    }

    pub fn nonce(&self, addr: H160) -> U256 {
        self.evm_backend
            .get_account_state(addr)
            .unwrap_or_default()
            .nonce
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
    use {
        super::{
            ExecutionResult, Executor, HELLO_WORLD_ABI, HELLO_WORLD_CODE, HELLO_WORLD_CODE_SAVED,
            HELLO_WORLD_RESULT,
        },
        crate::{
            context::EvmConfig,
            executor::{FeatureSet, OwnedPrecompile},
            *,
        },
        error::*,
        ethabi::Token,
        evm::{
            backend::MemoryBackend,
            executor::stack::{MemoryStackState, StackSubstateMetadata},
            Capture, CreateScheme, ExitReason, ExitSucceed, Handler,
        },
        log::LevelFilter,
        primitive_types::{H160, H256, U256},
        sha3::{Digest, Keccak256},
        std::{collections::BTreeMap, str::FromStr},
    };

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
        use {
            ethabi::{Function, Param, ParamType, StateMutability},
            once_cell::sync::Lazy,
        };

        #[allow(deprecated)]
        pub static GET_BALANCE: Lazy<Function> = Lazy::new(|| Function {
            name: "getBalance".to_string(),
            inputs: vec![Param {
                name: "addr".to_string(),
                kind: ParamType::Address,
                internal_type: None,
            }],
            outputs: vec![Param {
                name: "".to_string(),
                kind: ParamType::Uint(256),
                internal_type: None,
            }],
            constant: Some(true),
            state_mutability: StateMutability::View,
        });

        #[allow(deprecated)]
        pub static SEND_COIN: Lazy<Function> = Lazy::new(|| Function {
            name: "sendCoin".to_string(),
            inputs: vec![
                Param {
                    name: "receiver".to_string(),
                    kind: ParamType::Address,
                    internal_type: None,
                },
                Param {
                    name: "amount".to_string(),
                    kind: ParamType::Uint(256),
                    internal_type: None,
                },
            ],
            outputs: vec![Param {
                name: "sufficient".to_string(),
                kind: ParamType::Bool,
                internal_type: None,
            }],
            constant: Some(false),
            state_mutability: StateMutability::NonPayable,
        });
    }

    #[test]
    fn handle_duplicate_txs() {
        let _logger = simple_logger::SimpleLogger::new()
            .with_utc_timestamps()
            .init();

        let chain_id = TEST_CHAIN_ID;
        let evm_config = EvmConfig {
            chain_id,
            ..EvmConfig::default()
        };
        let mut executor = Executor::with_config(
            EvmBackend::default(),
            Default::default(),
            evm_config,
            FeatureSet::new_with_all_enabled(),
        );

        let code = hex::decode(METACOIN_CODE).unwrap();

        let alice = Persona::new();
        let create_tx = alice.unsigned(TransactionAction::Create, &code);

        let create_tx = create_tx.sign(&alice.secret, Some(chain_id));
        assert!(matches!(
            executor
                .transaction_execute(create_tx.clone(), true, OwnedPrecompile::default())
                .unwrap()
                .exit_reason,
            ExitReason::Succeed(ExitSucceed::Returned)
        ));

        let hash = create_tx.tx_id_hash();
        assert!(matches!(
            executor
                .transaction_execute(create_tx, true, OwnedPrecompile::default())
                .unwrap_err(),
            Error::DuplicateTx { tx_hash } if tx_hash == hash
        ));
    }

    #[test]
    fn handle_duplicate_txs_unsigned() {
        let _logger = simple_logger::SimpleLogger::new()
            .with_utc_timestamps()
            .init();

        let chain_id = TEST_CHAIN_ID;
        let evm_config = EvmConfig {
            chain_id,
            ..EvmConfig::default()
        };
        let mut executor = Executor::with_config(
            EvmBackend::default(),
            Default::default(),
            evm_config,
            FeatureSet::new(false, true, false),
        );

        let code = hex::decode(METACOIN_CODE).unwrap();

        let alice = Persona::new();
        let create_tx = alice.unsigned(TransactionAction::Create, &code);

        assert!(matches!(
            executor
                .transaction_execute_unsinged(
                    alice.address(),
                    create_tx.clone(),
                    true,
                    OwnedPrecompile::default()
                )
                .unwrap()
                .exit_reason,
            ExitReason::Succeed(ExitSucceed::Returned)
        ));

        let hash = create_tx.signing_hash(Some(chain_id));
        assert!(matches!(
            executor
            .transaction_execute_unsinged(alice.address(), create_tx, true, OwnedPrecompile::default())
                .unwrap_err(),
            Error::DuplicateTx { tx_hash } if tx_hash == hash
        ));
    }

    #[test]
    fn handle_execute_and_commit() {
        for gc in [true, false] {
            println!("Executing with gc_enabled={}", gc);
            let _logger = simple_logger::SimpleLogger::new()
                .with_utc_timestamps()
                .init();

            let chain_id = TEST_CHAIN_ID;
            let evm_config = EvmConfig {
                chain_id,
                ..EvmConfig::default()
            };
            let storage = if gc {
                Storage::create_temporary_gc()
            } else {
                Storage::create_temporary()
            };
            let backend = EvmBackend::new(Incomming::default(), storage.unwrap());
            let mut executor = Executor::with_config(
                backend,
                Default::default(),
                evm_config,
                FeatureSet::new_with_all_enabled(),
            );

            let code = hex::decode(METACOIN_CODE).unwrap();

            let mut alice = Persona::new();
            let create_tx = alice.create(&code);
            assert!(matches!(
                executor
                    .transaction_execute(create_tx.clone(), true, OwnedPrecompile::default())
                    .unwrap()
                    .exit_reason,
                ExitReason::Succeed(ExitSucceed::Returned)
            ));
            let slot = 1;
            let backend = executor
                .deconstruct()
                .commit_block(slot, H256::zero())
                .next_incomming(0);

            let first_root = backend.last_root();
            backend
                .kvs()
                .register_slot(slot, first_root, false)
                .unwrap();

            let mut executor = Executor::with_config(
                backend,
                Default::default(),
                evm_config,
                FeatureSet::new_with_all_enabled(),
            );
            let contract_address = create_tx.address().unwrap();

            alice.nonce += 1;
            let call_tx = alice.call(
                contract_address,
                &metacoin::GET_BALANCE
                    .encode_input(&[Token::Address(alice.address())])
                    .unwrap(),
            );

            let ExecutionResult {
                exit_reason,
                exit_data: bytes,
                ..
            } = executor
                .transaction_execute(call_tx, true, OwnedPrecompile::default())
                .unwrap();

            assert_eq!(exit_reason, ExitReason::Succeed(ExitSucceed::Returned));
            assert_eq!(
                metacoin::GET_BALANCE.decode_output(&bytes).unwrap(),
                vec![Token::Uint(U256::from(INITIAL_BALANCE))]
            );
            let backend = executor
                .deconstruct()
                .commit_block(2, H256::zero())
                .next_incomming(0);

            let root = backend.last_root();
            assert!(backend.kvs().check_root_exist(root));
            assert!(backend.kvs().check_root_exist(first_root));
            if gc {
                let hash = backend.kvs().purge_slot(slot).unwrap().unwrap();
                backend.kvs().gc_try_cleanup_account_hashes(&[hash]);
                // on gc it will be removed
                assert!(!backend.kvs().check_root_exist(first_root));
            } else {
                assert!(backend.kvs().check_root_exist(first_root));
            }
        }
    }

    #[test]
    fn handle_burn_fee() {
        let _logger = simple_logger::SimpleLogger::new()
            .with_utc_timestamps()
            .init();

        let chain_id = 0xeba;
        let evm_config = EvmConfig {
            chain_id,
            ..EvmConfig::new(chain_id, true)
        };
        let mut executor = Executor::with_config(
            EvmBackend::default(),
            Default::default(),
            evm_config,
            FeatureSet::new_with_all_enabled(),
        );

        let alice = Persona::new();
        let mut create_tx = alice.unsigned(TransactionAction::Call(H160::zero()), &[]);

        create_tx.gas_limit = 300_000.into();
        let address = alice.address();

        executor.deposit(
            address,
            create_tx.gas_limit * U256::from(crate::BURN_GAS_PRICE),
        );
        assert_eq!(
            executor
                .transaction_execute_unsinged(
                    address,
                    create_tx.clone(),
                    true,
                    OwnedPrecompile::default()
                )
                .unwrap_err(),
            Error::GasPriceOutOfBounds {
                gas_price: 0.into()
            }
        );

        create_tx.gas_price = crate::BURN_GAS_PRICE.into();

        assert_eq!(
            executor
                .transaction_execute_unsinged(address, create_tx, true, OwnedPrecompile::default())
                .unwrap()
                .exit_reason,
            ExitReason::Succeed(ExitSucceed::Stopped)
        );
    }

    #[test]
    fn handle_duplicate_txs_unsigned_new_hash() {
        let _logger = simple_logger::SimpleLogger::new()
            .with_utc_timestamps()
            .init();

        let chain_id = 0xeba;
        let evm_config = EvmConfig {
            chain_id,
            ..EvmConfig::default()
        };
        let mut executor = Executor::with_config(
            EvmBackend::default(),
            Default::default(),
            evm_config,
            FeatureSet::new_with_all_enabled(),
        );

        let code = hex::decode(METACOIN_CODE).unwrap();

        let alice = Persona::new();
        let create_tx = alice.unsigned(TransactionAction::Create, &code);

        let address = alice.address();
        assert_eq!(
            executor
                .transaction_execute_unsinged(
                    address,
                    create_tx.clone(),
                    true,
                    OwnedPrecompile::default()
                )
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
                .transaction_execute_unsinged(address, create_tx, true, OwnedPrecompile::default())
                .unwrap_err(),
            Error::DuplicateTx { tx_hash: hash }
        );
    }

    #[test]
    fn it_execute_only_txs_with_correct_chain_id() {
        let _logger = simple_logger::SimpleLogger::new()
            .with_utc_timestamps()
            .init();

        let chain_id = 0xeba;
        let another_chain_id = 0xb0ba;
        let evm_config = EvmConfig {
            chain_id,
            ..EvmConfig::default()
        };
        let mut executor = Executor::with_config(
            EvmBackend::default(),
            Default::default(),
            evm_config,
            FeatureSet::new_with_all_enabled(),
        );

        let code = hex::decode(METACOIN_CODE).unwrap();

        let alice = Persona::new();
        let create_tx = alice.unsigned(TransactionAction::Create, &code);

        let wrong_tx = create_tx.clone().sign(&alice.secret, None);
        assert!(matches!(
            dbg!(executor
                .transaction_execute(wrong_tx, true, OwnedPrecompile::default())
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
                .transaction_execute(wrong_tx, true, OwnedPrecompile::default())
                .unwrap_err(),
            Error::WrongChainId {
                chain_id: err_chain_id,
                tx_chain_id,
            } if (err_chain_id, tx_chain_id) == (chain_id, Some(another_chain_id))
        ));

        let create_tx = create_tx.sign(&alice.secret, Some(chain_id));
        assert!(matches!(
            executor
                .transaction_execute(create_tx, true, OwnedPrecompile::default())
                .unwrap()
                .exit_reason,
            ExitReason::Succeed(ExitSucceed::Returned)
        ));
    }

    #[test]
    fn it_handles_metacoin() {
        use ethabi::Token;

        let _logger = simple_logger::SimpleLogger::new()
            .with_utc_timestamps()
            .init();

        let code = hex::decode(METACOIN_CODE).unwrap();

        let mut executor = Executor::with_config(
            EvmBackend::default(),
            Default::default(),
            Default::default(),
            FeatureSet::new_with_all_enabled(),
        );

        let mut alice = Persona::new();
        let create_tx = alice.create(&code);
        let contract = create_tx.address().unwrap();

        assert!(matches!(
            executor
                .transaction_execute(create_tx, true, OwnedPrecompile::default())
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
            .transaction_execute(call_tx, true, OwnedPrecompile::default())
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
            .transaction_execute(send_tx, true, OwnedPrecompile::default())
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
            .transaction_execute(call_tx, true, OwnedPrecompile::default())
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
            .transaction_execute(call_tx, true, OwnedPrecompile::default())
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
            let mut executor = Executor::with_config(
                state,
                Default::default(),
                Default::default(),
                FeatureSet::new_with_all_enabled(),
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

            let ExecutionResult {
                exit_reason,
                exit_data: bytes,
                ..
            } = executor
                .transaction_execute(send_tx, true, OwnedPrecompile::default())
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
                .transaction_execute(call_tx, true, OwnedPrecompile::default())
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
                .transaction_execute(call_tx, true, OwnedPrecompile::default())
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
            let mut executor = Executor::with_config(
                state,
                Default::default(),
                Default::default(),
                FeatureSet::new_with_all_enabled(),
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

            let ExecutionResult {
                exit_reason,
                exit_data: bytes,
                ..
            } = executor
                .transaction_execute(send_tx, true, OwnedPrecompile::default())
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
                .transaction_execute(call_tx, true, OwnedPrecompile::default())
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
                .transaction_execute(call_tx, true, OwnedPrecompile::default())
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
        let _logger_error = simple_logger::SimpleLogger::new()
            .with_utc_timestamps()
            .init();

        let code = hex::decode(HELLO_WORLD_CODE).unwrap();
        let data = hex::decode(HELLO_WORLD_ABI).unwrap();

        let mut executor = Executor::with_config(
            EvmBackend::default(),
            Default::default(),
            Default::default(),
            FeatureSet::new(false, true, false),
        );

        let exit_reason = match executor.with_executor(OwnedPrecompile::default(), |e| {
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

        let exit_result = executor
            .transaction_execute_unsinged(
                name_to_key("caller"),
                UnsignedTransaction {
                    nonce: 1.into(),
                    gas_price: 0.into(),
                    gas_limit: 300000.into(),
                    action: TransactionAction::Call(name_to_key("contract")),
                    value: U256::zero(),
                    input: data.to_vec(),
                },
                true,
                OwnedPrecompile::default(),
            )
            .unwrap();

        let result = hex::decode(HELLO_WORLD_RESULT).unwrap();
        match (exit_result.exit_reason, exit_result.exit_data) {
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

    fn dummy_account() -> MemoryAccount {
        MemoryAccount {
            nonce: U256::one(),
            balance: U256::from(10000000),
            storage: BTreeMap::new(),
            code: Vec::new(),
        }
    }

    #[test]
    fn test_call_inner_with_estimate() {
        let _logger_error = simple_logger::SimpleLogger::new()
            .with_level(LevelFilter::Debug)
            .init();
        let config_estimate = Config {
            estimate: true,
            ..Config::istanbul()
        };
        let config_no_estimate = Config::istanbul();

        let vicinity = MemoryVicinity {
            gas_price: U256::zero(),
            origin: H160::default(),
            block_hashes: Vec::new(),
            block_number: Default::default(),
            block_coinbase: Default::default(),
            block_timestamp: Default::default(),
            block_difficulty: Default::default(),
            block_gas_limit: Default::default(),
            chain_id: U256::one(),
            block_base_fee_per_gas: Default::default(),
        };

        let mut state = BTreeMap::new();
        let caller_address = H160::from_str("0xf000000000000000000000000000000000000000").unwrap();
        let contract_address =
            H160::from_str("0x1000000000000000000000000000000000000000").unwrap();
        state.insert(caller_address, dummy_account());
        state.insert(
            contract_address,
            MemoryAccount {
                nonce: U256::one(),
                balance: U256::from(10000000),
                storage: BTreeMap::new(),
                // proxy contract code
                code: hex::decode("608060405260043610610041576000357c0100000000000000000000000000000000000000000000000000000000900463ffffffff1680632da4e75c1461006a575b6000543660008037600080366000845af43d6000803e8060008114610065573d6000f35b600080fd5b34801561007657600080fd5b506100ab600480360381019080803573ffffffffffffffffffffffffffffffffffffffff1690602001909291905050506100ad565b005b600160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff1614151561010957600080fd5b806000806101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff160217905550505600a165627a7a72305820f58232a59d38bc7ca7fcefa0993365e57f4cd4e8b3fa746e0d170c5b47a787920029").unwrap(),
            }
        );

        let call_data =
            hex::decode("6057361d0000000000000000000000000000000000000000000000000000000000000000")
                .unwrap();
        let transact_call = |config, gas_limit| {
            let backend = MemoryBackend::new(&vicinity, state.clone());
            let metadata = StackSubstateMetadata::new(gas_limit, config);
            let state = MemoryStackState::new(metadata, &backend, false);
            let precompiles = BTreeMap::new();
            let mut executor = StackExecutor::new_with_precompiles(state, config, &precompiles);

            let _reason = executor.transact_call(
                caller_address,
                contract_address,
                U256::zero(),
                call_data.clone(),
                gas_limit,
                vec![],
            );
            executor.used_gas()
        };
        {
            let gas_limit = u64::MAX;
            let gas_used_estimate = transact_call(&config_estimate, gas_limit);
            let gas_used_no_estimate = transact_call(&config_no_estimate, gas_limit);
            assert!(gas_used_estimate >= gas_used_no_estimate);
            assert!(gas_used_estimate < gas_used_no_estimate + gas_used_no_estimate / 4,
                    "gas_used with estimate=true is too high, gas_used_estimate={}, gas_used_no_estimate={}",
                    gas_used_estimate, gas_used_no_estimate);
        }

        {
            let gas_limit: u64 = 300_000_000;
            let gas_used_estimate = transact_call(&config_estimate, gas_limit);
            let gas_used_no_estimate = transact_call(&config_no_estimate, gas_limit);
            assert!(gas_used_estimate >= gas_used_no_estimate);
            assert!(gas_used_estimate < gas_used_no_estimate + gas_used_no_estimate / 4,
                    "gas_used with estimate=true is too high, gas_used_estimate={}, gas_used_no_estimate={}",
                    gas_used_estimate, gas_used_no_estimate);
        }
    }

    #[test]
    fn test_create_inner_with_estimate() {
        let _logger_error = simple_logger::SimpleLogger::new()
            .with_level(LevelFilter::Debug)
            .init();
        let config_estimate = Config {
            estimate: true,
            ..Config::istanbul()
        };
        let config_no_estimate = Config::istanbul();

        let vicinity = MemoryVicinity {
            gas_price: U256::zero(),
            origin: H160::default(),
            block_hashes: Vec::new(),
            block_number: Default::default(),
            block_coinbase: Default::default(),
            block_timestamp: Default::default(),
            block_difficulty: Default::default(),
            block_gas_limit: Default::default(),
            chain_id: U256::one(),
            block_base_fee_per_gas: Default::default(),
        };

        let mut state = BTreeMap::new();
        let caller_address = H160::from_str("0xf000000000000000000000000000000000000000").unwrap();
        let contract_address =
            H160::from_str("0x1000000000000000000000000000000000000000").unwrap();
        state.insert(caller_address, dummy_account());
        state.insert(
            contract_address,
            MemoryAccount {
                nonce: U256::one(),
                balance: U256::from(10000000),
                storage: BTreeMap::new(),
                // creator contract code
                code: hex::decode("6080604052348015600f57600080fd5b506004361060285760003560e01c8063fb971d0114602d575b600080fd5b60336035565b005b60006040516041906062565b604051809103906000f080158015605c573d6000803e3d6000fd5b50905050565b610170806100708339019056fe608060405234801561001057600080fd5b50610150806100206000396000f3fe608060405234801561001057600080fd5b50600436106100365760003560e01c80632e64cec11461003b5780636057361d14610059575b600080fd5b610043610075565b60405161005091906100a1565b60405180910390f35b610073600480360381019061006e91906100ed565b61007e565b005b60008054905090565b8060008190555050565b6000819050919050565b61009b81610088565b82525050565b60006020820190506100b66000830184610092565b92915050565b600080fd5b6100ca81610088565b81146100d557600080fd5b50565b6000813590506100e7816100c1565b92915050565b600060208284031215610103576101026100bc565b5b6000610111848285016100d8565b9150509291505056fea264697066735822122044f0132d3ce474198482cc3f79c22d7ed4cece5e1dcbb2c7cb533a23068c5d6064736f6c634300080d0033a2646970667358221220a7ba80fb064accb768e9e7126cd0b69e3889378082d659ad1b17317e6d578b9a64736f6c634300080d0033").unwrap(),
            }
        );

        let call_data = hex::decode("fb971d01").unwrap();
        let transact_call = |config, gas_limit| {
            let backend = MemoryBackend::new(&vicinity, state.clone());
            let metadata = StackSubstateMetadata::new(gas_limit, config);
            let state = MemoryStackState::new(metadata, &backend, false);
            let precompiles = BTreeMap::new();
            let mut executor = StackExecutor::new_with_precompiles(state, config, &precompiles);

            let _reason = executor.transact_call(
                caller_address,
                contract_address,
                U256::zero(),
                call_data.clone(),
                gas_limit,
                vec![],
            );
            executor.used_gas()
        };
        {
            let gas_limit = u64::MAX;
            let gas_used_estimate = transact_call(&config_estimate, gas_limit);
            let gas_used_no_estimate = transact_call(&config_no_estimate, gas_limit);
            assert!(gas_used_estimate >= gas_used_no_estimate);
            assert!(gas_used_estimate < gas_used_no_estimate + gas_used_no_estimate / 4,
                    "gas_used with estimate=true is too high, gas_used_estimate={}, gas_used_no_estimate={}",
                    gas_used_estimate, gas_used_no_estimate);
        }

        {
            let gas_limit: u64 = 300_000_000;
            let gas_used_estimate = transact_call(&config_estimate, gas_limit);
            let gas_used_no_estimate = transact_call(&config_no_estimate, gas_limit);
            assert!(gas_used_estimate >= gas_used_no_estimate);
            assert!(gas_used_estimate < gas_used_no_estimate + gas_used_no_estimate / 4,
                    "gas_used with estimate=true is too high, gas_used_estimate={}, gas_used_no_estimate={}",
                    gas_used_estimate, gas_used_no_estimate);
        }
    }
}
