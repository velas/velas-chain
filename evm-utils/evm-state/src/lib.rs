pub use evm::{
    backend::{Apply, Backend, Log},
    executor::StackExecutor,
    Config, Context, Handler, Transfer,
};

pub mod layered_backend;
pub mod transactions;

pub use layered_backend::*;
pub use primitive_types::{H256, U256};
pub use transactions::*;

mod layered_map;
mod storage;
mod version_map;

use std::collections::BTreeMap;
use std::fmt;
use std::ops::Deref;

/// StackExecutor, use config and backend by reference, this force object to be dependent on lifetime.
/// And poison all outer objects with this lifetime.
/// This is not userfriendly, so we pack Executor object into self referential object.
pub struct StaticExecutor<B: 'static> {
    evm: evm::executor::StackExecutor<'static, 'static, B>,
    // Avoid changing backend and config, while evm executor is reffer to it.
    _backend: Box<B>,
    _config: Box<Config>,
    txs_receipts: BTreeMap<H256, transactions::TransactionReceipt>,
}

impl<B: 'static> fmt::Debug for StaticExecutor<B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StaticExecutor")
            .field("config", &self._config)
            .finish()
    }
}

impl<B: evm::backend::Backend> StaticExecutor<B> {
    pub fn with_config(backend: B, config: Config, gas_limit: usize) -> Self {
        let _backend = Box::new(backend);
        let _config = Box::new(config);
        let evm = {
            let backend: &'static B = unsafe { std::mem::transmute(_backend.deref()) };
            let config: &'static Config = unsafe { std::mem::transmute(_config.deref()) };
            evm::executor::StackExecutor::new(backend, gas_limit, config)
        };
        StaticExecutor {
            _backend,
            _config,
            evm,
            txs_receipts: BTreeMap::new(),
        }
    }
    pub fn rent_executor(&mut self) -> &mut evm::executor::StackExecutor<'_, '_, B> {
        unsafe { std::mem::transmute(&mut self.evm) }
    }
    // TODO: Handle duplicates, statuses.
    pub fn register_tx_receipt(&mut self, tx_receipt: transactions::TransactionReceipt) {
        let tx: transactions::UnsignedTransaction = tx_receipt.transaction.clone().into();
        let tx_hash = tx.signing_hash(tx_receipt.transaction.signature.chain_id());
        self.txs_receipts.insert(tx_hash, tx_receipt);
    }

    pub fn deconstruct(
        self,
    ) -> (
        (
            impl IntoIterator<Item = Apply<impl IntoIterator<Item = (H256, H256)>>>,
            impl IntoIterator<Item = Log>,
        ),
        BTreeMap<H256, transactions::TransactionReceipt>,
    ) {
        (self.evm.deconstruct(), self.txs_receipts)
    }
}

impl<B: Default + evm::backend::Backend> Default for StaticExecutor<B> {
    fn default() -> Self {
        StaticExecutor::with_config(B::default(), Config::istanbul(), Default::default())
    }
}

pub const HELLO_WORLD_CODE:&str = "608060405234801561001057600080fd5b5061011e806100206000396000f3fe6080604052348015600f57600080fd5b506004361060285760003560e01c8063942ae0a714602d575b600080fd5b603360ab565b6040518080602001828103825283818151815260200191508051906020019080838360005b8381101560715780820151818401526020810190506058565b50505050905090810190601f168015609d5780820380516001836020036101000a031916815260200191505b509250505060405180910390f35b60606040518060400160405280600a81526020017f68656c6c6f576f726c640000000000000000000000000000000000000000000081525090509056fea2646970667358221220fa787b95ca91ffe90fdb780b8ee8cb11c474bc63cb8217112c88bc465f7ea7d364736f6c63430007020033";
pub const HELLO_WORLD_ABI: &str = "942ae0a7";
pub const HELLO_WORLD_RESULT:&str = "0000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000a68656c6c6f576f726c6400000000000000000000000000000000000000000000";
pub const HELLO_WORLD_CODE_SAVED:&str = "6080604052348015600f57600080fd5b506004361060285760003560e01c8063942ae0a714602d575b600080fd5b603360ab565b6040518080602001828103825283818151815260200191508051906020019080838360005b8381101560715780820151818401526020810190506058565b50505050905090810190601f168015609d5780820380516001836020036101000a031916815260200191505b509250505060405180910390f35b60606040518060400160405280600a81526020017f68656c6c6f576f726c640000000000000000000000000000000000000000000081525090509056fea2646970667358221220fa787b95ca91ffe90fdb780b8ee8cb11c474bc63cb8217112c88bc465f7ea7d364736f6c63430007020033";

#[cfg(test)]
mod test_utils;

#[cfg(test)]
mod tests {
    use std::sync::RwLock;

    use assert_matches::assert_matches;
    use evm::{Capture, CreateScheme, ExitReason, ExitSucceed, Handler};

    use primitive_types::{H160, H256, U256};
    use sha3::{Digest, Keccak256};

    use super::*;

    fn name_to_key(name: &str) -> H160 {
        let hash = H256::from_slice(Keccak256::digest(name.as_bytes()).as_slice());
        hash.into()
    }

    #[test]
    fn test_evm_bytecode() {
        simple_logger::SimpleLogger::new().init().unwrap();
        let accounts = ["contract", "caller"];

        let code = hex::decode(HELLO_WORLD_CODE).unwrap();
        let data = hex::decode(HELLO_WORLD_ABI).unwrap();

        let vicinity = MemoryVicinity {
            gas_price: U256::zero(),
            origin: H160::default(),
            chain_id: U256::zero(),
            block_hashes: Vec::new(),
            block_number: U256::zero(),
            block_coinbase: H160::default(),
            block_timestamp: U256::zero(),
            block_difficulty: U256::zero(),
            block_gas_limit: U256::max_value(),
        };

        let backend = EvmState::new(vicinity);
        let backend = RwLock::new(backend);

        {
            let mut state = backend.write().unwrap();

            for acc in &accounts {
                let account = name_to_key(acc);
                let memory = AccountState {
                    ..Default::default()
                };
                state.accounts.insert(account, memory);
            }
        }

        backend.write().unwrap().freeze();

        let config = evm::Config::istanbul();
        let mut executor = StaticExecutor::with_config(
            backend.read().unwrap().try_fork(1).unwrap(),
            config,
            usize::max_value(),
        );

        let exit_reason = match executor.rent_executor().create(
            name_to_key("caller"),
            CreateScheme::Fixed(name_to_key("contract")),
            U256::zero(),
            code,
            None,
        ) {
            Capture::Exit((s, _, v)) => (s, v),
            Capture::Trap(_) => unreachable!(),
        };

        assert_matches!(exit_reason, (ExitReason::Succeed(ExitSucceed::Returned), _));
        let exit_reason = executor.rent_executor().transact_call(
            name_to_key("contract"),
            name_to_key("contract"),
            U256::zero(),
            data.to_vec(),
            usize::max_value(),
        );

        let result = hex::decode(HELLO_WORLD_RESULT).unwrap();
        match exit_reason {
            (ExitReason::Succeed(ExitSucceed::Returned), res) if res == result => {}
            any_other => panic!("Not expected result={:?}", any_other),
        }

        let patch = executor.deconstruct();
        backend.write().unwrap().apply(patch);

        let mutex_lock = backend.read().unwrap();
        let contract = mutex_lock.accounts.get(name_to_key("contract"));
        assert_eq!(
            &contract.unwrap().code,
            &hex::decode(HELLO_WORLD_CODE_SAVED).unwrap()
        );
    }
}
