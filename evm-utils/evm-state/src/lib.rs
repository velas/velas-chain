pub use evm::{
    backend::{Apply, ApplyBackend, Backend, Log},
    executor::StackExecutor,
    Config, Context, Handler, Transfer,
};
pub use evm::{ExitError, ExitFatal, ExitReason, ExitRevert, ExitSucceed};
use log::{debug, error};
pub use primitive_types::{H256, U256};
pub use secp256k1::rand;

mod error;
mod layered_backend;

pub mod transactions;
pub mod types;

use error::*;
pub use evm_backend::*;
pub use layered_backend::Storage;
pub use layered_backend::*;
pub use transactions::*;
pub use types::*;

mod evm_backend;
mod mb_value;
mod storage;

use std::fmt;

pub const MAX_TX_LEN: u64 = 3 * 1024 * 1024; // Limit size to 3 MB
pub const TX_MTU: u64 = 920;

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
    used_gas: usize,
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
        gas_limit: usize,
        block_number: u64,
    ) -> Self {
        let vicinity = MemoryVicinity {
            block_gas_limit: gas_limit.into(),
            block_number: block_number.into(),
            ..Default::default()
        };
        Executor {
            evm: EvmBackend::new_from_state(state, vicinity),
            config,
            used_gas: 0,
        }
    }

    pub fn transaction_execute(
        &mut self,
        evm_tx: Transaction,
    ) -> Result<(evm::ExitReason, Vec<u8>), Error> {
        let caller = evm_tx.caller()?;

        self.evm.tx_info.origin = caller;
        self.evm.tx_info.gas_price = evm_tx.gas_price;
        let gas_limit = self.evm.block_gas_limit().as_usize() - self.used_gas;
        let mut executor = StackExecutor::new(&self.evm, gas_limit, &self.config);
        let result = match evm_tx.action {
            TransactionAction::Call(addr) => {
                debug!(
                    "TransactionAction::Call caller  = {}, to = {}.",
                    caller, addr
                );
                executor.transact_call(
                    caller,
                    addr,
                    evm_tx.value,
                    evm_tx.input.clone(),
                    evm_tx.gas_limit.as_usize(),
                )
            }
            TransactionAction::Create => {
                let addr = evm_tx.address();
                debug!(
                    "TransactionAction::Create caller  = {}, to = {:?}.",
                    caller, addr
                );
                (
                    executor.transact_create(
                        caller,
                        evm_tx.value,
                        evm_tx.input.clone(),
                        evm_tx.gas_limit.as_usize(),
                    ),
                    vec![],
                )
            }
        };
        let used_gas = executor.used_gas();

        assert!(used_gas + self.used_gas <= self.evm.tx_info.block_gas_limit.as_usize());
        let (updates, logs) = executor.deconstruct();
        self.evm.apply(updates, false);
        self.register_tx_receipt(evm_tx, used_gas.into(), logs, result.clone());
        self.used_gas += used_gas;

        Ok(result)
    }

    /// Do lowlevel operation with executor, without storing transaction into logs.
    /// Usefull for testing and transfering tokens from evm to solana and back.
    pub fn with_executor<F, U>(&mut self, func: F) -> U
    where
        F: FnOnce(&mut StackExecutor<'_, '_, EvmBackend>) -> U,
    {
        let gas_limit = self.evm.block_gas_limit().as_usize() - self.used_gas;
        let mut executor = StackExecutor::new(&self.evm, gas_limit, &self.config);
        let result = func(&mut executor);
        let used_gas = executor.used_gas();
        let (updates, _logs) = executor.deconstruct();
        self.used_gas += used_gas;
        self.evm.apply(updates, false);
        result
    }

    pub fn used_gas(&self) -> usize {
        self.used_gas
    }

    pub fn get_tx_receipt_by_hash(&mut self, tx: H256) -> Option<TransactionReceipt> {
        self.evm.evm_state.get_tx_receipt_by_hash(tx)
    }

    pub fn take_big_tx(&mut self, key: H256) -> Result<Vec<u8>, Error> {
        let big_tx_storage = if let Some(big_tx_storage) = self.evm.evm_state.get_big_tx(key) {
            debug!("data at get = {:?}", big_tx_storage.tx_chunks);
            big_tx_storage.clone()
        } else {
            return DataNotFound { key }.fail();
        };
        self.evm.evm_state.big_transactions.remove(key);

        Ok(big_tx_storage.tx_chunks)
    }

    pub fn allocate_store(&mut self, key: H256, size: u64) -> Result<(), Error> {
        if self.evm.evm_state.get_big_tx(key).is_some() || size > MAX_TX_LEN {
            error!("Double allocation for key = {:?}", key);
            return AllocationError { key, size }.fail();
        };

        let big_tx_storage = BigTransactionStorage {
            tx_chunks: vec![0; size as usize],
        };

        self.evm
            .evm_state
            .big_transactions
            .insert(key, big_tx_storage);

        Ok(())
    }

    pub fn publish_data(&mut self, key: H256, offset: u64, data: &[u8]) -> Result<(), Error> {
        let mut big_tx_storage = if let Some(big_tx_storage) = self.evm.evm_state.get_big_tx(key) {
            let max_len = big_tx_storage.tx_chunks.len() as u64;
            let data_end = offset.saturating_add(data.len() as u64);
            // check offset to avoid integer overflow
            if data_end > max_len {
                return OutOfBound {
                    key,
                    offset,
                    size: max_len,
                }
                .fail();
            }
            big_tx_storage.clone()
        } else {
            error!("Failed to write without allocation = {:?}", key);
            return FailedToWrite { key, offset }.fail();
        };

        let offset = offset as usize;
        big_tx_storage.tx_chunks[offset..offset + data.len()].copy_from_slice(data);

        self.evm
            .evm_state
            .big_transactions
            .insert(key, big_tx_storage);

        Ok(())
    }

    // TODO: Handle duplicates, statuses.
    fn register_tx_receipt<I>(
        &mut self,
        tx: transactions::Transaction,
        used_gas: U256,
        logs: I,
        result: (evm::ExitReason, Vec<u8>),
    ) where
        I: IntoIterator<Item = Log>,
    {
        let block_num = self.evm.tx_info.block_number.as_u64();
        let tx_hash = tx.signing_hash();

        debug!("Register tx in evm block={}, tx= {}", block_num, tx_hash);
        // TODO: replace by Entry-like api
        let mut hashes = self
            .evm
            .evm_state
            .get_txs_in_block(block_num)
            .unwrap_or_default();
        hashes.push(tx_hash);

        let index = hashes.len() as u64;
        self.evm
            .evm_state
            .txs_in_block
            .insert(block_num, hashes.into());

        let tx_receipt = TransactionReceipt::new(
            tx,
            used_gas,
            block_num,
            index,
            logs.into_iter().collect(),
            result,
        );
        self.evm.evm_state.txs_receipts.insert(tx_hash, tx_receipt);
    }

    pub fn deconstruct(self) -> EvmState {
        self.evm.evm_state
    }
}

pub const HELLO_WORLD_CODE:&str = "608060405234801561001057600080fd5b5061011e806100206000396000f3fe6080604052348015600f57600080fd5b506004361060285760003560e01c8063942ae0a714602d575b600080fd5b603360ab565b6040518080602001828103825283818151815260200191508051906020019080838360005b8381101560715780820151818401526020810190506058565b50505050905090810190601f168015609d5780820380516001836020036101000a031916815260200191505b509250505060405180910390f35b60606040518060400160405280600a81526020017f68656c6c6f576f726c640000000000000000000000000000000000000000000081525090509056fea2646970667358221220fa787b95ca91ffe90fdb780b8ee8cb11c474bc63cb8217112c88bc465f7ea7d364736f6c63430007020033";
pub const HELLO_WORLD_ABI: &str = "942ae0a7";
pub const HELLO_WORLD_RESULT:&str = "0000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000a68656c6c6f576f726c6400000000000000000000000000000000000000000000";
pub const HELLO_WORLD_CODE_SAVED:&str = "6080604052348015600f57600080fd5b506004361060285760003560e01c8063942ae0a714602d575b600080fd5b603360ab565b6040518080602001828103825283818151815260200191508051906020019080838360005b8381101560715780820151818401526020810190506058565b50505050905090810190601f168015609d5780820380516001836020036101000a031916815260200191505b509250505060405180910390f35b60606040518060400160405280600a81526020017f68656c6c6f576f726c640000000000000000000000000000000000000000000081525090509056fea2646970667358221220fa787b95ca91ffe90fdb780b8ee8cb11c474bc63cb8217112c88bc465f7ea7d364736f6c63430007020033";

#[cfg(test)]
mod tests {
    use evm::{Capture, CreateScheme, ExitReason, ExitSucceed, Handler};
    use primitive_types::{H160, H256, U256};
    use sha3::{Digest, Keccak256};

    use tempfile::tempdir;

    use super::Executor;
    use super::*;

    fn name_to_key(name: &str) -> H160 {
        let hash = H256::from_slice(Keccak256::digest(name.as_bytes()).as_slice());
        hash.into()
    }

    #[test]
    fn test_evm_bytecode() {
        let _logger_error = simple_logger::SimpleLogger::new().init();
        let accounts = ["contract", "caller"];

        let code = hex::decode(HELLO_WORLD_CODE).unwrap();
        let data = hex::decode(HELLO_WORLD_ABI).unwrap();

        let tmp_dir = tempdir().unwrap();
        let mut backend = EvmState::load_from(&tmp_dir, Slot::default()).unwrap();

        for acc in &accounts {
            let account = name_to_key(acc);
            let memory = AccountState {
                ..Default::default()
            };
            backend.accounts.insert(account, memory);
        }

        backend.freeze();

        let config = evm::Config::istanbul();
        let mut executor = Executor::with_config(backend.clone(), config, usize::max_value(), 0);

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
                name_to_key("contract"),
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

        let patch = executor.deconstruct();
        backend.swap_commit(patch);

        let contract = backend.get_account(name_to_key("contract"));
        assert_eq!(
            &contract.unwrap().code,
            &hex::decode(HELLO_WORLD_CODE_SAVED).unwrap()
        );
    }

    #[test]
    fn test_freeze_fork_save_storage() {
        let _ = simple_logger::SimpleLogger::new().init();
        let accounts = ["contract", "caller"];

        let state_dir = tempdir().unwrap();
        let mut state = EvmState::new(state_dir.path()).unwrap();

        {
            for acc in &accounts {
                let account = name_to_key(acc);
                let memory = AccountState {
                    ..Default::default()
                };
                state.accounts.insert(account, memory);
            }
        }

        state.freeze();

        let config = evm::Config::istanbul();
        let mut executor = Executor::with_config(state.clone(), config, usize::max_value(), 0);
        let key = H256::random();
        let size = 100;
        let data = vec![0, 1, 2, 3];
        executor.allocate_store(key, size).unwrap();

        let patch = executor.deconstruct();
        state.swap_commit(patch);
        state.freeze();

        let config = evm::Config::istanbul();
        let mut executor = Executor::with_config(state.clone(), config, usize::max_value(), 0);
        executor.publish_data(key, 0, &data).unwrap();

        let patch = executor.deconstruct();

        state.swap_commit(patch);
        state.freeze();

        let config = evm::Config::istanbul();
        let mut executor = Executor::with_config(state.clone(), config, usize::max_value(), 0);
        executor
            .publish_data(key, data.len() as u64, &data)
            .unwrap();

        let patch = executor.deconstruct();

        state.swap_commit(patch);
        state.freeze();

        let config = evm::Config::istanbul();
        let mut executor = Executor::with_config(state.clone(), config, usize::max_value(), 0);
        let result = executor.take_big_tx(key).unwrap();
        assert_eq!(&result[..data.len()], &*data);

        assert_eq!(&result[data.len()..2 * data.len()], &*data)
    }
}
