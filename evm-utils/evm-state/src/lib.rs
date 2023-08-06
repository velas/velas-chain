pub use {
    evm::{
        backend::{Apply, ApplyBackend, Backend, Log, MemoryAccount, MemoryVicinity},
        executor::stack::StackExecutor,
        CallScheme, Config, Context, CreateScheme, ExitError, ExitFatal, ExitReason, ExitRevert,
        ExitSucceed, Handler, Opcode, Transfer,
    },
    primitive_types::{H256, U256},
    secp256k1::{self, rand},
};

pub mod error;
pub mod storage;
pub mod traces;
pub mod transactions;
pub mod types;

pub use {
    context::{ChainContext, EvmConfig},
    ethbloom::Bloom,
    executor::{
        ExecutionResult, Executor, PrecompileCallResult, HELLO_WORLD_ABI, HELLO_WORLD_CODE,
        HELLO_WORLD_CODE_SAVED, HELLO_WORLD_RESULT, MAX_TX_LEN, TEST_CHAIN_ID, TX_MTU,
    },
    state::{
        AccountProvider, ChangedState, Committed, EvmBackend, EvmPersistState, EvmState, Incomming,
        BURN_GAS_PRICE, DEFAULT_GAS_LIMIT, MAX_IN_HEAP_EVM_ACCOUNTS_BYTES,
        MAX_IN_MEMORY_EVM_ACCOUNTS,
    },
    storage::{Storage, StorageSecondary},
    traces::*,
    transactions::*,
    triedb::empty_trie_hash,
    types::*,
};

mod context;
pub mod executor;
mod state;

// Cannot link to solana-sdk, because solana_sdk already linked to evm-state
// Used in BlockHeader
#[path = "../../../sdk/src/deserialize_utils.rs"]
mod deserialize_utils;

pub trait FromKey {
    fn to_public_key(&self) -> secp256k1::PublicKey;
    fn to_address(&self) -> crate::Address;
}

impl FromKey for secp256k1::SecretKey {
    fn to_public_key(&self) -> secp256k1::PublicKey {
        secp256k1::PublicKey::from_secret_key(secp256k1::SECP256K1, self)
    }
    fn to_address(&self) -> crate::Address {
        addr_from_public_key(&secp256k1::PublicKey::from_secret_key(
            secp256k1::SECP256K1,
            self,
        ))
    }
}
