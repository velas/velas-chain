use {
    derivative::Derivative,
    evm::ExitFatal,
    primitive_types::{H256, U256},
    snafu::{Backtrace, Snafu},
};

#[derive(Derivative, Debug, Snafu)]
#[derivative(PartialEq)]
#[snafu(visibility(pub(crate)))]
#[snafu(context(suffix(false)))]
pub enum Error {
    #[snafu(display(
        "Failed to recover tx sender pubkey {:x}: {}",
        transaction_hash,
        source
    ))]
    UnrecoverableCaller {
        transaction_hash: H256,
        source: secp256k1::Error,
    },

    #[snafu(display(
        "Transaction nonce {} differs from nonce in state {}",
        tx_nonce,
        state_nonce
    ))]
    NonceNotEqual { tx_nonce: U256, state_nonce: U256 },

    #[snafu(display(
        "Fatal evm error while executing tx {:x}: {:?}",
        transaction_hash,
        evm_source
    ))]
    EvmFatal {
        transaction_hash: H256,
        evm_source: ExitFatal,
    },

    #[snafu(display("Failed to allocate {} bytes: key={:x}", size, key))]
    AllocationError {
        key: H256,
        size: u64,
        #[derivative(PartialEq = "ignore")]
        backtrace: Backtrace,
    },

    #[snafu(display("Data not found: key={:x}", key))]
    DataNotFound {
        key: H256,
        #[derivative(PartialEq = "ignore")]
        backtrace: Backtrace,
    },

    #[snafu(display("Failed to write at offset {}: key={:x}", offset, key))]
    FailedToWrite {
        key: H256,
        offset: u64,
        #[derivative(PartialEq = "ignore")]
        backtrace: Backtrace,
    },

    #[snafu(display(
        "Write at offset {} out of bounds, with len {}: key={:x}",
        offset,
        size,
        key
    ))]
    OutOfBound {
        key: H256,
        offset: u64,
        size: u64,
        #[derivative(PartialEq = "ignore")]
        backtrace: Backtrace,
    },

    #[snafu(display(
        "Wrong chain id, expected={}, but tx provide={:?}",
        chain_id,
        tx_chain_id,
    ))]
    WrongChainId {
        chain_id: u64,
        tx_chain_id: Option<u64>,
    },

    #[snafu(display(
        "Gas limit should not exceed U64::MAX, provided_gas_limit={}",
        gas_limit,
    ))]
    GasLimitOutOfBounds { gas_limit: U256 },

    #[snafu(display("Gas used={} exceed gas_limit={}", used_gas, gas_limit,))]
    GasUsedOutOfBounds { used_gas: U256, gas_limit: U256 },
    #[snafu(display(
        "Gas price should not exceed U64::MAX, and be more than BURN_GAS_PRICE({}), provided_gas_price={}",
        crate::BURN_GAS_PRICE,
        gas_price,
    ))]
    GasPriceOutOfBounds { gas_price: U256 },

    #[snafu(display("Transaction with this hash already executed, tx_hash={:?}", tx_hash,))]
    DuplicateTx { tx_hash: H256 },

    #[snafu(display(
        "User cant pay the bills state_balance={} transaction.value={}, transaction_max_fee={}",
        state_balance,
        value,
        max_fee,
    ))]
    CantPayTheBills {
        state_balance: U256,
        value: U256,
        max_fee: U256,
    },

    #[snafu(display(
        "Gas limit in config = exceed used gas gas_limit={}, gas_used={}",
        gas_limit,
        gas_used,
    ))]
    GasLimitConfigAssert { gas_limit: u64, gas_used: u64 },
}
