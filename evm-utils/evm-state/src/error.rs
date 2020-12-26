use snafu::{Backtrace, Snafu};

use evm::ExitFatal;
use primitive_types::H256;

#[derive(Debug, Snafu)]
#[snafu(visibility = "pub(crate)")]
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
        backtrace: Backtrace,
    },

    #[snafu(display("Data not found: key={:x}", key))]
    DataNotFound { key: H256, backtrace: Backtrace },

    #[snafu(display("Failed to write at offset {}: key={:x}", offset, key))]
    FailedToWrite {
        key: H256,
        offset: u64,
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
        backtrace: Backtrace,
    },
}
