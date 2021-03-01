use super::scope::*;
use serde::{Deserialize, Serialize};

/// Solana blockchain limit amount of data that transaction can have.
/// To get around this limitation, we use design that is similar to LoaderInstruction in sdk.

#[derive(Debug, PartialEq, Eq, Ord, PartialOrd, Serialize, Deserialize)]
pub enum EvmBigTransaction {
    /// Allocate data in storage, pay fee should be taken from evm.
    EvmTransactionAllocate { size: u64 },

    /// Store part of evm transaction into temporary storage, in order to execute it later.
    EvmTransactionWrite { offset: u64, data: Vec<u8> },

    /// Execute merged transaction, in order to do this, user should make sure that transaction is successfully writed.
    EvmTransactionExecute {},
}

#[derive(Debug, PartialEq, Eq, Ord, PartialOrd, Serialize, Deserialize)]
pub enum EvmInstruction {
    /// Execute native evm transaction.
    ///
    /// Outer args:
    /// account_key[0] - `[writable]`. EVM state account, used for lock.
    /// account_key[1] - `[readable]`. Optional argument, used in case tokens swaps from evm back to native.
    ///
    EvmTransaction { evm_tx: evm::Transaction },

    /// Transfer native lamports to ethereum.
    ///
    /// Outer args:
    /// account_key[0] - `[writable]`. Evm state account, used for lock.
    /// account_key[1] - `[writable, signer]`. Owner account that's allowed to manage withdrawal of his account by transfering ownership.
    ///
    /// Inner args:
    /// amount - count of lamports to be transfered.
    /// ether_key - recevier etherium address.
    ///
    SwapNativeToEther {
        lamports: u64,
        ether_address: evm::Address,
    },

    /// Transfer user account ownership back to system program.
    ///
    /// Outer args:
    /// account_key[0] - `[writable]`. Evm state account, used for lock.
    /// account_key[1] - `[writable, signer]`. Owner account that's allowed to manage withdrawal of his account by transfering ownership.
    ///
    FreeOwnership {},

    /// Allocate / push data / execute Big Transaction
    ///
    /// Outer args:
    /// account_key[0] - `[writable]`. EVM state account. used for lock.
    /// account_key[1] - `[writable]`. Big Transaction data storage.
    EvmBigTransaction(EvmBigTransaction),
    // / Transfer gweis to solana lamports.
    // /
    // / Outer args:
    // / account_key[0] - `[writable]`. Evm state account, used for lock.
    // / account_key[1] - `[writable, signer]`. Owner account that's allowed to manage withdrawal of his account by transfering ownership.
    // /
    // / Inner args:
    // / amount - count of lamports to be transfered.
    // / ether_key - recevier etherium address.
    // /
    // SwapEtherToNative {
    //     amount: u64,
    //     ether_key: evm::Address,
    //     account_key: solana::Address,
    //     ether_signature: evm::Signature,
    // }
}
