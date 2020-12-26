use super::scope::*;
use serde::{Deserialize, Serialize};

#[derive(Debug, PartialEq, Eq, Ord, PartialOrd, Serialize, Deserialize)]
pub enum EvmInstruction {
    /// Execute native evm transaction.
    ///
    ///
    EvmTransaction { evm_tx: evm::Transaction },
    /// Transfer native lamports to ethereum.
    ///
    /// Outer args:
    /// account_key[0] - `[writable]. Evm state account, used for lock.
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
    /// account_key[0] - `[writable]. Evm state account, used for lock.
    /// account_key[1] - `[writable, signer]`. Owner account that's allowed to manage withdrawal of his account by transfering ownership.
    ///
    FreeOwnership {},
    // / Transfer gweis to solana lamports.
    // /
    // / Outer args:
    // / account_key[0] - `[writable]. Evm state account, used for lock.
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
