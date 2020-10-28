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
    /// account_key[0] - `[writable, signer]`.
    ///
    /// Inner args:
    /// amount - count of lamports to be transfered.
    /// ether_key - recevier etherium address.
    SwapNativeToEther {
        amount: u64,
        ether_key: evm::Address,
    },
    // TODO: Transfer eth to sol back

    // /// Transfer native lamports to ethereum.
    // ///
    // /// Outer args:
    // /// account_key[0] - `[]`.
    // ///
    // /// Inner args:
    // /// amount - count of lamports to be transfered.
    // /// ether_key - etherium address.
    // SwapEtherToNative {
    //     amount: u64,
    //     ether_key: evm::Address,
    //     account_key: solana::Address,
    //     ether_signature: evm::Signature,
    // }
}
