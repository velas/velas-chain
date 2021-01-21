use super::scope::*;
use evm_state::H256;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};

/// Solana blockchain limit amount of data that transaction can have.
/// To get around this limitation, we use design that is similar to LoaderInstruction in sdk.

#[derive(Debug, PartialEq, Eq, Ord, PartialOrd, Serialize, Deserialize)]
pub enum EvmBigTransaction {
    /// Allocate data in storage, pay fee should be taken from evm.
    EvmTransactionAllocate {
        seed: H256,
        len: u64,
        _pay_for_data: Option<evm::Transaction>,
    },

    /// Store part of evm transaction into temporary storage, in order to execute it later.
    EvmTransactionWrite {
        seed: H256,
        offset: u64,
        data: Vec<u8>,
    },

    /// Execute merged transaction, in order to do this, user should make sure that transaction is successfully writed.
    EvmTransactionExecute { seed: H256 },
}

impl EvmBigTransaction {
    fn seed(&self) -> &H256 {
        match self {
            EvmBigTransaction::EvmTransactionAllocate { seed, .. } => seed,
            EvmBigTransaction::EvmTransactionWrite { seed, .. } => seed,
            EvmBigTransaction::EvmTransactionExecute { seed } => seed,
        }
    }

    pub fn get_key(&self, bridge_key: solana::Address) -> H256 {
        let mut hash = Keccak256::new();
        hash.update(self.seed().as_bytes());
        hash.update(&bridge_key.to_bytes());
        H256::from_slice(hash.finalize().as_slice())
    }
}

#[derive(Debug, PartialEq, Eq, Ord, PartialOrd, Serialize, Deserialize)]
pub enum EvmInstruction {
    /// Execute native evm transaction.
    ///
    ///
    EvmTransaction {
        evm_tx: evm::Transaction,
    },
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

    EvmBigTransaction(EvmBigTransaction),
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
