use super::scope::*;
use serde::{Deserialize, Serialize};
use solana_sdk::instruction::InstructionError;

#[derive(Debug, PartialEq, Eq, Ord, PartialOrd, Serialize, Deserialize)]
pub enum EvmInstruction {
    /// Execute native evm transaction.
    ///
    ///
    EvmTransaction { evm_tx: evm::Transaction },

    /// Create Intermediate account, to allow evm manage your native tokens.
    ///
    /// Outer args:
    ///
    ///
    CreateDepositAccount { pubkey: solana::Address },
    /// Transfer native lamports to ethereum.
    ///
    /// Outer args:
    /// account_key[0] - `[writable, signer]`.
    /// account_key[1] - `[writable]`. Account that should be created with CreateDepositAccount
    ///
    /// Inner args:
    /// amount - count of lamports to be transfered.
    /// ether_key - recevier etherium address.
    SwapNativeToEther {
        lamports: u64,
        ether_address: evm::Address,
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

/// Mint data.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, Default, PartialEq)]
pub struct Deposit {
    pub deposit_authority: Option<solana::Address>,
    pub locked_lamports: u64,
    pub is_initialized: bool,
}

impl Deposit {
    pub const LEN: usize = 42;

    pub fn get_owner(&self) -> Result<solana::Address, InstructionError> {
        self.deposit_authority
            .ok_or(InstructionError::AccountBorrowFailed)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn test_len() {
        let deposit = Deposit {
            deposit_authority: Some(solana::Address::default()),
            locked_lamports: 123,
            is_initialized: true,
        };
        let data = bincode::serialize(&deposit).unwrap();
        assert_eq!(data.len(), Deposit::LEN)
    }
}
