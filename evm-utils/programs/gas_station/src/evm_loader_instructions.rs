use borsh::{BorshDeserialize, BorshSerialize};
use super::evm_types::{Address, Transaction, UnsignedTransaction};

pub const EVM_INSTRUCTION_BORSH_PREFIX: u8 = 255u8;

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq)]
pub enum FeePayerType {
    Evm,
    Native,
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq)]
pub enum EvmBigTransaction {
    /// Allocate data in storage, pay fee should be taken from EVM.
    EvmTransactionAllocate { size: u64 },

    /// Store part of EVM transaction into temporary storage, in order to execute it later.
    EvmTransactionWrite { offset: u64, data: Vec<u8> },
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq)]
pub enum ExecuteTransaction {
    Signed {
        tx: Option<Transaction>,
    },
    ProgramAuthorized {
        tx: Option<UnsignedTransaction>,
        from: Address,
    },
}

#[allow(clippy::large_enum_variant)]
#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq)]
pub enum EvmInstruction {
    /// Transfer native lamports to ethereum.
    ///
    /// Outer args:
    /// account_key[0] - `[writable]`. EVM state account, used for lock.
    /// account_key[1] - `[writable, signer]`. Owner account that's allowed to manage withdrawal of his account by transfering ownership.
    ///
    /// Inner args:
    /// amount - count of lamports to be transfered.
    /// ether_key - recevier etherium address.
    ///
    SwapNativeToEther {
        lamports: u64,
        evm_address: Address,
    },

    /// Transfer user account ownership back to system program.
    ///
    /// Outer args:
    /// account_key[0] - `[writable]`. EVM state account, used for lock.
    /// account_key[1] - `[writable, signer]`. Owner account that's allowed to manage withdrawal of his account by transfering ownership.
    ///
    FreeOwnership {},

    /// Allocate / push data / execute Big Transaction
    ///
    /// Outer args:
    /// account_key[0] - `[writable]`. EVM state account. used for lock.
    /// account_key[1] - `[writable]`. Big Transaction data storage.
    EvmBigTransaction(EvmBigTransaction),

    /// Execute native EVM transaction
    ///
    /// Outer args:
    /// account_key[0] - `[writable]`. EVM state account, used for lock.
    /// account_key[1] - `[readable]`. Optional argument, used in case tokens swaps from EVM back to native.
    ///
    /// Outer args (Big tx case):
    /// account_key[0] - `[writable]`. EVM state account. used for lock.
    /// account_key[1] - `[writable]`. Big Transaction data storage.
    ///
    /// Inner args:
    /// tx - information about transaction execution:
    ///   who authorized and whether or not should we get transaction from account data storage
    /// fee_type - which side will be used for charging fee: Native or Evm
    ExecuteTransaction {
        tx: ExecuteTransaction,
        fee_type: FeePayerType,
    },
}