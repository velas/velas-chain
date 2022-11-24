use num_derive::FromPrimitive;
use solana_sdk::program_error::ProgramError;
use thiserror::Error;

#[derive(Clone, Debug, Eq, Error, FromPrimitive, PartialEq)]
pub enum GasStationError {
    /// The account cannot be initialized because it is already being used.
    #[error("Account is already in use")]
    AccountInUse,
    #[error("Account storage isn't uninitialized")]
    AccountNotInitialized,
    #[error("Account info for big transaction storage is missing")]
    BigTxStorageMissing,
    #[error("Unable to deserialize borsh encoded account data")]
    InvalidAccountBorshData,
    #[error("Unable to deserialize big transaction account data")]
    InvalidBigTransactionData,
    #[error("Invalid filter amount")]
    InvalidFilterAmount,
    #[error("Lamport balance below rent-exempt threshold")]
    NotRentExempt,
    #[error("Payer account doesn't match key from payer storage")]
    PayerAccountMismatch,
    #[error("None of payer filters correspond to evm transaction")]
    PayerFilterMismatch,
    #[error("PDA account info doesn't match DPA derived by this program id")]
    PdaAccountMismatch,
}

impl From<GasStationError> for ProgramError {
    fn from(e: GasStationError) -> Self {
        ProgramError::Custom(e as u32)
    }
}
