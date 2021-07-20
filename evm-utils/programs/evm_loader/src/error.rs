use num_derive::{FromPrimitive, ToPrimitive};

use snafu::Snafu;
/// Reasons the stake might have had an error
#[derive(Error, Debug, Clone, PartialEq, FromPrimitive, ToPrimitive, Snafu)]
pub enum EvmError {
    #[snafu(display("Cross-Program evm execution not enabled."))]
    CrossExecutionNotEnabled,

    #[snafu(display("InvokeContext didn't provide evm executor."))]
    NoEvmExecutorFound,

    #[snafu(display("Recursive cross-program evm execution not enabled."))]
    RecursiveCrossExecution,
    
    #[snafu(display("Internal executor error."))]
    InternalExecutorError,
    
    #[snafu(display("Internal transaction error."))]
    InternalTransactionError,

    #[snafu(display("Recursive cross-program evm execution not enabled."))]
    RecursiveCrossExecution,

    
}

impl<E> DecodeError<E> for StakeError {
    fn type_of() -> &'static str {
        "EvmError"
    }
}
