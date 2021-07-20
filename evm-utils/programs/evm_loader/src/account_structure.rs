use solana_sdk::{keyed_account::KeyedAccount, pubkey::Pubkey};

use crate::error::EvmError;

/// Helper structure that wrap all solana accounts, that is needed for evm loader.
/// It will restrict and provide access to needed solana accounts in:
/// 1. Instruction handlers (ExecuteTx, SwapToEvm, FreeOwnership) - full access to evm state.
/// 2. Builtin contracts (SwapToNative) - Full access to evm state.
/// 3. User written evm2native callbacks (SwapERCToSol, CallSolMethod) - Full access to specific users account,
///   call from users account, read/credit access to evm state. (TBD)
///
#[derive(Copy, Clone, Debug)]
pub struct AccountStructure<'a> {
    pub evm: &'a KeyedAccount<'a>,
    pub users: &'a [KeyedAccount<'a>],
}

impl<'a> AccountStructure<'a> {
    /// Create new account structure, from keyed accounts.
    pub fn new(evm: &'a KeyedAccount<'a>, users: &'a [KeyedAccount<'a>]) -> AccountStructure<'a> {
        AccountStructure { evm, users }
    }

    /// Returns account of the first user.
    pub fn first(&self) -> Option<&KeyedAccount> {
        self.users.first()
    }

    /// Find user by its public key.
    pub fn find_user(&self, key: &Pubkey) -> Option<&KeyedAccount> {
        self.users.iter().find(|keyed| keyed.unsigned_key() == key)
    }

    pub fn refund_fee(&self, user: &'a KeyedAccount<'a>, fee: u64) -> Result<(), EvmError> {
        self.evm
            .try_account_ref_mut()
            .map_err(|_| EvmError::BorrowingFailed)?
            .lamports -= fee;
        user.try_account_ref_mut()
            .map_err(|_| EvmError::BorrowingFailed)?
            .lamports += fee;
        Ok(())
    }

    /// Create AccountStructure for testing purposes, with random accounts.
    #[cfg(test)]
    pub(crate) fn testing<F, U>(num_keys: usize, func: F) -> U
    where
        F: for<'r> Fn(AccountStructure<'r>) -> U,
    {
        use solana_sdk::account::AccountSharedData;
        use std::cell::RefCell;

        let evm_key = Pubkey::new_unique();
        let evm_account = RefCell::new(crate::create_state_account(0));
        let evm_state = KeyedAccount::new(&evm_key, false, &evm_account);

        let keys: Vec<_> = std::iter::repeat_with(|| {
            let user_key = Pubkey::new_unique();
            let user_account = RefCell::new(AccountSharedData {
                lamports: 1000,
                data: vec![],
                owner: crate::ID,
                executable: false,
                rent_epoch: 0,
            });
            (user_key, user_account)
        })
        .take(num_keys + 1)
        .collect();
        let keyed_accounts: Vec<_> = keys
            .iter()
            .map(|(user_key, user_account)| KeyedAccount::new(&user_key, false, &user_account))
            .collect();
        let borrowed_keys: &[_] = &keyed_accounts;
        let structure = AccountStructure::new(&evm_state, borrowed_keys);
        func(structure)
    }
}
