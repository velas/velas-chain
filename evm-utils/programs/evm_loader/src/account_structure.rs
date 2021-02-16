use std::cell::RefCell;

use solana_sdk::{account::Account, keyed_account::KeyedAccount, pubkey::Pubkey};
#[derive(Copy, Clone, Debug)]
/// Helper structure that wrap all solana accounts, that is needed for evm loader.
/// It will restrict and provide access to needed solana accounts in:
/// 1. Instruction handlers (ExecuteTx, SwapToEvm, FreeOwnership) - full access to evm state.
/// 2. Builtin contracts (SwapToNative) - Full access to evm state.
/// 3. User written evm2native callbacks (SwapERCToSol, CallSolMethod) - Full access to specific users account,
///   call from users account, read/credit access to evm state. (TBD)
///
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
    pub fn user(&self) -> Option<&KeyedAccount> {
        self.users.get(0)
    }

    /// Find user by its public key.
    pub fn find_user(&self, key: &Pubkey) -> Option<&KeyedAccount> {
        for keyed_account in self.users {
            if keyed_account.unsigned_key() == key {
                return Some(keyed_account);
            }
        }

        None
    }

    /// Create AccountStructure for testing purposes, with random accounts.
    pub(crate) fn testing<F, U>(num_keys: usize, func: F) -> U
    where
        F: for<'r> Fn(AccountStructure<'r>) -> U,
    {
        let evm_key = Pubkey::new_unique();
        let evm_account = RefCell::new(crate::create_state_account());
        let evm_state = KeyedAccount::new(&evm_key, false, &evm_account);

        let keys: Vec<_> = (0..(num_keys + 1))
            .into_iter()
            .map(|_| {
                let user_key = Pubkey::new_unique();
                let user_account = RefCell::new(Account {
                    lamports: 1000,
                    data: vec![],
                    owner: crate::ID,
                    executable: false,
                    rent_epoch: 0,
                });
                (user_key, user_account)
            })
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
