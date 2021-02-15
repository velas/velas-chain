use std::cell::RefCell;

use solana_sdk::{account::Account, keyed_account::KeyedAccount, pubkey::Pubkey};
#[derive(Copy, Clone, Debug)]
pub struct AccountStructure<'a> {
    pub evm_state: &'a KeyedAccount<'a>,
    pub first_user: &'a KeyedAccount<'a>,
    pub rest: &'a [KeyedAccount<'a>],
}

impl<'a> AccountStructure<'a> {
    pub fn new(
        evm_state: &'a KeyedAccount<'a>,
        users: &'a [KeyedAccount<'a>],
    ) -> Option<AccountStructure<'a>> {
        users
            .split_first()
            .map(|(first_user, rest)| AccountStructure {
                evm_state,
                first_user,
                rest,
            })
    }

    pub fn find_user(&self, key: &Pubkey) -> Option<&KeyedAccount> {
        if self.first_user.unsigned_key() == key {
            return Some(&self.first_user);
        }

        for keyed_account in self.rest {
            if keyed_account.unsigned_key() == key {
                return Some(keyed_account);
            }
        }

        None
    }

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
        let structure = AccountStructure::new(&evm_state, borrowed_keys).unwrap();
        func(structure)
    }
}
