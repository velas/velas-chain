use crate::account::{create_account, to_account, Account};
use crate::hash::Hash;
use solana_program::sysvar::recent_evm_blockhashes::{RecentBlockhashes, MAX_ENTRIES};

pub fn update_account(
    account: &mut Account,
    recent_blockhashes: [Hash; MAX_ENTRIES],
) -> Option<()> {
    let recent_blockhashes: RecentBlockhashes = RecentBlockhashes(recent_blockhashes);
    to_account(&recent_blockhashes, account)
}

pub fn create_account_with_data(lamports: u64, recent_blockhashes: [Hash; MAX_ENTRIES]) -> Account {
    let mut account = create_account::<RecentBlockhashes>(&RecentBlockhashes::default(), lamports);
    update_account(&mut account, recent_blockhashes).unwrap();
    account
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::from_account;
    use solana_program::hash::{Hash, HASH_BYTES};

    #[test]
    fn test_create_account() {
        let mut blocks: [Hash; MAX_ENTRIES] = [Hash::default(); MAX_ENTRIES];

        for i in 0..MAX_ENTRIES {
            // create hash with visibly recognizable ordering
            let mut h = [0; HASH_BYTES];
            h[HASH_BYTES - 1] = i as u8;
            blocks[i] = Hash::new(&h)
        }

        let account = create_account_with_data(42, blocks);
        let recent_blockhashes = from_account::<RecentBlockhashes>(&account).unwrap();

        assert_eq!(recent_blockhashes.0, blocks);
    }
}
