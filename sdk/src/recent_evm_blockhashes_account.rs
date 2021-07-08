use crate::account::{
    create_account_shared_data_with_fields, to_account, AccountSharedData, InheritableAccountFields,
};

use crate::hash::Hash;

use solana_program::sysvar::recent_evm_blockhashes::{RecentBlockhashes, MAX_ENTRIES};

pub fn update_account(
    account: &mut AccountSharedData,
    recent_blockhashes: [Hash; MAX_ENTRIES],
) -> Option<()> {
    let recent_blockhashes: RecentBlockhashes = RecentBlockhashes(recent_blockhashes);
    to_account(&recent_blockhashes, account)
}

pub fn create_account_with_data_and_fields(
    fields: InheritableAccountFields,
    recent_blockhashes: [Hash; MAX_ENTRIES],
) -> AccountSharedData {
    let mut account = create_account_shared_data_with_fields::<RecentBlockhashes>(
        &RecentBlockhashes::default(),
        fields,
    );
    update_account(&mut account, recent_blockhashes).unwrap();
    account
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::from_account;
    use crate::clock::INITIAL_RENT_EPOCH;
    use solana_program::hash::{Hash, HASH_BYTES};

    #[test]
    fn test_create_account() {
        let mut blocks: [Hash; MAX_ENTRIES] = [Hash::default(); MAX_ENTRIES];

        blocks
            .iter_mut()
            .enumerate()
            .take(MAX_ENTRIES)
            .for_each(|(i, entry)| {
                // create hash with visibly recognizable ordering
                let mut h = [0; HASH_BYTES];
                h[HASH_BYTES - 1] = i as u8;
                *entry = Hash::new(&h);
            });

        let account = create_account_with_data_and_fields((42, INITIAL_RENT_EPOCH), blocks);
        let recent_blockhashes = from_account::<RecentBlockhashes, _>(&account).unwrap();

        assert_eq!(recent_blockhashes.0, blocks);
    }
}
