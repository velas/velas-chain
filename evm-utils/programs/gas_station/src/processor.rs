use super::*;
use borsh::{BorshDeserialize, BorshSerialize};
use solana_evm_loader_program::scope::evm;
use solana_program::{program_memory::sol_memcmp, pubkey::PUBKEY_BYTES};
use solana_sdk::{
    account_info::{next_account_info, AccountInfo},
    entrypoint::ProgramResult,
    instruction::{AccountMeta, Instruction},
    msg,
    program::invoke_signed,
    program_error::ProgramError,
    program_pack::IsInitialized,
    pubkey::Pubkey,
    rent::Rent,
    system_instruction,
    sysvar::Sysvar,
};

use error::GasStationError;
use evm_rpc::Either;
use instruction::{GasStationInstruction, TxFilter};
use state::{Payer, MAX_FILTERS};

const EXECUTE_CALL_REFUND_AMOUNT: u64 = 10000;

pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    let ix = BorshDeserialize::deserialize(&mut &*instruction_data)
        .map_err(|_| ProgramError::InvalidInstructionData)?;

    match ix {
        GasStationInstruction::RegisterPayer {
            owner,
            transfer_amount,
            whitelist,
        } => process_register_payer(program_id, accounts, owner, transfer_amount, whitelist),
        GasStationInstruction::ExecuteWithPayer { tx } => {
            process_execute_with_payer(program_id, accounts, tx)
        }
    }
}

fn process_register_payer(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    owner: Pubkey,
    transfer_amount: u64,
    whitelist: Vec<TxFilter>,
) -> ProgramResult {
    if whitelist.is_empty() || whitelist.len() > MAX_FILTERS {
        return Err(GasStationError::InvalidFilterAmount.into());
    }
    let account_info_iter = &mut accounts.iter();
    let creator_info = next_account_info(account_info_iter)?;
    let storage_acc_info = next_account_info(account_info_iter)?;
    let payer_acc_info = next_account_info(account_info_iter)?;
    let system_program = next_account_info(account_info_iter)?;

    let mut payer: Payer = BorshDeserialize::deserialize(&mut &**storage_acc_info.data.borrow())
        .map_err(|_e| -> ProgramError { GasStationError::InvalidAccountBorshData.into() })?;
    if payer.is_initialized() {
        return Err(GasStationError::AccountInUse.into());
    }

    let rent = Rent::get()?;
    let payer_data_len = storage_acc_info.data_len();
    if !rent.is_exempt(storage_acc_info.lamports(), payer_data_len) {
        return Err(ProgramError::AccountNotRentExempt);
    }

    let (payer_acc, bump_seed) = Pubkey::find_program_address(&[owner.as_ref()], program_id);
    let rent_lamports = rent.minimum_balance(0);
    invoke_signed(
        &system_instruction::create_account(
            creator_info.key,
            &payer_acc,
            rent_lamports + transfer_amount,
            0,
            program_id,
        ),
        &[
            creator_info.clone(),
            payer_acc_info.clone(),
            system_program.clone(),
        ],
        &[&[owner.as_ref(), &[bump_seed]]],
    )?;
    msg!("PDA created: {}", payer_acc);

    payer.owner = owner;
    payer.payer = payer_acc;
    payer.filters = whitelist;
    BorshSerialize::serialize(&payer, &mut &mut storage_acc_info.data.borrow_mut()[..]).unwrap();
    Ok(())
}

fn process_execute_with_payer(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    tx: Option<evm::Transaction>,
) -> ProgramResult {
    let account_info_iter = &mut accounts.iter();
    let sender = next_account_info(account_info_iter)?;
    let payer_storage_info = next_account_info(account_info_iter)?;
    let payer_info = next_account_info(account_info_iter)?;
    let evm_loader = next_account_info(account_info_iter)?;
    let evm_state = next_account_info(account_info_iter)?;
    let system_program = next_account_info(account_info_iter)?;

    let (unpacked_tx, big_tx_storage_info) = match tx.as_ref() {
        None => {
            let big_tx_storage_info = next_account_info(account_info_iter)?;
            (get_big_tx_from_storage(big_tx_storage_info)?, Some(big_tx_storage_info))
        }
        Some(tx) => (tx.clone(), None),
    };

    if !cmp_pubkeys(program_id, payer_storage_info.owner) {
        return Err(ProgramError::IncorrectProgramId);
    }
    let mut payer_data_buf: &[u8] = &**payer_storage_info.data.borrow();
    let payer: Payer = BorshDeserialize::deserialize(&mut payer_data_buf)
        .map_err(|_e| -> ProgramError { GasStationError::InvalidAccountBorshData.into() })?;
    if !payer.is_initialized() {
        return Err(GasStationError::AccountNotInitialized.into());
    }
    if !payer_data_buf.is_empty() {
        return Err(GasStationError::InvalidAccountBorshData.into());
    }
    if payer.payer != *payer_info.key {
        return Err(GasStationError::PayerAccountMismatch.into());
    }
    if !payer.do_filter_match(&unpacked_tx) {
        return Err(GasStationError::PayerFilterMismatch.into());
    }

    {
        let (_payer_acc, bump_seed) =
            Pubkey::find_program_address(&[payer.owner.as_ref()], program_id);
        let signers_seeds: &[&[&[u8]]] = &[&[payer.owner.as_ref(), &[bump_seed]]];
        // pass sender acc to evm loader, execute tx restore ownership
        payer_info.assign(&solana_sdk::evm_loader::ID);

        let ix = make_evm_loader_execute_ix(*evm_loader.key, *evm_state.key, *payer_info.key, tx.map_or_else(|| Either::Right(*big_tx_storage_info.unwrap().key), |tx| Either::Left(tx)));
        let account_infos = match big_tx_storage_info {
            Some(big_tx_storage_info) => vec![evm_loader.clone(), big_tx_storage_info.clone(), evm_state.clone(), payer_info.clone()],
            None => vec![evm_loader.clone(), evm_state.clone(), payer_info.clone()],
        };
        invoke_signed(&ix, &account_infos, signers_seeds)?;

        let ix = solana_evm_loader_program::free_ownership(*payer_info.key);
        let account_infos = vec![evm_loader.clone(), evm_state.clone(), payer_info.clone()];
        invoke_signed(&ix, &account_infos, signers_seeds)?;

        let ix = system_instruction::assign(payer_info.key, &program_id);
        let account_infos = vec![system_program.clone(), payer_info.clone()];
        invoke_signed(&ix, &account_infos, signers_seeds)?;
    }

    let refund_amount = EXECUTE_CALL_REFUND_AMOUNT;
    refund_native_fee(sender, payer_info, refund_amount)
}

pub fn cmp_pubkeys(a: &Pubkey, b: &Pubkey) -> bool {
    sol_memcmp(a.as_ref(), b.as_ref(), PUBKEY_BYTES) == 0
}

fn get_big_tx_from_storage(storage_acc: &AccountInfo) -> Result<evm::Transaction, ProgramError> {
    let mut bytes: &[u8] = &storage_acc.try_borrow_data().unwrap();
    msg!("Trying to deserialize tx chunks byte = {:?}", bytes);
    BorshDeserialize::deserialize(&mut bytes)
        .map_err(|_e| GasStationError::InvalidBigTransactionData.into())
}

fn make_evm_loader_execute_ix(
    evm_loader: Pubkey,
    evm_state: Pubkey,
    sender: Pubkey,
    tx: Either<evm::Transaction, Pubkey>,
) -> Instruction {
    use solana_evm_loader_program::instructions::*;
    let (tx, accounts) = match tx {
        Either::Left(tx) => (Some(tx), vec![
            AccountMeta::new(evm_state, false),
            AccountMeta::new(sender, true),
        ]),
        Either::Right(big_tx_storage_key) => (None, vec![
            AccountMeta::new(evm_state, false),
            AccountMeta::new(big_tx_storage_key, true),
            AccountMeta::new(sender, true),
        ]),
    };
    solana_evm_loader_program::create_evm_instruction_with_borsh(
        evm_loader,
        &EvmInstruction::ExecuteTransaction {
            tx: ExecuteTransaction::Signed { tx },
            fee_type: FeePayerType::Native,
        },
        accounts,
    )
}

fn refund_native_fee(caller: &AccountInfo, payer: &AccountInfo, amount: u64) -> ProgramResult {
    **payer.try_borrow_mut_lamports()? -= amount;
    **caller.try_borrow_mut_lamports()? += amount;
    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;
    use solana_program::instruction::InstructionError::{Custom, IncorrectProgramId};
    use solana_program_test::{processor, ProgramTest};
    use solana_sdk::{
        account::Account,
        signature::{Keypair, Signer},
        system_program,
        transaction::{Transaction, TransactionError::InstructionError},
        transport::TransportError::TransactionError,
    };

    const SECRET_KEY_DUMMY: [u8; 32] = [1; 32];
    const TEST_CHAIN_ID: u64 = 0xdead;

    pub fn dummy_eth_tx(contract: evm::H160, input: Vec<u8>) -> evm::Transaction {
        evm::UnsignedTransaction {
            nonce: evm::U256::zero(),
            gas_price: evm::U256::zero(),
            gas_limit: evm::U256::zero(),
            action: evm::TransactionAction::Call(contract),
            value: evm::U256::zero(),
            input,
        }
        .sign(
            &evm::SecretKey::from_slice(&SECRET_KEY_DUMMY).unwrap(),
            Some(TEST_CHAIN_ID),
        )
    }

    #[ignore]
    #[tokio::test]
    async fn test_register_payer() {
        let program_id = Pubkey::new_unique();

        let mut program_test =
            ProgramTest::new("gas-station", program_id, processor!(process_instruction));

        let creator = Keypair::new();
        program_test.add_account(
            creator.pubkey(),
            Account {
                lamports: 10000000,
                ..Account::default()
            },
        );

        let (mut banks_client, _, recent_blockhash) = program_test.start().await;

        let (storage, _) =
            Pubkey::find_program_address(&[creator.pubkey().as_ref(), &[0]], &program_id);
        let (payer, _) =
            Pubkey::find_program_address(&[creator.pubkey().as_ref(), &[1]], &program_id);
        let account_metas = vec![
            AccountMeta::new(creator.pubkey(), true),
            AccountMeta::new(storage, false),
            AccountMeta::new(payer, false),
            AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
        ];
        let ix = Instruction::new_with_borsh(
            program_id,
            &GasStationInstruction::RegisterPayer {
                owner: creator.pubkey(),
                transfer_amount: 0,
                whitelist: vec![TxFilter::InputStartsWith {
                    contract: evm::Address::zero(),
                    input_prefix: vec![],
                }],
            },
            account_metas,
        );
        let mut transaction = Transaction::new_with_payer(&[ix], Some(&creator.pubkey()));
        transaction.sign(&[&creator], recent_blockhash);
        banks_client.process_transaction(transaction).await.unwrap();
    }

    #[tokio::test]
    async fn test_execute_tx() {
        let program_id = Pubkey::new_unique();
        let mut program_test =
            ProgramTest::new("gas-station", program_id, processor!(process_instruction));

        let user = Keypair::new();
        let owner = Keypair::new();
        let storage = Keypair::new();
        let (payer, _) = Pubkey::find_program_address(&[owner.pubkey().as_ref()], &program_id);
        program_test.add_account(
            user.pubkey(),
            Account::new(1000000, 0, &system_program::id()),
        );
        program_test.add_account(payer, Account::new(1000000, 0, &program_id));
        program_test.add_account(
            solana_sdk::evm_state::ID,
            solana_evm_loader_program::create_state_account(1000000).into(),
        );
        let payer_data = Payer {
            owner: owner.pubkey(),
            payer,
            filters: vec![TxFilter::InputStartsWith {
                contract: evm::Address::zero(),
                input_prefix: vec![],
            }],
        };
        let mut payer_bytes = vec![];
        BorshSerialize::serialize(&payer_data, &mut payer_bytes).unwrap();
        program_test.add_account(
            storage.pubkey(),
            Account {
                lamports: 10000000,
                owner: program_id,
                data: payer_bytes,
                ..Account::default()
            },
        );

        let (mut banks_client, _, recent_blockhash) = program_test.start().await;

        let account_metas = vec![
            AccountMeta::new(user.pubkey(), true),
            AccountMeta::new(storage.pubkey(), false),
            AccountMeta::new(payer, false),
            AccountMeta::new_readonly(solana_sdk::evm_loader::ID, false),
            AccountMeta::new(solana_sdk::evm_state::ID, false),
            AccountMeta::new_readonly(system_program::id(), false),
        ];
        let ix = Instruction::new_with_borsh(
            program_id,
            &GasStationInstruction::ExecuteWithPayer {
                tx: Some(dummy_eth_tx(evm::H160::zero(), vec![])),
            },
            account_metas,
        );
        let mut transaction = Transaction::new_with_payer(&[ix], Some(&user.pubkey()));
        transaction.sign(&[&user], recent_blockhash);
        banks_client.process_transaction(transaction).await.unwrap();
    }

    #[tokio::test]
    async fn test_execute_big_tx() {
        let program_id = Pubkey::new_unique();
        let mut program_test =
            ProgramTest::new("gas-station", program_id, processor!(process_instruction));

        let user = Keypair::new();
        let owner = Keypair::new();
        let storage = Keypair::new();
        let big_tx_storage = Keypair::new();
        let (payer, _) = Pubkey::find_program_address(&[owner.pubkey().as_ref()], &program_id);
        program_test.add_account(
            user.pubkey(),
            Account::new(1000000, 0, &system_program::id()),
        );
        program_test.add_account(payer, Account::new(1000000, 0, &program_id));
        program_test.add_account(
            solana_sdk::evm_state::ID,
            solana_evm_loader_program::create_state_account(1000000).into(),
        );
        let payer_data = Payer {
            owner: owner.pubkey(),
            payer,
            filters: vec![TxFilter::InputStartsWith {
                contract: evm::Address::zero(),
                input_prefix: vec![],
            }],
        };
        let mut payer_bytes = vec![];
        BorshSerialize::serialize(&payer_data, &mut payer_bytes).unwrap();
        program_test.add_account(
            storage.pubkey(),
            Account {
                lamports: 10000000,
                owner: program_id,
                data: payer_bytes,
                ..Account::default()
            },
        );
        let big_tx = dummy_eth_tx(evm::H160::zero(), vec![0; 1000]);
        let mut big_tx_bytes = vec![];
        BorshSerialize::serialize(&big_tx, &mut big_tx_bytes).unwrap();
        program_test.add_account(
            big_tx_storage.pubkey(),
            Account {
                lamports: 10000000,
                owner: solana_evm_loader_program::ID,
                data: big_tx_bytes,
                ..Account::default()
            },
        );

        let (mut banks_client, _, recent_blockhash) = program_test.start().await;
        let account_metas = vec![
            AccountMeta::new(user.pubkey(), true),
            AccountMeta::new(storage.pubkey(), false),
            AccountMeta::new(payer, false),
            AccountMeta::new_readonly(solana_sdk::evm_loader::ID, false),
            AccountMeta::new(solana_sdk::evm_state::ID, false),
            AccountMeta::new_readonly(system_program::id(), false),
            AccountMeta::new(big_tx_storage.pubkey(), true),
        ];
        let ix = Instruction::new_with_borsh(
            program_id,
            &GasStationInstruction::ExecuteWithPayer { tx: None },
            account_metas,
        );
        let mut transaction = Transaction::new_with_payer(&[ix], Some(&user.pubkey()));
        transaction.sign(&[&user, &big_tx_storage], recent_blockhash);
        banks_client.process_transaction(transaction).await.unwrap();
    }

    #[tokio::test]
    async fn test_invalid_storage_account_owner() {
        let program_id = Pubkey::new_unique();
        let mut program_test =
            ProgramTest::new("gas-station", program_id, processor!(process_instruction));

        let user = Keypair::new();
        let owner = Keypair::new();
        let storage = Keypair::new();
        let (payer, _) = Pubkey::find_program_address(&[owner.pubkey().as_ref()], &program_id);
        program_test.add_account(
            user.pubkey(),
            Account::new(1000000, 0, &system_program::id()),
        );
        program_test.add_account(payer, Account::new(1000000, 0, &program_id));
        program_test.add_account(
            solana_sdk::evm_state::ID,
            solana_evm_loader_program::create_state_account(1000000).into(),
        );
        let payer_data = Payer {
            owner: owner.pubkey(),
            payer,
            filters: vec![TxFilter::InputStartsWith {
                contract: evm::Address::zero(),
                input_prefix: vec![],
            }],
        };
        let mut payer_bytes = vec![];
        BorshSerialize::serialize(&payer_data, &mut payer_bytes).unwrap();
        program_test.add_account(
            storage.pubkey(),
            Account {
                lamports: 10000000,
                owner: system_program::id(),
                data: payer_bytes,
                ..Account::default()
            },
        );

        let (mut banks_client, _, recent_blockhash) = program_test.start().await;

        let account_metas = vec![
            AccountMeta::new(user.pubkey(), true),
            AccountMeta::new(storage.pubkey(), false),
            AccountMeta::new(payer, false),
            AccountMeta::new_readonly(solana_sdk::evm_loader::ID, false),
            AccountMeta::new(solana_sdk::evm_state::ID, false),
            AccountMeta::new_readonly(system_program::id(), false),
        ];
        let ix = Instruction::new_with_borsh(
            program_id,
            &GasStationInstruction::ExecuteWithPayer {
                tx: Some(dummy_eth_tx(evm::H160::zero(), vec![])),
            },
            account_metas,
        );
        let mut transaction = Transaction::new_with_payer(&[ix], Some(&user.pubkey()));
        transaction.sign(&[&user], recent_blockhash);
        assert!(matches!(
            banks_client
                .process_transaction(transaction)
                .await
                .unwrap_err(),
            TransactionError(InstructionError(0, IncorrectProgramId))
        ));
    }

    #[tokio::test]
    async fn test_invalid_storage_data() {
        let program_id = Pubkey::new_unique();
        let mut program_test =
            ProgramTest::new("gas-station", program_id, processor!(process_instruction));

        let user = Keypair::new();
        let owner = Keypair::new();
        let storage1 = Keypair::new();
        let storage2 = Keypair::new();
        let storage3 = Keypair::new();
        let (payer, _) = Pubkey::find_program_address(&[owner.pubkey().as_ref()], &program_id);
        program_test.add_account(
            user.pubkey(),
            Account::new(1000000, 0, &system_program::id()),
        );
        program_test.add_account(payer, Account::new(1000000, 0, &program_id));
        program_test.add_account(
            solana_sdk::evm_state::ID,
            solana_evm_loader_program::create_state_account(1000000).into(),
        );
        let short_payer_bytes = vec![0u8; 64];
        program_test.add_account(
            storage1.pubkey(),
            Account {
                lamports: 10000000,
                owner: program_id,
                data: short_payer_bytes.clone(), // data too short
                ..Account::default()
            },
        );
        program_test.add_account(
            storage2.pubkey(),
            Account {
                lamports: 10000000,
                owner: program_id,
                data: short_payer_bytes
                    .into_iter()
                    // this 4 bytes mean that the size of filter array is 1 but there's no data after
                    .chain([0, 0, 0, 1].into_iter())
                    .collect(),
                ..Account::default()
            },
        );
        let payer_data = Payer {
            owner: owner.pubkey(),
            payer,
            filters: vec![TxFilter::InputStartsWith {
                contract: evm::Address::zero(),
                input_prefix: vec![],
            }],
        };
        let mut valid_payer_bytes = vec![];
        BorshSerialize::serialize(&payer_data, &mut valid_payer_bytes).unwrap();
        program_test.add_account(
            storage3.pubkey(),
            Account {
                lamports: 10000000,
                owner: program_id,
                data: valid_payer_bytes
                    .into_iter()
                    // add 1 extra byte
                    .chain([0].into_iter())
                    .collect(),
                ..Account::default()
            },
        );

        let (mut banks_client, _, recent_blockhash) = program_test.start().await;

        for storage in [storage1, storage2, storage3] {
            let account_metas = vec![
                AccountMeta::new(user.pubkey(), true),
                AccountMeta::new(storage.pubkey(), false),
                AccountMeta::new(payer, false),
                AccountMeta::new_readonly(solana_sdk::evm_loader::ID, false),
                AccountMeta::new(solana_sdk::evm_state::ID, false),
                AccountMeta::new_readonly(system_program::id(), false),
            ];
            let ix = Instruction::new_with_borsh(
                program_id,
                &GasStationInstruction::ExecuteWithPayer {
                    tx: Some(dummy_eth_tx(evm::H160::zero(), vec![])),
                },
                account_metas,
            );
            let mut transaction = Transaction::new_with_payer(&[ix], Some(&user.pubkey()));
            transaction.sign(&[&user], recent_blockhash);
            assert!(matches!(
                banks_client
                    .process_transaction(transaction)
                    .await
                    .unwrap_err(),
                TransactionError(InstructionError(0, Custom(2)))
            ));
        }
    }

    #[tokio::test]
    async fn test_storage_not_initialized() {
        let program_id = Pubkey::new_unique();
        let mut program_test =
            ProgramTest::new("gas-station", program_id, processor!(process_instruction));

        let user = Keypair::new();
        let owner = Keypair::new();
        let storage = Keypair::new();
        let (payer, _) = Pubkey::find_program_address(&[owner.pubkey().as_ref()], &program_id);
        program_test.add_account(
            user.pubkey(),
            Account::new(1000000, 0, &system_program::id()),
        );
        program_test.add_account(payer, Account::new(1000000, 0, &program_id));
        program_test.add_account(
            solana_sdk::evm_state::ID,
            solana_evm_loader_program::create_state_account(1000000).into(),
        );
        let payer_bytes = vec![0u8; 93];
        program_test.add_account(
            storage.pubkey(),
            Account {
                lamports: 10000000,
                owner: program_id,
                data: payer_bytes,
                ..Account::default()
            },
        );

        let (mut banks_client, _, recent_blockhash) = program_test.start().await;

        let account_metas = vec![
            AccountMeta::new(user.pubkey(), true),
            AccountMeta::new(storage.pubkey(), false),
            AccountMeta::new(payer, false),
            AccountMeta::new_readonly(solana_sdk::evm_loader::ID, false),
            AccountMeta::new(solana_sdk::evm_state::ID, false),
            AccountMeta::new_readonly(system_program::id(), false),
        ];
        let ix = Instruction::new_with_borsh(
            program_id,
            &GasStationInstruction::ExecuteWithPayer {
                tx: Some(dummy_eth_tx(evm::H160::zero(), vec![])),
            },
            account_metas,
        );
        let mut transaction = Transaction::new_with_payer(&[ix], Some(&user.pubkey()));
        transaction.sign(&[&user], recent_blockhash);
        assert!(matches!(
            banks_client
                .process_transaction(transaction)
                .await
                .unwrap_err(),
            TransactionError(InstructionError(0, Custom(1)))
        ));
    }

    #[tokio::test]
    async fn test_payer_account_mismatch() {
        let program_id = Pubkey::new_unique();
        let mut program_test =
            ProgramTest::new("gas-station", program_id, processor!(process_instruction));

        let user = Keypair::new();
        let owner1 = Keypair::new();
        let owner2 = Keypair::new();
        let storage = Keypair::new();
        let (payer1, _) = Pubkey::find_program_address(&[owner1.pubkey().as_ref()], &program_id);
        let (payer2, _) = Pubkey::find_program_address(&[owner2.pubkey().as_ref()], &program_id);
        program_test.add_account(
            user.pubkey(),
            Account::new(1000000, 0, &system_program::id()),
        );
        program_test.add_account(payer1, Account::new(1000000, 0, &program_id));
        program_test.add_account(
            solana_sdk::evm_state::ID,
            solana_evm_loader_program::create_state_account(1000000).into(),
        );
        let payer_data = Payer {
            owner: owner1.pubkey(),
            payer: payer1,
            filters: vec![TxFilter::InputStartsWith {
                contract: evm::Address::zero(),
                input_prefix: vec![],
            }],
        };
        let mut payer_bytes = vec![];
        BorshSerialize::serialize(&payer_data, &mut payer_bytes).unwrap();
        program_test.add_account(
            storage.pubkey(),
            Account {
                lamports: 10000000,
                owner: program_id,
                data: payer_bytes,
                ..Account::default()
            },
        );

        let (mut banks_client, _, recent_blockhash) = program_test.start().await;

        let account_metas = vec![
            AccountMeta::new(user.pubkey(), true),
            AccountMeta::new(storage.pubkey(), false),
            AccountMeta::new(payer2, false),
            AccountMeta::new_readonly(solana_sdk::evm_loader::ID, false),
            AccountMeta::new(solana_sdk::evm_state::ID, false),
            AccountMeta::new_readonly(system_program::id(), false),
        ];
        let ix = Instruction::new_with_borsh(
            program_id,
            &GasStationInstruction::ExecuteWithPayer {
                tx: Some(dummy_eth_tx(evm::H160::zero(), vec![0; 4])),
            },
            account_metas,
        );
        let mut transaction = Transaction::new_with_payer(&[ix], Some(&user.pubkey()));
        transaction.sign(&[&user], recent_blockhash);
        assert!(matches!(
            banks_client
                .process_transaction(transaction)
                .await
                .unwrap_err(),
            TransactionError(InstructionError(0, Custom(6)))
        ));
    }

    #[tokio::test]
    async fn test_payer_filter_mismatch() {
        let program_id = Pubkey::new_unique();
        let mut program_test =
            ProgramTest::new("gas-station", program_id, processor!(process_instruction));

        let user = Keypair::new();
        let owner = Keypair::new();
        let storage = Keypair::new();
        let (payer, _) = Pubkey::find_program_address(&[owner.pubkey().as_ref()], &program_id);
        program_test.add_account(
            user.pubkey(),
            Account::new(1000000, 0, &system_program::id()),
        );
        program_test.add_account(payer, Account::new(1000000, 0, &program_id));
        program_test.add_account(
            solana_sdk::evm_state::ID,
            solana_evm_loader_program::create_state_account(1000000).into(),
        );
        let payer_data = Payer {
            owner: owner.pubkey(),
            payer,
            filters: vec![
                TxFilter::InputStartsWith {
                    contract: evm::Address::zero(),
                    input_prefix: vec![1; 4],
                },
                TxFilter::InputStartsWith {
                    contract: evm::Address::from([1u8; 20]),
                    input_prefix: vec![0; 4],
                },
            ],
        };
        let mut payer_bytes = vec![];
        BorshSerialize::serialize(&payer_data, &mut payer_bytes).unwrap();
        program_test.add_account(
            storage.pubkey(),
            Account {
                lamports: 10000000,
                owner: program_id,
                data: payer_bytes,
                ..Account::default()
            },
        );

        let (mut banks_client, _, recent_blockhash) = program_test.start().await;

        let account_metas = vec![
            AccountMeta::new(user.pubkey(), true),
            AccountMeta::new(storage.pubkey(), false),
            AccountMeta::new(payer, false),
            AccountMeta::new_readonly(solana_sdk::evm_loader::ID, false),
            AccountMeta::new(solana_sdk::evm_state::ID, false),
            AccountMeta::new_readonly(system_program::id(), false),
        ];
        let ix = Instruction::new_with_borsh(
            program_id,
            &GasStationInstruction::ExecuteWithPayer {
                tx: Some(dummy_eth_tx(evm::H160::zero(), vec![0; 4])),
            },
            account_metas,
        );
        let mut transaction = Transaction::new_with_payer(&[ix], Some(&user.pubkey()));
        transaction.sign(&[&user], recent_blockhash);
        assert!(matches!(
            banks_client
                .process_transaction(transaction)
                .await
                .unwrap_err(),
            TransactionError(InstructionError(0, Custom(7)))
        ));
    }

    // TODO: add test for insufficient_funds during refund
}
