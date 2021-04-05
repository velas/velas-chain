use std::{collections::HashSet, iter, time::Instant};

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

use evm::{ExitReason, ExitSucceed};
use evm_state::*;
use primitive_types::{H160 as Address, H256, U256};
use sha3::{Digest, Keccak256};

fn name_to_key<S: AsRef<str>>(name: S) -> H160 {
    H256::from_slice(Keccak256::digest(name.as_ref().as_bytes()).as_slice()).into()
}

fn criterion_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("Evm");
    group.throughput(Throughput::Elements(1));

    let chain_id = 42;
    let code = hex::decode(HELLO_WORLD_CODE).unwrap();
    let data = hex::decode(HELLO_WORLD_ABI).unwrap();
    let expected_result = hex::decode(HELLO_WORLD_RESULT).unwrap();

    let contract = name_to_key("contract");

    const N_ACCOUNTS: usize = 100;
    let accounts: Vec<Address> = (0..N_ACCOUNTS)
        .map(|i| format!("account_{}", i))
        .map(name_to_key)
        .collect();

    // Ensures there no duplicates in addresses.
    assert_eq!(
        iter::once(contract)
            .chain(accounts.iter().copied())
            .collect::<HashSet<Address>>()
            .len(),
        N_ACCOUNTS + 1 // contract + [account]s
    );

    group.bench_function("call_hello", |b| {
        let mut state = EvmState::default();

        for address in iter::once(contract).chain(accounts.iter().copied()) {
            state.set_account_state(address, AccountState::default());
        }

        let slot = state.block_num;
        let mut executor =
            Executor::with_config(state, evm::Config::istanbul(), u64::max_value(), chain_id, slot);

        let exit_reason = executor.with_executor(|executor| {
            executor.transact_create(
                contract,
                U256::zero(),
                code.clone(),
                u64::max_value(),
            )
        });
        assert!(matches!(
            exit_reason,
            ExitReason::Succeed(ExitSucceed::Returned)
        ));

        let contract_address = TransactionAction::Create.address(contract, U256::zero());
        let mut idx = 0;
        b.iter(|| {
            let exit_reason = black_box(executor.with_executor(|executor| {
                executor.transact_call(
                    accounts[idx % accounts.len()],
                    contract_address,
                    U256::zero(),
                    data.to_vec(),
                    u64::max_value(),
                )
            }));

            assert!(matches!(
                exit_reason,
                (ExitReason::Succeed(ExitSucceed::Returned), ref result) if result == &expected_result
            ));

            idx += 1;
        });
    });

    group.bench_function("call_hello_with_executor_recreate_raw", |b| {
        let mut executor = Executor::with_config(
            EvmState::default(),
            evm::Config::istanbul(),
            u64::max_value(),
            chain_id,
            0,
        );

        let exit_reason = executor.with_executor(|executor| {
            executor.transact_create(contract, U256::zero(), code.clone(), u64::max_value())
        });
        assert!(matches!(
            exit_reason,
            ExitReason::Succeed(ExitSucceed::Returned)
        ));

        let mut state = executor.deconstruct();
        state.commit_block(0);

        let contract_address = TransactionAction::Create.address(contract, U256::zero());
        let mut rng = secp256k1::rand::thread_rng();
        let user_key = secp256k1::key::SecretKey::new(&mut rng);
        let caller = user_key.to_address();

        let tx = UnsignedTransaction {
            nonce: 0.into(),
            gas_price: 1.into(),
            gas_limit: u64::max_value().into(),
            action: TransactionAction::Call(contract_address),
            value: 0.into(),
            input: data.to_vec()
        };
        b.iter(|| {
            let mut executor =
                Executor::with_config(state.clone(), evm::Config::istanbul(), u64::max_value(), chain_id,state.block_num);

            let exit_reason = black_box(executor.transaction_execute_unsinged(
                caller,
                tx.clone(),
                |_,_,_,_| None
            )).unwrap();

            assert!(matches!(
                exit_reason,
                (ExitReason::Succeed(ExitSucceed::Returned), ref result) if result == &expected_result
            ));

        });
    });

    group.bench_function("call_hello_with_signature_verify_single_key", |b| {
        let mut executor = Executor::with_config(
            EvmState::default(),
            evm::Config::istanbul(),
            u64::max_value(),
            chain_id,
            0,
        );

        let exit_reason = executor.with_executor(|executor| {
            executor.transact_create(contract, U256::zero(), code.clone(), u64::max_value())
        });
        assert!(matches!(
            exit_reason,
            ExitReason::Succeed(ExitSucceed::Returned)
        ));

        let mut state = executor.deconstruct();
        state.commit_block(0);

        let contract_address = TransactionAction::Create.address(contract, U256::zero());
        let mut rng = secp256k1::rand::thread_rng();
        let user_key = secp256k1::key::SecretKey::new(&mut rng);
        let tx = UnsignedTransaction {
            nonce: 0.into(),
            gas_price: 1.into(),
            gas_limit: u64::max_value().into(),
            action: TransactionAction::Call(contract_address),
            value: 0.into(),
            input: data.to_vec()
        }.sign(&user_key, None);

        b.iter(|| {
            let mut executor =
                Executor::with_config(state.clone(), evm::Config::istanbul(), u64::max_value(), chain_id,state.block_num);

            let exit_reason = black_box(executor.transaction_execute(
                tx.clone(),
                |_,_,_,_| None
            )).unwrap();

            assert!(matches!(
                exit_reason,
                (ExitReason::Succeed(ExitSucceed::Returned), ref result) if result == &expected_result
            ));

        });
    });

    for n_forks in &[0, 1, 10, 50, 100, 1000] {
        group.bench_with_input(
            BenchmarkId::new("call_hello_on_frozen_forks", n_forks),
            n_forks,
            |b, n_forks| {
                let mut state = EvmState::default();

                for address in iter::once(contract).chain(accounts.iter().copied()) {
                    state.set_account_state(address, AccountState::default());
                }

                let slot = state.block_num;
                let mut executor =
                    Executor::with_config(state, evm::Config::istanbul(), u64::max_value(), chain_id, slot);
                let create_transaction_result = executor.with_executor(|executor| {
                    executor.transact_create(contract, U256::zero(), code.clone(), u64::max_value())
                });
                assert!(matches!(
                    create_transaction_result,
                    ExitReason::Succeed(ExitSucceed::Returned)
                ));

                let mut state = executor.deconstruct();
                state.commit_block(0);

                for new_slot in (slot + 1)..=*n_forks {
                    // state.freeze();
                    state = state.fork(new_slot);
                }

                let contract = TransactionAction::Create.address(contract, U256::zero());

                let accounts = &accounts;
                let data = data.clone();
                let expected_result = &expected_result;

                b.iter_custom(move |iters| {
                    let mut executor = Executor::with_config(
                        state.clone(),
                        evm::Config::istanbul(),
                        u64::max_value(),
                        chain_id,
                        state.block_num,
                    );

                    let start = Instant::now();

                    for idx in 0..iters {
                        let caller = accounts[idx as usize % accounts.len()];
                        let call_transaction_result =
                            black_box(executor.with_executor(|executor| {
                                executor.transact_call(
                                    caller,
                                    contract,
                                    U256::zero(),
                                    data.to_vec(),
                                    u64::max_value(),
                                )
                            }));
                        assert!(matches!(
                            call_transaction_result,
                            (ExitReason::Succeed(ExitSucceed::Returned), ref result) if result == expected_result
                        ));
                    }

                    start.elapsed()
                });
            },
        );
    }

    group.bench_function("call_hello_on_dumped_state", |b| {
        let mut state = EvmState::default();

        iter::once(contract)
            .chain(accounts.iter().copied())
            .for_each(|address| state.set_account_state(address, AccountState::default()));

        state.commit_block(0);

        let slot = state.block_num;
        let mut executor =
            Executor::with_config(state, evm::Config::istanbul(), u64::max_value(), chain_id, slot);

        let exit_reason = executor.with_executor(|executor| {
            executor.transact_create(contract, U256::zero(), code.clone(), u64::max_value())
        });
        assert!(matches!(
            exit_reason,
            ExitReason::Succeed(ExitSucceed::Returned)
        ));

        let mut state = executor.deconstruct();
        state.commit_block(0);

        let contract_address = TransactionAction::Create.address(contract, U256::zero());
        let mut idx = 0;
        b.iter(|| {
            let mut executor =
                Executor::with_config(state.clone(), evm::Config::istanbul(), u64::max_value(), chain_id, state.block_num);

            let exit_reason = executor.with_executor(|executor| {
                executor.transact_call(
                    accounts[idx % accounts.len()],
                    contract_address,
                    U256::zero(),
                    data.to_vec(),
                    u64::max_value(),
                )
            });

            assert!(matches!(
                exit_reason,
                (ExitReason::Succeed(ExitSucceed::Returned), ref result) if result == &expected_result
            ));

            idx += 1;
        });
    });

    group.finish();
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
