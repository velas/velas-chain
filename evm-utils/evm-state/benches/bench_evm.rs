use {
    criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput},
    evm::{ExitReason, ExitSucceed},
    evm_state::{
        executor::{FeatureSet, OwnedPrecompile},
        *,
    },
    primitive_types::{H160 as Address, H256, U256},
    sha3::{Digest, Keccak256},
    std::{collections::HashSet, iter, time::Instant},
};

fn name_to_key<S: AsRef<str>>(name: S) -> H160 {
    H256::from_slice(Keccak256::digest(name.as_ref().as_bytes()).as_slice()).into()
}

fn criterion_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("Evm");
    group.throughput(Throughput::Elements(1));

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

    group.bench_function("call_hello_with_executor", |b| {
        let mut state = EvmBackend::default();

        for address in iter::once(contract).chain(accounts.iter().copied()) {
            state.set_account_state(address, AccountState::default());
        }

        let mut executor = Executor::with_config(
            Default::default(),
            Default::default(),
            Default::default(),
            FeatureSet::new_with_all_enabled(),
        );

        let exit_reason: (ExitReason, Vec<u8>) =
            executor.with_executor(OwnedPrecompile::default(), |executor| {
                executor.transact_create(contract, U256::zero(), code.clone(), u64::MAX, vec![])
            });
        assert!(matches!(
            exit_reason,
            (ExitReason::Succeed(ExitSucceed::Returned), _)
        ));

        let contract_address = TransactionAction::Create.address(contract, U256::zero());
        let mut idx = 0;
        b.iter(|| {
            let exit_reason = black_box(executor.with_executor(
                OwnedPrecompile::default(),
                |executor| {
                    executor.transact_call(
                        accounts[idx % accounts.len()],
                        contract_address,
                        U256::zero(),
                        data.to_vec(),
                        u64::MAX,
                        vec![],
                    )
                },
            ));

            //hack: Avoid gas limit
            executor.evm_backend.state.used_gas = 0;

            assert!(matches!(
                exit_reason.0,
                ExitReason::Succeed(ExitSucceed::Returned)
            ));
            assert_eq!(exit_reason.1, expected_result);

            idx += 1;
        });
    });

    group.bench_function("call_hello_with_executor_recreate", |b| {
        let mut state = EvmBackend::default();

        for address in iter::once(contract).chain(accounts.iter().copied()) {
            state.set_account_state(address, AccountState::default());
        }

        let mut executor = Executor::with_config(
            Default::default(),
            Default::default(),
            Default::default(),
            FeatureSet::new_with_all_enabled(),
        );

        let exit_reason = executor.with_executor(OwnedPrecompile::default(), |executor| {
            executor.transact_create(contract, U256::zero(), code.clone(), u64::MAX, vec![])
        });
        assert!(matches!(
            exit_reason,
            (ExitReason::Succeed(ExitSucceed::Returned), _)
        ));

        let state = executor.deconstruct();
        let committed = state.commit_block(0, Default::default());
        let updated_state = committed.next_incomming(0);

        let contract_address = TransactionAction::Create.address(contract, U256::zero());

        let mut idx = 0;
        b.iter(|| {
            let mut executor = Executor::with_config(
                updated_state.clone(),
                Default::default(),
                Default::default(),
                FeatureSet::new_with_all_enabled(),
            );

            let exit_reason = black_box(executor.with_executor(
                OwnedPrecompile::default(),
                |executor| {
                    executor.transact_call(
                        accounts[idx % accounts.len()],
                        contract_address,
                        U256::zero(),
                        data.to_vec(),
                        u64::MAX,
                        vec![],
                    )
                },
            ));

            assert!(matches!(
                exit_reason.0,
                ExitReason::Succeed(ExitSucceed::Returned)
            ));
            assert_eq!(exit_reason.1, expected_result);

            idx += 1;
        });
    });

    group.bench_function("call_hello_with_executor_recreate_raw", |b| {
        let mut executor = Executor::with_config(
            Default::default(),
            Default::default(),
            Default::default(),
            FeatureSet::new_with_all_enabled(),
        );

        let exit_reason = executor.with_executor(OwnedPrecompile::default(), |executor| {
            executor.transact_create(contract, U256::zero(), code.clone(), u64::MAX, vec![])
        });
        assert!(matches!(
            exit_reason,
            (ExitReason::Succeed(ExitSucceed::Returned), _)
        ));

        let state = executor.deconstruct();
        let committed = state.commit_block(0, Default::default());
        let updated_state = committed.next_incomming(0);

        let contract_address = TransactionAction::Create.address(contract, U256::zero());
        let mut rng = secp256k1::rand::thread_rng();
        let user_key = secp256k1::key::SecretKey::new(&mut rng);
        let caller = user_key.to_address();

        let tx = UnsignedTransaction {
            nonce: 0.into(),
            gas_price: 0.into(),
            gas_limit: u64::max_value().into(),
            action: TransactionAction::Call(contract_address),
            value: 0.into(),
            input: data.to_vec(),
        };
        b.iter(|| {
            let mut executor = Executor::with_config(
                updated_state.clone(),
                Default::default(),
                Default::default(),
                FeatureSet::new_with_all_enabled(),
            );

            let ExecutionResult {
                exit_reason,
                exit_data,
                ..
            } = black_box(executor.transaction_execute_unsinged(
                caller,
                tx.clone(),
                true,
                OwnedPrecompile::default(),
            ))
            .unwrap();

            assert!(matches!(
                exit_reason,
                ExitReason::Succeed(ExitSucceed::Returned)
            ));
            assert_eq!(exit_data, expected_result)
        });
    });

    group.bench_function("call_hello_with_executor_recreate_and_commit", |b| {
        let mut executor = Executor::with_config(
            Default::default(),
            Default::default(),
            Default::default(),
            FeatureSet::new_with_all_enabled(),
        );

        let exit_reason = executor.with_executor(OwnedPrecompile::default(), |executor| {
            executor.transact_create(contract, U256::zero(), code.clone(), u64::MAX, vec![])
        });
        assert!(matches!(
            exit_reason,
            (ExitReason::Succeed(ExitSucceed::Returned), _)
        ));

        let state = executor.deconstruct();
        let committed = state.commit_block(0, Default::default());
        let mut updated_state = committed.next_incomming(0);

        let contract_address = TransactionAction::Create.address(contract, U256::zero());
        let mut rng = secp256k1::rand::thread_rng();
        let user_key = secp256k1::key::SecretKey::new(&mut rng);
        let caller = user_key.to_address();

        let mut slot = 0;
        b.iter(|| {
            let mut executor = Executor::with_config(
                updated_state.clone(),
                Default::default(),
                Default::default(),
                FeatureSet::new_with_all_enabled(),
            );

            let tx = UnsignedTransaction {
                nonce: slot.into(),
                gas_price: 0.into(),
                gas_limit: u64::max_value().into(),
                action: TransactionAction::Call(contract_address),
                value: 0.into(),
                input: data.to_vec(),
            };
            let ExecutionResult {
                exit_reason,
                exit_data,
                ..
            } = black_box(executor.transaction_execute_unsinged(
                caller,
                tx.clone(),
                true,
                OwnedPrecompile::default(),
            ))
            .unwrap();
            updated_state = executor
                .deconstruct()
                .commit_block(slot, H256::zero())
                .next_incomming(0);

            assert!(matches!(
                exit_reason,
                ExitReason::Succeed(ExitSucceed::Returned)
            ));
            assert_eq!(exit_data, expected_result);
            slot += 1;
        });
    });

    group.bench_function(
        "call_hello_with_executor_recreate_and_commit_with_gc",
        |b| {
            let backend = EvmBackend::new(
                Incomming::default(),
                Storage::create_temporary_gc().unwrap(),
            );
            let mut executor = Executor::with_config(
                backend,
                Default::default(),
                Default::default(),
                FeatureSet::new_with_all_enabled(),
            );

            let exit_reason = executor.with_executor(OwnedPrecompile::default(), |executor| {
                executor.transact_create(contract, U256::zero(), code.clone(), u64::MAX, vec![])
            });
            assert!(matches!(
                exit_reason,
                (ExitReason::Succeed(ExitSucceed::Returned), _)
            ));

            let state = executor.deconstruct();
            let committed = state.commit_block(0, Default::default());
            let mut updated_state = committed.next_incomming(0);

            let contract_address = TransactionAction::Create.address(contract, U256::zero());
            let mut rng = secp256k1::rand::thread_rng();
            let user_key = secp256k1::key::SecretKey::new(&mut rng);
            let caller = user_key.to_address();

            let mut slot = 0;
            b.iter(|| {
                let mut executor = Executor::with_config(
                    updated_state.clone(),
                    Default::default(),
                    Default::default(),
                    FeatureSet::new_with_all_enabled(),
                );

                let tx = UnsignedTransaction {
                    nonce: slot.into(),
                    gas_price: 0.into(),
                    gas_limit: u64::max_value().into(),
                    action: TransactionAction::Call(contract_address),
                    value: 0.into(),
                    input: data.to_vec(),
                };

                let ExecutionResult {
                    exit_reason,
                    exit_data,
                    ..
                } = black_box(executor.transaction_execute_unsinged(
                    caller,
                    tx.clone(),
                    true,
                    OwnedPrecompile::default(),
                ))
                .unwrap();
                let state = executor.deconstruct();

                let root_before = state.last_root();
                let block = state.commit_block(slot, H256::zero()).next_incomming(0);

                // register and remove root link

                if slot != 0 {
                    // skip gc at first slot
                    let removed_root = block.kvs().purge_slot(slot).unwrap().unwrap();
                    assert_eq!(removed_root, root_before);

                    let (mut direct, mut indirect) = (vec![removed_root], vec![]);
                    while !direct.is_empty() {
                        let childs = block.kvs().gc_try_cleanup_account_hashes(&direct);

                        direct = childs.0;
                        indirect.extend_from_slice(&childs.1);
                    }
                    while !indirect.is_empty() {
                        let childs = block.kvs().gc_try_cleanup_account_hashes(&direct);

                        indirect = childs.0;
                    }
                }
                slot += 1;

                block
                    .kvs()
                    .register_slot(slot, block.last_root(), false)
                    .unwrap();
                updated_state = block;

                assert!(matches!(
                    exit_reason,
                    ExitReason::Succeed(ExitSucceed::Returned)
                ));
                assert_eq!(exit_data, expected_result)
            });
        },
    );

    group.bench_function(
        "call_hello_with_executor_recreate_and_commit_with_gc_no_purge",
        |b| {
            let backend = EvmBackend::new(
                Incomming::default(),
                Storage::create_temporary_gc().unwrap(),
            );
            let mut executor = Executor::with_config(
                backend,
                Default::default(),
                Default::default(),
                FeatureSet::new_with_all_enabled(),
            );

            let exit_reason = executor.with_executor(OwnedPrecompile::default(), |executor| {
                executor.transact_create(contract, U256::zero(), code.clone(), u64::MAX, vec![])
            });
            assert!(matches!(
                exit_reason,
                (ExitReason::Succeed(ExitSucceed::Returned), _)
            ));

            let state = executor.deconstruct();
            let committed = state.commit_block(0, Default::default());
            let mut updated_state = committed.next_incomming(0);

            let contract_address = TransactionAction::Create.address(contract, U256::zero());
            let mut rng = secp256k1::rand::thread_rng();
            let user_key = secp256k1::key::SecretKey::new(&mut rng);
            let caller = user_key.to_address();

            let mut slot = 0;
            b.iter(|| {
                let mut executor = Executor::with_config(
                    updated_state.clone(),
                    Default::default(),
                    Default::default(),
                    FeatureSet::new_with_all_enabled(),
                );

                let tx = UnsignedTransaction {
                    nonce: slot.into(),
                    gas_price: 0.into(),
                    gas_limit: u64::max_value().into(),
                    action: TransactionAction::Call(contract_address),
                    value: 0.into(),
                    input: data.to_vec(),
                };

                let ExecutionResult {
                    exit_reason,
                    exit_data,
                    ..
                } = black_box(executor.transaction_execute_unsinged(
                    caller,
                    tx.clone(),
                    true,
                    OwnedPrecompile::default(),
                ))
                .unwrap();
                let state = executor.deconstruct();

                let block = state.commit_block(slot, H256::zero()).next_incomming(0);

                slot += 1;

                block
                    .kvs()
                    .register_slot(slot, block.last_root(), false)
                    .unwrap();
                updated_state = block;

                assert!(matches!(
                    exit_reason,
                    ExitReason::Succeed(ExitSucceed::Returned)
                ));
                assert_eq!(exit_data, expected_result)
            });
        },
    );

    group.bench_function("call_hello_with_signature_verify_single_key", |b| {
        let mut executor = Executor::with_config(
            Default::default(),
            Default::default(),
            Default::default(),
            FeatureSet::new_with_all_enabled(),
        );

        let exit_reason = executor.with_executor(OwnedPrecompile::default(), |executor| {
            executor.transact_create(contract, U256::zero(), code.clone(), u64::MAX, vec![])
        });

        assert!(matches!(
            exit_reason,
            (ExitReason::Succeed(ExitSucceed::Returned), _)
        ));

        let state = executor.deconstruct();

        let committed = state.commit_block(0, Default::default());
        let updated_state = committed.next_incomming(0);

        let contract_address = TransactionAction::Create.address(contract, U256::zero());
        let mut rng = secp256k1::rand::thread_rng();
        let user_key = secp256k1::key::SecretKey::new(&mut rng);
        let tx = UnsignedTransaction {
            nonce: 0.into(),
            gas_price: 0.into(),
            gas_limit: u64::max_value().into(),
            action: TransactionAction::Call(contract_address),
            value: 0.into(),
            input: data.to_vec(),
        }
        .sign(&user_key, Some(evm_state::TEST_CHAIN_ID));

        b.iter(|| {
            let mut executor = Executor::with_config(
                updated_state.clone(),
                Default::default(),
                Default::default(),
                FeatureSet::new_with_all_enabled(),
            );

            let ExecutionResult {
                exit_reason,
                exit_data,
                ..
            } = black_box(executor.transaction_execute(
                tx.clone(),
                true,
                OwnedPrecompile::default(),
            ))
            .unwrap();

            assert!(matches!(
                exit_reason,
                ExitReason::Succeed(ExitSucceed::Returned)
            ));
            assert_eq!(exit_data, expected_result)
        });
    });

    for n_forks in &[0, 1, 10, 50, 100, 1000] {
        group.bench_with_input(
            BenchmarkId::new("call_hello_on_frozen_forks", n_forks),
            n_forks,
            |b, n_forks| {
                let mut state = EvmBackend::default();

                for address in iter::once(contract).chain(accounts.iter().copied()) {
                    state.set_account_state(address, AccountState::default());
                }

                let mut executor = Executor::with_config(
                    Default::default(),
                    Default::default(),
                    Default::default(),
                    FeatureSet::new_with_all_enabled(),
                );
                let create_transaction_result = executor.with_executor(OwnedPrecompile::default(),|executor| {
                    executor.transact_create(contract, U256::zero(), code.clone(), u64::MAX, vec![])
                });
                assert!(matches!(
                    create_transaction_result,
                    (ExitReason::Succeed(ExitSucceed::Returned), _)
                ));

                let mut state = executor.deconstruct();
                let committed = state.commit_block(0, Default::default());
                state = committed.next_incomming(0);

                for new_slot in 1..=*n_forks {
                    // state.freeze();
                    let committed = state.commit_block(new_slot, Default::default());
                    state = committed.next_incomming(0);
                }

                let contract = TransactionAction::Create.address(contract, U256::zero());

                let accounts = &accounts;
                let data = data.clone();
                let expected_result = &expected_result;

                b.iter_custom(move |iters| {
                    let mut executor = Executor::with_config(
                        state.clone(),
                        Default::default(),
                        Default::default(),
                        FeatureSet::new_with_all_enabled(),
                    );

                    let start = Instant::now();

                    for idx in 0..iters {
                        let caller = accounts[idx as usize % accounts.len()];
                        let call_transaction_result =
                            black_box(executor.with_executor(OwnedPrecompile::default(),|executor| {
                                executor.transact_call(
                                    caller,
                                    contract,
                                    U256::zero(),
                                    data.to_vec(),
                                    u64::MAX,
                                    vec![],
                                )
                            }));
                        assert!(matches!(
                            call_transaction_result,
                            (ExitReason::Succeed(ExitSucceed::Returned), ref result) if result == expected_result
                        ));

                        //hack: Avoid gas limit
                        executor.evm_backend.state.used_gas = 0;
                    }

                    start.elapsed()
                });
            },
        );
    }

    group.bench_function("call_hello_on_dumped_state", |b| {
        let mut state = EvmBackend::default();

        iter::once(contract)
            .chain(accounts.iter().copied())
            .for_each(|address| state.set_account_state(address, AccountState::default()));

        let committed = state.commit_block(0, Default::default());

        let  state = committed.next_incomming(0);
        let mut executor = Executor::with_config(
            state,
            Default::default(),
            Default::default(),
            FeatureSet::new_with_all_enabled(),
        );

        let exit_reason = executor.with_executor(OwnedPrecompile::default(),|executor| {
            executor.transact_create(contract, U256::zero(), code.clone(), u64::MAX, vec![])
        });
        assert!(matches!(
            exit_reason,
            (ExitReason::Succeed(ExitSucceed::Returned), _)
        ));

        let committed = executor.deconstruct().commit_block(0, Default::default());
        let state = committed.next_incomming(0);

        let contract_address = TransactionAction::Create.address(contract, U256::zero());
        let mut idx = 0;
        b.iter(|| {
            let mut executor = Executor::with_config(
                state.clone(),
                Default::default(),
                Default::default(),
                FeatureSet::new_with_all_enabled(),
            );

            let exit_reason = executor.with_executor(OwnedPrecompile::default(),|executor| {
                executor.transact_call(
                    accounts[idx % accounts.len()],
                    contract_address,
                    U256::zero(),
                    data.to_vec(),
                    u64::MAX,
                    vec![],
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
