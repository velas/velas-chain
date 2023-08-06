use {
    criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion},
    derive_more::Display,
    evm_state::{types::BlockNum, AccountProvider, EvmBackend, EvmState, Incomming, Storage},
    rand::Rng,
    std::fs,
    tempfile::tempdir,
};

mod utils;

#[derive(Clone, Display)]
#[display(
    fmt = "slots {}, squash each {}, {} accounts per 100k slots, gc={}",
    n_slots,
    squash_each,
    accounts_per_100k,
    with_gc
)]
struct Params {
    n_slots: BlockNum,
    squash_each: BlockNum,
    accounts_per_100k: usize,
    with_gc: bool,
}

impl Params {
    fn new(n_slots: BlockNum, squash_each: BlockNum, accounts_per_100k: usize) -> Vec<Params> {
        vec![
            Params {
                n_slots,
                squash_each,
                accounts_per_100k,
                with_gc: false,
            },
            Params {
                n_slots,
                squash_each,
                accounts_per_100k,
                with_gc: true,
            },
        ]
    }
}

fn add_some_and_advance(state: &mut EvmBackend<Incomming>, params: &Params) {
    // repeat 1/3 of accounts from previous slots
    let mut addresses = utils::AddrMixer::new(3);
    let mut rng = rand::thread_rng();

    for slot in 0..params.n_slots {
        addresses.advance();

        if rng.gen_ratio(params.accounts_per_100k as u32, 100_000) {
            let (address, account) = (addresses.some_addr(), utils::some_account());
            state.set_account_state(address, account);

            // TODO: add some transactions into state
            // if rng.gen() {
            //     state.set_transaction(
            //         H256::random(),
            //         iter::repeat_with(random)
            //             .take(rng.gen_range(0..=2 * BIG_TX_AVERAGE_SIZE))
            //             .collect(),
            //     );
            // }
        }

        let committed = state.clone().commit_block(slot, Default::default());
        *state = committed.next_incomming(0);

        state
            .kvs()
            .register_slot(slot, state.last_root(), false)
            .unwrap();

        if params.with_gc {
            if slot % params.squash_each == 0 {
                for remove_slot in (slot - params.squash_each)..slot {
                    let (mut direct, mut indirect): (Vec<_>, Vec<_>) = (
                        state
                            .kvs()
                            .purge_slot(remove_slot)
                            .unwrap()
                            .into_iter()
                            .collect(),
                        vec![],
                    );
                    while !direct.is_empty() {
                        let childs = state.kvs().gc_try_cleanup_account_hashes(&direct);

                        direct = childs.0;
                        indirect.extend_from_slice(&childs.1);
                    }
                    while !indirect.is_empty() {
                        let childs = state.kvs().gc_try_cleanup_account_hashes(&direct);

                        indirect = childs.0;
                    }
                }
            }
        }
    }
}

fn fill_bd_with_gc_squash(c: &mut Criterion) {
    let mut group = c.benchmark_group("fill_bd_with_gc_squash");
    group.sample_size(10);

    vec![(100_00, 100, 1_000), (1_000_00, 1_000, 1_000)]
        .into_iter()
        .flat_map(|(n_slots, squash_each, accounts_per_100k)| {
            Params::new(n_slots, squash_each, accounts_per_100k)
        })
        .for_each(|params| {
            let _persist = group.bench_with_input(
                BenchmarkId::from_parameter(&params),
                &params,
                |b, _params| {
                    b.iter(|| {
                        let dir = tempdir().unwrap();
                        let evm_state = EvmState::new(&dir)
                            .expect("Unable to create new EVM state in temporary directory");
                        let mut state = match evm_state {
                            EvmState::Incomming(i) => i,
                            _ => unreachable!(),
                        };
                        add_some_and_advance(&mut state, &params);
                    })
                },
            );
        });
}

fn fill_new_db_then_backup(c: &mut Criterion) {
    let mut group = c.benchmark_group("fill then backup once");
    group.sample_size(10);

    vec![(100_000, 100, 1_000), (1_000_000, 1_000, 1_000)]
        .into_iter()
        .map(|(n_slots, squash_each, accounts_per_100k)| Params {
            n_slots,
            squash_each,
            accounts_per_100k,
            with_gc: false,
        })
        .for_each(|params| {
            let dir = tempdir().unwrap();

            let evm_state =
                EvmState::new(&dir).expect("Unable to create new EVM state in temporary directory");
            let mut state = match evm_state {
                EvmState::Incomming(i) => i,
                _ => unreachable!(),
            };
            add_some_and_advance(&mut state, &params);

            let evm_state = EvmState::Incomming(state);
            assert!(
                evm_state.kvs_references() == 1,
                "Ensure that only one kvs users left."
            );
            let persist_state = evm_state.save_state();

            let _persist = group.bench_with_input(
                BenchmarkId::from_parameter(&params),
                &params,
                |b, _params| {
                    b.iter_batched(
                        || {
                            let evm_state = EvmState::load_from(&dir, persist_state.clone(), false)
                                .expect("Unable to create new EVM state in temporary directory");

                            let empty_dir = tempdir().unwrap();
                            assert_eq!(0, fs::read_dir(&empty_dir).unwrap().count());

                            (evm_state, empty_dir)
                        },
                        |(state, target_dir)| {
                            let _ = state.make_backup().expect(
                                "Unable to save EVM state storage data into temporary directory",
                            );
                            (state, target_dir) // drop outside
                        },
                        BatchSize::NumIterations(1),
                    )
                },
            );
        });
}

fn fill_new_db_then_backup_and_then_backup_again(c: &mut Criterion) {
    // let _ = simple_logger::SimpleLogger::default().init();
    let mut group = c.benchmark_group("fill then backup twice");
    group.sample_size(10);

    vec![
        (100_000, 100_000, 100, 1_000),
        (200_000, 100_000, 1_000, 1_000),
    ]
    .into_iter()
    .map(
        |(n_slots, another_n_slots, squash_each, accounts_per_100k)| {
            (
                Params {
                    n_slots,
                    squash_each,
                    accounts_per_100k,
                    with_gc: false,
                },
                Params {
                    n_slots: another_n_slots,
                    squash_each,
                    accounts_per_100k,
                    with_gc: false,
                },
            )
        },
    )
    .for_each(|(params1, params2)| {
        let dir = tempdir().unwrap();

        let mut state = EvmBackend::new(
            Incomming::default(),
            Storage::open_persistent(
                &dir, true, // gc_enabled = true
            )
            .unwrap(),
        );

        add_some_and_advance(&mut state, &params1);
        let evm_state = EvmState::Incomming(state);
        assert!(
            evm_state.kvs_references() == 1,
            "Ensure that only one kvs users left."
        );
        let persist_state = evm_state.save_state();
        log::info!(" Persist state = {:?}", persist_state);
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{} => {}", &params1, &params2)),
            &params2,
            |b, _params| {
                b.iter_batched(
                    || {
                        let evm_state = EvmState::load_from(&dir, persist_state.clone(), false)
                            .expect("Unable to create new EVM state in temporary directory");
                        let _ = evm_state.make_backup().unwrap();
                        let mut state = match evm_state {
                            EvmState::Incomming(i) => i,
                            _ => unreachable!(),
                        };
                        add_some_and_advance(&mut state, &params2);
                        EvmState::Incomming(state)
                    },
                    |state| {
                        let _ = state.make_backup().unwrap();
                        state // drop outside
                    },
                    BatchSize::NumIterations(1),
                )
            },
        );
    });
}

criterion_group!(
    evm_save,
    fill_new_db_then_backup,
    fill_new_db_then_backup_and_then_backup_again,
    fill_bd_with_gc_squash,
);
criterion_main!(evm_save);
