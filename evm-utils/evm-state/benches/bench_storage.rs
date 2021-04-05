use std::fs;

use derive_more::Display;
use rand::Rng;
use tempfile::tempdir;

use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion};

use evm_state::{types::BlockNum, EvmState};

mod utils;

#[derive(Clone, Display)]
#[display(
    fmt = "total slots {}, squash each {} slot, {} accounts per 100k slots",
    n_slots,
    squash_each,
    accounts_per_100k
)]
struct Params {
    n_slots: BlockNum,
    squash_each: BlockNum,
    accounts_per_100k: usize,
}

fn add_some_and_advance(state: &mut EvmState, params: &Params) {
    // repeat 1/3 of accounts from previous slots
    let mut addresses = utils::AddrMixer::new(3);
    let mut rng = rand::thread_rng();

    for _ in 0..params.n_slots {
        let slot = state.block_num;
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

        state.commit_block(0);
        *state = state.fork(slot + 1);
    }

    state.commit_block(0);
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
        })
        .for_each(|params| {
            let dir = tempdir().unwrap();

            let mut state =
                EvmState::new(&dir).expect("Unable to create new EVM state in temporary directory");
            add_some_and_advance(&mut state, &params);

            let slot = state.block_num;
            let root = state.root;
            drop(state);

            group.bench_with_input(
                BenchmarkId::from_parameter(&params),
                &params,
                |b, _params| {
                    b.iter_batched(
                        || {
                            let state = EvmState::load_from(
                                &dir,
                                evm_state::types::EvmStatePersistFields::Empty {
                                    block_number: slot,
                                    state_root: root,
                                },
                            )
                            .expect("Unable to load EVM state from temporary directory");

                            let empty_dir = tempdir().unwrap();
                            assert_eq!(0, fs::read_dir(&empty_dir).unwrap().count());

                            (state, empty_dir)
                        },
                        |(state, target_dir)| {
                            let _ = state.kvs.backup().expect(
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
                },
                Params {
                    n_slots: another_n_slots,
                    squash_each,
                    accounts_per_100k,
                },
            )
        },
    )
    .for_each(|(params1, params2)| {
        let dir = tempdir().unwrap();

        let mut state =
            EvmState::new(&dir).expect("Unable to create new EVM state in temporary directory");
        add_some_and_advance(&mut state, &params1);

        let slot = state.block_num;
        let root = state.root;
        drop(state);

        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{} => {}", &params1, &params2)),
            &params2,
            |b, _params| {
                b.iter_batched(
                    || {
                        let mut state = EvmState::load_from(
                            &dir,
                            evm_state::types::EvmStatePersistFields::Empty {
                                block_number: slot,
                                state_root: root,
                            },
                        )
                        .expect("Unable to load EVM state from temporary directory");

                        let _ = state.kvs.backup().unwrap();

                        add_some_and_advance(&mut state, &params2);

                        state
                    },
                    |state| {
                        let _ = state.kvs.backup().unwrap();
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
);
criterion_main!(evm_save);
