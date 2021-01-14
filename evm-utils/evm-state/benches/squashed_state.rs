use std::{collections::HashMap, iter, time::Instant};

use rand::random;
use tempfile::TempDir;

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

use evm_state::{
    types::{AccountState, Slot, H160 as Address, U256},
    EvmState,
};

const N_ACCOUNTS: usize = 1024;
const AVERAGE_DATA_SIZE: usize = 2 * 1024;

fn some_account() -> AccountState {
    AccountState {
        nonce: U256::from(random::<u64>()),
        balance: U256::from(random::<u64>()),
        code: iter::repeat_with(random).take(AVERAGE_DATA_SIZE).collect(),
    }
}

fn squashed_state_bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("squashed_state");
    group.throughput(Throughput::Elements(1));

    for &layers in &[0, 1, 10, 20, 40, 100, 120, 140, 200, 240, 400, 800] {
        let state_dir = TempDir::new().expect("Unable to create temporary directory");

        let slot = Slot::default();
        let mut state = EvmState::load_from(state_dir.path(), slot)
            .expect("Unable to open storage in temporary directory");

        let accounts = iter::repeat_with(|| (Address::random(), some_account()))
            .take(N_ACCOUNTS)
            .collect::<HashMap<_, _>>()
            .into_iter()
            .collect::<Vec<_>>();

        for (address, account) in accounts.iter().cloned() {
            state.set_account(address, account);
        }

        for layer in slot + 1..=layers {
            state.freeze();
            state = state.try_fork(layer).expect("Unable to fork EVM state");
        }

        if layers % 100 == 0 {
            state.freeze();
            state.squash();
        }

        group.bench_with_input(BenchmarkId::from_parameter(layers), &layers, move |b, _| {
            let accounts = &accounts;
            let state = &state;

            b.iter_custom(move |iters| {
                let start = Instant::now();

                for idx in 0..iters {
                    let (address, account) = &accounts[idx as usize % accounts.len()];
                    black_box({
                        let acc = state.get_account(*address);
                        assert_eq!(acc.as_ref(), Some(account));
                        acc
                    });
                }

                start.elapsed()
            });
        });
    }
    group.finish();
}

criterion_group!(squashed_state, squashed_state_bench);
criterion_main!(squashed_state);
