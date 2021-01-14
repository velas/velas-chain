use std::{collections::HashSet, iter, time::Instant};

use rand::{prelude::IteratorRandom, random, Rng};

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

use evm_state::{
    types::{AccountState, Slot, H160 as Address, U256},
    EvmState,
};

const AVERAGE_DATA_SIZE: usize = 2 * 1024;

fn some_account() -> AccountState {
    AccountState {
        nonce: U256::from(random::<u64>()),
        balance: U256::from(random::<u64>()),
        code: iter::repeat_with(random)
            .take(rand::thread_rng().gen_range(0, 2 * AVERAGE_DATA_SIZE))
            .collect(),
    }
}

fn unique_random_accounts() -> impl Iterator<Item = (Address, AccountState)> {
    let mut addresses = HashSet::new();

    iter::repeat_with(Address::random)
        .filter(move |addr| addresses.insert(*addr))
        .zip(iter::repeat_with(some_account))
}

/// Random accounts generator with chance to repeat existing address as 1 / repeat_prob
struct AddrMixer {
    repeat_prob: u32,
    current: HashSet<Address>,
    previous: HashSet<Address>,
}

impl AddrMixer {
    fn new(repeat_prob: u32) -> Self {
        Self {
            repeat_prob,
            current: HashSet::new(),
            previous: HashSet::new(),
        }
    }

    fn next(&mut self) -> Address {
        let mut rng = rand::thread_rng();
        if rng.gen_ratio(1, self.repeat_prob) {
            match self.previous.iter().choose(&mut rng) {
                Some(addr) => *addr,
                None => self.new_addr(),
            }
        } else {
            self.new_addr()
        }
    }

    fn new_addr(&mut self) -> Address {
        loop {
            let addr = random();
            if !self.previous.contains(&addr) && self.current.insert(addr) {
                return addr;
            }
        }
    }

    fn advance(&mut self) {
        self.previous.extend(self.current.drain());
    }
}

fn squashed_state_bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("squashed_state");
    group.throughput(Throughput::Elements(1));
    const N_ACCOUNTS: usize = 1024;

    for (n_forks, squash_target) in vec![
        (0, None),
        (1, None),
        (10, None),
        (20, None),
        (40, None),
        (100, None),
        (100, Some(100)),
        (120, Some(100)),
        (140, Some(100)),
        (200, Some(100)),
        (240, Some(200)),
        (400, Some(200)),
        (800, Some(400)),
    ] {
        let slot = Slot::default();
        let mut state = EvmState::default();

        let accounts: Vec<(Address, AccountState)> =
            unique_random_accounts().take(N_ACCOUNTS).collect();

        for (address, account) in accounts.iter().cloned() {
            state.set_account(address, account);
        }

        for slot in (slot + 1)..=n_forks {
            state.freeze();
            if squash_target == Some(slot) {
                state.squash();
            }
            state = state.try_fork(slot).expect("Unable to fork EVM state");
        }

        group.bench_with_input(
            BenchmarkId::new(
                "get_account",
                format!(" {} forks, squashed on {:?}", n_forks, squash_target),
            ),
            &n_forks,
            move |b, _| {
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
            },
        );
    }
    group.finish();

    let mut group = c.benchmark_group("squash_time");
    group.sample_size(10);

    const ACCOUNTS_PER_SLOT: usize = 12;

    for squash_targets in vec![
        (None, 0),
        (None, 1),
        (None, 10),
        (None, 50),
        (None, 100),
        (Some(100), 101),
        (Some(100), 110),
        (Some(100), 150),
        (Some(100), 200),
        (None, 1000),
        (Some(1000), 2000),
        (None, 10000),
        (Some(5000), 10000),
        (Some(9000), 10000),
    ] {
        group.bench_with_input(
            BenchmarkId::new(
                "squash",
                format!(
                    " first on {:?}, then {}",
                    squash_targets.0, squash_targets.1
                ),
            ),
            &squash_targets,
            move |b, (squash_target_1, squash_target_2)| {
                b.iter_with_large_setup(
                    || {
                        let slot = Slot::default();
                        let mut state = EvmState::default();

                        // repeat 1/3 of accounts from previous slots
                        let mut addresses = AddrMixer::new(3);

                        for new_slot in (slot + 1)..=*squash_target_2 {
                            addresses.advance();
                            for _ in 0..ACCOUNTS_PER_SLOT {
                                let (address, account) = (addresses.next(), some_account());
                                state.set_account(address, account);
                            }

                            state.freeze();
                            if squash_target_1.as_ref() == Some(&new_slot) {
                                state.squash();
                            }
                            state = state.try_fork(new_slot).expect("Unable to fork EVM state");
                        }
                        state
                    },
                    move |mut state| {
                        state.freeze();
                        state.squash();
                    },
                );
            },
        );
    }

    group.finish();
}

criterion_group!(squashed_state, squashed_state_bench);
criterion_main!(squashed_state);
