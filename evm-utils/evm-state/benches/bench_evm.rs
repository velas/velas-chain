use criterion::{criterion_group, criterion_main, Criterion, Throughput};

use assert_matches::assert_matches;
use evm::{Capture, CreateScheme, ExitReason, ExitSucceed};
use evm_state::*;

use primitive_types::{H160, H256, U256};
use sha3::{Digest, Keccak256};
use std::sync::RwLock;

fn name_to_key(name: &str) -> H160 {
    let hash = H256::from_slice(Keccak256::digest(name.as_bytes()).as_slice());
    hash.into()
}

fn criterion_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("Evm");

    group.throughput(Throughput::Elements(1 as u64));
    // simple_logger::SimpleLogger::new().init().unwrap();

    group.bench_function("call_hello", |b| {
        let code = hex::decode(HELLO_WORLD_CODE).unwrap();
        let data = hex::decode(HELLO_WORLD_ABI).unwrap();

        let config = evm::Config::istanbul();
        let backend = EvmState::new();

        let backend = RwLock::new(backend);

        let mut executor = Executor::with_config(
            backend.read().unwrap().clone(),
            config,
            usize::max_value(),
            0,
        );

        let exit_reason = match executor.with_executor(|e| {
            e.create(
                name_to_key("caller"),
                CreateScheme::Fixed(name_to_key("contract")),
                U256::zero(),
                code.clone(),
                None,
            )
        }) {
            Capture::Exit((s, _, v)) => (s, v),
            Capture::Trap(_) => unreachable!(),
        };

        assert_matches!(exit_reason, (ExitReason::Succeed(ExitSucceed::Returned), _));

        b.iter(|| {
            let exit_reason = executor.with_executor(|e| {
                e.transact_call(
                    name_to_key("contract"),
                    name_to_key("contract"),
                    U256::zero(),
                    data.to_vec(),
                    usize::max_value(),
                )
            });

            let result = hex::decode(HELLO_WORLD_RESULT).unwrap();
            match exit_reason {
                (ExitReason::Succeed(ExitSucceed::Returned), res) if res == result => {}
                any_other => panic!("Not expected result={:?}", any_other),
            }
        });
    });

    group.bench_function("call_hello_with_executor_recreate", |b| {
        let accounts = ["contract", "caller"];

        let code = hex::decode(HELLO_WORLD_CODE).unwrap();
        let data = hex::decode(HELLO_WORLD_ABI).unwrap();

        let config = evm::Config::istanbul();
        let backend = EvmState::new();

        let backend = RwLock::new(backend);
        let mut executor = Executor::with_config(
            backend.read().unwrap().clone(),
            config.clone(),
            usize::max_value(),
            0,
        );

        let exit_reason = match executor.with_executor(|e| {
            e.create(
                name_to_key("caller"),
                CreateScheme::Fixed(name_to_key("contract")),
                U256::zero(),
                code.clone(),
                None,
            )
        }) {
            Capture::Exit((s, _, v)) => (s, v),
            Capture::Trap(_) => unreachable!(),
        };

        assert_matches!(exit_reason, (ExitReason::Succeed(ExitSucceed::Returned), _));
        let patch = executor.deconstruct();
        backend.write().unwrap().swap_commit(patch);

        b.iter(|| {
            let mut executor = Executor::with_config(
                backend.read().unwrap().clone(),
                config.clone(),
                usize::max_value(),
                1,
            );
            let exit_reason = executor.with_executor(|e| {
                e.transact_call(
                    name_to_key("contract"),
                    name_to_key("contract"),
                    U256::zero(),
                    data.to_vec(),
                    usize::max_value(),
                )
            });

            let result = hex::decode(HELLO_WORLD_RESULT).unwrap();
            match exit_reason {
                (ExitReason::Succeed(ExitSucceed::Returned), res) if res == result => {}
                any_other => panic!("Not expected result={:?}", any_other),
            }
        });
    });
    group.finish();
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
