use criterion::{criterion_group, criterion_main, Criterion, Throughput};

use assert_matches::assert_matches;
use evm::{Capture, CreateScheme, ExitReason, ExitSucceed, Handler};
use evm_state::layered_backend::*;
use evm_state::*;
use hex;

use primitive_types::{H160, H256, U256};
use sha3::{Digest, Keccak256};
use std::sync::RwLock;

fn name_to_key(name: &str) -> H160 {
    let hash = H256::from_slice(Keccak256::digest(name.as_bytes()).as_slice());
    hash.into()
}

fn criterion_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("Evm");
    // group.throughput(Throughput::Elements(1 as u64));
    // group.bench_function("create_hello", |b| {
    //     let accounts = ["contract", "caller"];

    //     let code = hex::decode(HELLO_WORLD_CODE).unwrap();
    //     let data = hex::decode(HELLO_WORLD_ABI).unwrap();

    //     let vicinity = MemoryVicinity {
    //         gas_price: U256::zero(),
    //         origin: H160::default(),
    //         chain_id: U256::zero(),
    //         block_hashes: Vec::new(),
    //         block_number: U256::zero(),
    //         block_coinbase: H160::default(),
    //         block_timestamp: U256::zero(),
    //         block_difficulty: U256::zero(),
    //         block_gas_limit: U256::max_value(),
    //     };
    //     let config = evm::Config::istanbul();
    //     let backend = EvmState::new(vicinity);

    //     let backend = RwLock::new(backend);

    //     let mut locked = EvmState::try_lock(&backend).unwrap();

    //     {
    //         let state = locked.fork_mut();

    //         for acc in &accounts {
    //             let account = name_to_key(acc);
    //             let memory = AccountState {
    //                 ..Default::default()
    //             };
    //             state.accounts.insert(account, memory);
    //         }
    //     }

    //     let mut executor =
    //         StaticExecutor::with_config(locked.backend(), config, usize::max_value());

    //     b.iter(|| {
    //         let exit_reason = match executor.rent_executor().create(
    //             name_to_key("caller"),
    //             CreateScheme::Fixed(name_to_key("contract")),
    //             U256::zero(),
    //             code.clone(),
    //             None,
    //         ) {
    //             Capture::Exit((s, _, v)) => (s, v),
    //             Capture::Trap(_) => unreachable!(),
    //         };

    //         assert_matches!(exit_reason, (ExitReason::Succeed(ExitSucceed::Returned), _));

    //     })
    // });

    group.throughput(Throughput::Elements(1 as u64));
    // simple_logger::SimpleLogger::new().init().unwrap();
    group.bench_function("call_hello", |b| {
        let accounts = ["contract", "caller"];

        let code = hex::decode(HELLO_WORLD_CODE).unwrap();
        let data = hex::decode(HELLO_WORLD_ABI).unwrap();

        let vicinity = MemoryVicinity {
            gas_price: U256::zero(),
            origin: H160::default(),
            chain_id: U256::zero(),
            block_hashes: Vec::new(),
            block_number: U256::zero(),
            block_coinbase: H160::default(),
            block_timestamp: U256::zero(),
            block_difficulty: U256::zero(),
            block_gas_limit: U256::max_value(),
        };
        let config = evm::Config::istanbul();
        let backend = EvmState::new(vicinity);

        let backend = RwLock::new(backend);

        let mut locked = EvmState::try_lock(&backend).unwrap();

        {
            let state = locked.fork_mut();

            for acc in &accounts {
                let account = name_to_key(acc);
                let memory = AccountState {
                    ..Default::default()
                };
                state.accounts.insert(account, memory);
            }
        }

        let mut executor =
            StaticExecutor::with_config(locked.backend(), config, usize::max_value());

        let exit_reason = match executor.rent_executor().create(
            name_to_key("caller"),
            CreateScheme::Fixed(name_to_key("contract")),
            U256::zero(),
            code.clone(),
            None,
        ) {
            Capture::Exit((s, _, v)) => (s, v),
            Capture::Trap(_) => unreachable!(),
        };

        assert_matches!(exit_reason, (ExitReason::Succeed(ExitSucceed::Returned), _));

        b.iter(|| {
            let exit_reason = executor.rent_executor().transact_call(
                name_to_key("contract"),
                name_to_key("contract"),
                U256::zero(),
                data.to_vec(),
                usize::max_value(),
            );

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

        let vicinity = MemoryVicinity {
            gas_price: U256::zero(),
            origin: H160::default(),
            chain_id: U256::zero(),
            block_hashes: Vec::new(),
            block_number: U256::zero(),
            block_coinbase: H160::default(),
            block_timestamp: U256::zero(),
            block_difficulty: U256::zero(),
            block_gas_limit: U256::max_value(),
        };
        let config = evm::Config::istanbul();
        let backend = EvmState::new(vicinity);

        let backend = RwLock::new(backend);

        let mut locked = EvmState::try_lock(&backend).unwrap();

        {
            let state = locked.fork_mut();

            for acc in &accounts {
                let account = name_to_key(acc);
                let memory = AccountState {
                    ..Default::default()
                };
                state.accounts.insert(account, memory);
            }
        }

        let mut executor =
            StaticExecutor::with_config(locked.backend(), config.clone(), usize::max_value());

        let exit_reason = match executor.rent_executor().create(
            name_to_key("caller"),
            CreateScheme::Fixed(name_to_key("contract")),
            U256::zero(),
            code.clone(),
            None,
        ) {
            Capture::Exit((s, _, v)) => (s, v),
            Capture::Trap(_) => unreachable!(),
        };

        assert_matches!(exit_reason, (ExitReason::Succeed(ExitSucceed::Returned), _));
        let patch = executor.deconstruct();
        locked.apply(patch);

        b.iter(|| {
            let mut executor =
                StaticExecutor::with_config(locked.backend(), config.clone(), usize::max_value());
            let exit_reason = executor.rent_executor().transact_call(
                name_to_key("contract"),
                name_to_key("contract"),
                U256::zero(),
                data.to_vec(),
                usize::max_value(),
            );

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
