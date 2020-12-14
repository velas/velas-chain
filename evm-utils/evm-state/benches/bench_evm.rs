use std::fs;
use std::path::{Path, PathBuf};

use criterion::{criterion_group, criterion_main, Criterion, Throughput};

use anyhow::{bail, Context, Result};
use assert_matches::assert_matches;
use evm::{Capture, CreateScheme, ExitReason, ExitSucceed, Handler};
use primitive_types::{H160, H256, U256};
use sha3::{Digest, Keccak256};

use evm_state::{layered_backend::*, *};

fn name_to_key(name: &str) -> H160 {
    let hash = H256::from_slice(Keccak256::digest(name.as_bytes()).as_slice());
    hash.into()
}

fn prepare_dir<P: AsRef<Path>>(path: P) -> Result<PathBuf> {
    let path = path.as_ref();
    if path.exists() {
        bail!("Path {} is already exists", path.display());
    }
    fs::create_dir_all(path).context("Unable to create for bench data")?;
    Ok(path.to_owned())
}

fn cleanup_dir<P: AsRef<Path>>(path: P) -> Result<()> {
    let path = path.as_ref();
    if !path.exists() {
        bail!("Path {} is not exists", path.display());
    }
    fs::remove_dir_all(path).context("Clean-up")?;
    Ok(())
}

fn criterion_benchmark(c: &mut Criterion) {
    // simple_logger::SimpleLogger::new().init().unwrap();

    let mut group = c.benchmark_group("Evm");
    group.throughput(Throughput::Elements(1));

    group.bench_function("call_hello", |b| {
        let accounts = ["contract", "caller"];

        let code = hex::decode(HELLO_WORLD_CODE).unwrap();
        let data = hex::decode(HELLO_WORLD_ABI).unwrap();

        let dir = prepare_dir("call_hello").unwrap();
        let mut state = EvmState::load_from(&dir, 0).unwrap();

        for acc in &accounts {
            let account = name_to_key(acc);
            let memory = AccountState {
                ..Default::default()
            };
            state.accounts.insert(account, memory);
        }

        let config = evm::Config::istanbul();
        let mut executor = StaticExecutor::with_config(state, config, usize::max_value());

        let exit_reason = match executor.rent_executor().create(
            name_to_key("caller"),
            CreateScheme::Fixed(name_to_key("contract")),
            U256::zero(),
            code,
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

        cleanup_dir(dir).unwrap();
    });

    group.bench_function("call_hello_on_dumped_state", |b| {
        let accounts = ["contract", "caller"];

        let code = hex::decode(HELLO_WORLD_CODE).unwrap();
        let data = hex::decode(HELLO_WORLD_ABI).unwrap();

        let dir = prepare_dir("call_hello_on_dumped_state").unwrap();
        let mut state = EvmState::load_from(&dir, 0).unwrap();

        for acc in &accounts {
            let account = name_to_key(acc);
            let memory = AccountState {
                ..Default::default()
            };
            state.accounts.insert(account, memory);
        }
        state.dump().unwrap();

        let config = evm::Config::istanbul();
        let mut executor = StaticExecutor::with_config(state, config, usize::max_value());

        let exit_reason = match executor.rent_executor().create(
            name_to_key("caller"),
            CreateScheme::Fixed(name_to_key("contract")),
            U256::zero(),
            code,
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

        cleanup_dir(dir).unwrap();
    });

    group.finish();
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
