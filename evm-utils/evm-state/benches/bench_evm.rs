use std::fs;
use std::path::{Path, PathBuf};

use criterion::{criterion_group, criterion_main, Criterion, Throughput};

use anyhow::{bail, Context, Result};
use evm::{ExitReason, ExitSucceed};
use evm_state::*;
use primitive_types::{H160, H256, U256};
use sha3::{Digest, Keccak256};

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
    let mut group = c.benchmark_group("Evm");
    group.throughput(Throughput::Elements(1));

    group.bench_function("call_hello", |b| {
        let code = hex::decode(HELLO_WORLD_CODE).unwrap();
        let data = hex::decode(HELLO_WORLD_ABI).unwrap();
        let accounts = ["contract", "caller"];

        let dir = prepare_dir("call_hello").unwrap();
        let mut state = EvmState::load_from(&dir, 0).unwrap();

        for acc in &accounts {
            let account = name_to_key(acc);
            let memory = AccountState {
                ..Default::default()
            };
            state.set_account(account, memory);
        }

        let config = evm::Config::istanbul();
        let mut executor = Executor::with_config(state.clone(), config, usize::max_value(), 0);

        let exit_reason = executor.with_executor(|executor| {
            executor.transact_create(
                name_to_key("caller"),
                U256::zero(),
                code,
                usize::max_value(),
            )
        });
        let contract_address = TransactionAction::Create.address(name_to_key("caller"), 0.into());
        assert!(matches!(
            exit_reason,
            ExitReason::Succeed(ExitSucceed::Returned)
        ));

        b.iter(|| {
            let exit_reason = executor.with_executor(|executor| {
                executor.transact_call(
                    name_to_key("caller"),
                    contract_address,
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

        cleanup_dir(dir).unwrap();
    });

    group.bench_function("call_hello_with_executor_recreate", |b| {
        let code = hex::decode(HELLO_WORLD_CODE).unwrap();
        let data = hex::decode(HELLO_WORLD_ABI).unwrap();

        let dir = prepare_dir("call_hello_with_executor_recreate").unwrap();
        let mut state = EvmState::load_from(&dir, 0).unwrap();
        let config = evm::Config::istanbul();

        let mut executor =
            Executor::with_config(state.clone(), config.clone(), usize::max_value(), 0);

        let exit_reason = executor.with_executor(|executor| {
            executor.transact_create(
                name_to_key("caller"),
                U256::zero(),
                code,
                usize::max_value(),
            )
        });
        assert!(matches!(
            exit_reason,
            ExitReason::Succeed(ExitSucceed::Returned)
        ));

        let contract_address = TransactionAction::Create.address(name_to_key("caller"), 0.into());
        let patch = executor.deconstruct();
        state.swap_commit(patch);

        b.iter(|| {
            let mut executor =
                Executor::with_config(state.clone(), config.clone(), usize::max_value(), 0);
            let exit_reason = executor.with_executor(|executor| {
                executor.transact_call(
                    name_to_key("caller"),
                    contract_address,
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
            state.set_account(account, memory);
        }
        state.freeze();

        let config = evm::Config::istanbul();
        let mut executor =
            Executor::with_config(state.clone(), config.clone(), usize::max_value(), 0);

        let exit_reason = executor.with_executor(|executor| {
            executor.transact_create(
                name_to_key("caller"),
                U256::zero(),
                code,
                usize::max_value(),
            )
        });
        assert!(matches!(
            exit_reason,
            ExitReason::Succeed(ExitSucceed::Returned),
        ));

        let patch = executor.deconstruct();
        state.swap_commit(patch);

        state.freeze();

        let contract_address = TransactionAction::Create.address(name_to_key("caller"), 0.into());
        b.iter(|| {
            let mut executor =
                Executor::with_config(state.clone(), config.clone(), usize::max_value(), 0);
            let exit_reason = executor.with_executor(|executor| {
                executor.transact_call(
                    name_to_key("caller"),
                    contract_address,
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

        cleanup_dir(dir).unwrap();
    });

    group.finish();
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
