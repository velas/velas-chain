use std::path::{Path, PathBuf};

use anyhow::{ensure, Result};
use clap::{value_t_or_exit, App, AppSettings, Arg, ArgMatches, SubCommand};
use log::*;
use solana_clap_utils::ArgConstant;

use evm_state::storage::{
    inspectors::verifier::{AccountsVerifier, HashVerifier},
    inspectors::NoopInspector,
    walker::Walker,
};
use rayon::prelude::*;

use evm_state::{
    storage::cleaner,
    storage::{inspectors, Storage},
    H256,
};
// use rayon::prelude::*;

pub trait EvmStateSubCommand {
    fn evm_state_subcommand(self) -> Self;
}

const ROOT_ARG: ArgConstant<'static> = ArgConstant {
    name: "root",
    long: "root",
    help: "EVM state root hash",
};

impl EvmStateSubCommand for App<'_, '_> {
    fn evm_state_subcommand(self) -> Self {
        self.subcommand(
            SubCommand::with_name("evm_state")
                .about("EVM state utilities")
                .setting(AppSettings::ArgRequiredElseHelp)
                .subcommand(
                    SubCommand::with_name("purge")
                        .about("Cleanup EVM state data unreachable from state root")
                        .arg(
                            Arg::with_name(ROOT_ARG.name)
                                .long(ROOT_ARG.long)
                                .required(true)
                                .takes_value(true)
                                .help(ROOT_ARG.help),
                        )
                        .arg(
                            Arg::with_name("dry_run")
                                .long("dry-run")
                                .help("Do nothing, just collect hashes and print them"),
                        ),
                )
                .subcommand(
                    SubCommand::with_name("copy")
                        .about("Copy EVM accounts state into destination RocksDB")
                        .setting(AppSettings::ArgRequiredElseHelp)
                        .arg(
                            Arg::with_name(ROOT_ARG.name)
                                .long(ROOT_ARG.long)
                                .required(true)
                                .takes_value(true)
                                .help(ROOT_ARG.help),
                        )
                        .arg(
                            Arg::with_name("destination")
                                .long("destination")
                                .required(true)
                                .takes_value(true)
                                .help("Path to destination RocksDB"),
                        ),
                )
                .subcommand(
                    SubCommand::with_name("verify")
                        .about("Verify hashes of data reachable from state root")
                        .setting(AppSettings::ArgRequiredElseHelp)
                        .arg(
                            Arg::with_name(ROOT_ARG.name)
                                .long(ROOT_ARG.long)
                                .required(true)
                                .takes_value(true)
                                .help(ROOT_ARG.help),
                        ),
                ),
        )
    }
}

pub fn process_evm_state_command(ledger_path: &Path, matches: &ArgMatches<'_>) -> Result<()> {
    let evm_state_path = ledger_path.join("evm-state");
    let storage = Storage::open_persistent(evm_state_path)?;

    match matches.subcommand() {
        ("purge", Some(matches)) => {
            let root = value_t_or_exit!(matches, ROOT_ARG.name, H256);
            let is_dry_run = matches.is_present("dry_run");

            ensure!(storage.check_root_exist(root));
            let db = storage.db();

            if is_dry_run {
                info!("Dry run, do nothing after collecting keys ...");
            }

            let trie_collector =
                std::sync::Arc::new(inspectors::memorizer::TrieCollector::default());
            let accounts = {
                let accounts_state_walker = Walker::new_sec_encoding(
                    db,
                    trie_collector.clone(),
                    inspectors::memorizer::AccountStorageRootsCollector::default(),
                );
                accounts_state_walker.traverse(root)?;
                accounts_state_walker.data_inspector.inner.summarize();

                println!("Account trie nodes info:");
                trie_collector.summarize();
                let storages_walker = Walker::new_raw(db, trie_collector.clone(), NoopInspector);
                for storage_root in accounts_state_walker
                    .data_inspector
                    .inner
                    .storage_roots
                    .iter()
                {
                    storages_walker.traverse(*storage_root)?;
                }
                println!("Total trie nodes info:");
                storages_walker.trie_inspector.summarize();
                accounts_state_walker.data_inspector.inner
            };

            if !is_dry_run {
                let cleaner = cleaner::Cleaner::new_with(db, trie_collector, accounts);
                cleaner.cleanup()?;
            }
        }
        ("copy", Some(matches)) => {
            let root = value_t_or_exit!(matches, ROOT_ARG.name, H256);
            let destination = value_t_or_exit!(matches, "destination", PathBuf);

            ensure!(storage.check_root_exist(root));
            let destination = Storage::open_persistent(destination)?;

            let source = storage.clone();
            let streamer = inspectors::streamer::AccountsStreamer {
                source,
                destination,
            };
            let walker = Walker::new_shared(storage, streamer);
            walker.traverse(root)?;
        }
        ("verify", Some(matches)) => {
            let root = value_t_or_exit!(matches, ROOT_ARG.name, H256);

            assert!(storage.check_root_exist(root));
            let db = storage.db();

            let accounts_verifier = AccountsVerifier::new(storage.clone());
            let walker = Walker::new_sec_encoding(db, HashVerifier, accounts_verifier);
            walker.traverse(root)?;

            walker
                .data_inspector
                .inner
                .storage_roots
                .into_par_iter()
                .try_for_each(|storage_root| {
                    Walker::new_raw(db, HashVerifier, NoopInspector).traverse(storage_root)
                })?
        }
        unhandled => panic!("Unhandled {:?}", unhandled),
    }
    Ok(())
}
