/// The `bigtable` subcommand
use clap::{value_t, value_t_or_exit, App, AppSettings, Arg, ArgMatches, SubCommand};
use solana_clap_utils::input_validators::is_slot;

use solana_ledger::{blockstore::Blockstore, blockstore_db::AccessType};
use solana_sdk::clock::Slot;
use std::{path::Path, process::exit, result::Result};

pub fn modify_block(
    blockstore: Blockstore,
    block_num: evm_state::BlockNum,
    native_slot: Slot,
    native_hash: evm_state::H256,
    timestamp: Option<u64>,
    skip_consistency_check: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut block, confirmed) = blockstore.get_evm_block(block_num)?;
    println!("Found block = {:?}, confirmed = {}", block, confirmed);
    block.header.native_chain_hash = native_hash;
    block.header.native_chain_slot = native_slot;
    if let Some(timestamp) = timestamp {
        block.header.timestamp = timestamp;
    }
    if !skip_consistency_check {
        let (next_block, confirmed) = blockstore.get_evm_block(block_num + 1)?;

        println!(
            "Next block num = {}, parent_hash = {:?}, confirmed = {}",
            next_block.header.block_number, next_block.header.parent_hash, confirmed
        );
        if block.header.hash() != next_block.header.parent_hash {
            return Err(format!(
                "Block hash not equal next blocks parent (inconsistent chain), {:?} != {:?}",
                block.header.hash(),
                next_block.header.parent_hash
            )
            .into());
        }
    }
    blockstore
        .write_evm_block_header(&block.header)
        .expect("Expected database write to succed");
    for (hash, tx) in block.transactions {
        blockstore
            .write_evm_transaction(
                block.header.block_number,
                block.header.native_chain_slot,
                hash,
                tx,
            )
            .expect("Expected database write to succed");
    }
    Ok(())
}

pub fn first_available_block(blockstore: Blockstore) -> Result<(), Box<dyn std::error::Error>> {
    match blockstore.get_first_available_evm_block() {
        Ok(block) => println!("{}", block),
        Err(e) => println!("No blocks available = {:?}", e),
    }
    Ok(())
}

pub fn last_available_block(blockstore: Blockstore) -> Result<(), Box<dyn std::error::Error>> {
    match blockstore.get_last_available_evm_block()? {
        Some(block) => println!("{}", block),
        None => println!("No blocks available"),
    }
    Ok(())
}

pub fn block(
    blockstore: Blockstore,
    block_num: evm_state::BlockNum,
) -> Result<(), Box<dyn std::error::Error>> {
    match blockstore.get_evm_block(block_num) {
        Ok((block, confirmed)) => {
            println!("{:?}, confirmed={}", block, confirmed);
            println!("block_hash={:?}", block.header.hash());
        }
        Err(e) => println!("No blocks available = {:?}", e),
    }
    Ok(())
}

pub fn blocks(
    blockstore: Blockstore,
    starting_slot: evm_state::BlockNum,
    limit: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    let slots: Vec<_> = blockstore
        .evm_blocks_iterator(starting_slot)?
        .take(limit)
        .map(|((b, slot), _)| (b, slot))
        .collect();
    println!("{:?}", slots);
    println!("{} blocks found", slots.len());

    Ok(())
}

pub trait EvmBlockstoreSubcommand {
    fn evm_blockstore_subcommand(self) -> Self;
}

impl EvmBlockstoreSubcommand for App<'_, '_> {
    fn evm_blockstore_subcommand(self) -> Self {
        self.subcommand(
            SubCommand::with_name("evm_blockstore")
                .about("Evm blockstore manipulation utility")
                .setting(AppSettings::ArgRequiredElseHelp)
                .subcommand(
                    SubCommand::with_name("first-available-block")
                        .about("Get the first available block in the storage"),
                )
                .subcommand(
                    SubCommand::with_name("blocks")
                        .about("Get a list of evm blocks in ledger")
                        .arg(
                            Arg::with_name("starting_block")
                                .long("starting-block")
                                .validator(is_slot)
                                .value_name("BLOCK")
                                .takes_value(true)
                                .index(1)
                                .required(true)
                                .default_value("1")
                                .help("Start listing at this block"),
                        )
                        .arg(
                            Arg::with_name("limit")
                                .long("limit")
                                .validator(is_slot)
                                .value_name("LIMIT")
                                .takes_value(true)
                                .index(2)
                                .required(true)
                                .default_value("1000")
                                .help("Maximum number of blocks to return"),
                        ),
                )
                .subcommand(
                    SubCommand::with_name("block")
                        .about("Get a evm block info")
                        .arg(
                            Arg::with_name("block")
                                .long("block")
                                .validator(is_slot)
                                .value_name("BLOCK")
                                .takes_value(true)
                                .index(1)
                                .required(true),
                        ),
                )
                .subcommand(
                    SubCommand::with_name("modify-block")
                        .about("Modify a evm block according to jsonspec")
                        .arg(
                            Arg::with_name("block_number")
                                .long("block-number")
                                .validator(is_slot)
                                .value_name("BLOCK")
                                .takes_value(true)
                                .index(1)
                                .required(true),
                        )
                        .arg(
                            Arg::with_name("native_slot")
                                .long("native-slot")
                                .validator(is_slot)
                                .value_name("NATIVE_SLOT")
                                .takes_value(true)
                                .index(2)
                                .required(true),
                        )
                        .arg(
                            Arg::with_name("native_hash")
                                .long("native-hash")
                                .value_name("NATIVE_HASH")
                                .takes_value(true)
                                .index(3)
                                .required(true),
                        )
                        .arg(
                            Arg::with_name("timestamp")
                                .long("timestamp")
                                .value_name("TIMESTAMP")
                                .takes_value(true),
                        )
                        .arg(
                            Arg::with_name("skip_consistency_check")
                                .long("skip-consistency-check")
                                .takes_value(false)
                                .help("Do not Check next blocks parent_hash"),
                        ),
                ),
        )
    }
}

pub fn evm_blockstore_process_command(ledger_path: &Path, matches: &ArgMatches<'_>) {
    let blockstore = crate::open_blockstore(ledger_path, AccessType::TryPrimaryThenSecondary, None);

    let future = match matches.subcommand() {
        ("modify-block", Some(arg_matches)) => {
            let block_number = value_t_or_exit!(arg_matches, "block_number", Slot);
            let native_slot = value_t_or_exit!(arg_matches, "native_slot", Slot);
            let native_hash = value_t_or_exit!(arg_matches, "native_hash", evm_state::H256);
            let timestamp = value_t!(arg_matches, "timestamp", u64).ok();
            let skip_consistency_check = arg_matches.is_present("skip_consistency_check");

            modify_block(
                blockstore,
                block_number,
                native_slot,
                native_hash,
                timestamp,
                skip_consistency_check,
            )
        }
        ("first-available-block", Some(_arg_matches)) => first_available_block(blockstore),
        ("last-available-block", Some(_arg_matches)) => last_available_block(blockstore),
        ("block", Some(arg_matches)) => {
            let block_num = value_t_or_exit!(arg_matches, "block", Slot);
            block(blockstore, block_num)
        }
        ("blocks", Some(arg_matches)) => {
            let starting_block = value_t_or_exit!(arg_matches, "starting_block", Slot);
            let limit = value_t_or_exit!(arg_matches, "limit", usize);

            blocks(blockstore, starting_block, limit)
        }
        _ => unreachable!(),
    };

    future.unwrap_or_else(|err| {
        eprintln!("{:?}", err);
        exit(1);
    });
}
