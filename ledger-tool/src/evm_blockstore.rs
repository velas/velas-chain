/// The `bigtable` subcommand
use clap::{value_t_or_exit, App, AppSettings, Arg, ArgMatches, SubCommand};
use solana_clap_utils::input_validators::is_slot;

use solana_ledger::{blockstore::Blockstore, blockstore_db::AccessType};
use solana_sdk::clock::Slot;
use std::{path::Path, process::exit, result::Result};

// pub async fn upload(
//     blockstore: Blockstore,
//     starting_block: Slot,
//     ending_block: Option<Slot>,
//     push_not_confirmed: bool,
//     force_reupload: bool,
// ) -> Result<Slot, Box<dyn std::error::Error>> {
//     let bigtable = solana_storage_bigtable::LedgerStorage::new(false, None)
//         .await
//         .map_err(|err| format!("Failed to connect to storage: {:?}", err))?;

//     solana_ledger::bigtable_upload::upload_evm_confirmed_blocks(
//         Arc::new(blockstore),
//         bigtable,
//         starting_block,
//         ending_block,
//         push_not_confirmed,
//         force_reupload,
//         Arc::new(AtomicBool::new(false)),
//     )
//     .await
// }

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
                ),
        )
    }
}

pub fn evm_blockstore_process_command(ledger_path: &Path, matches: &ArgMatches<'_>) {
    let blockstore =
        crate::open_blockstore(&ledger_path, AccessType::TryPrimaryThenSecondary, None);

    let future = match matches.subcommand() {
        // ("upload", Some(arg_matches)) => {
        //     let starting_block = value_t!(arg_matches, "starting_block", Slot).unwrap_or(1);
        //     let ending_block = value_t!(arg_matches, "ending_block", Slot).ok();
        //     let push_not_confirmed = arg_matches.is_present("push_not_confirmed");
        //     let force_reupload = arg_matches.is_present("force_reupload");
        //

        //     runtime
        //         .block_on(evm::upload(
        //             blockstore,
        //             starting_block,
        //             ending_block,
        //             push_not_confirmed,
        //             force_reupload,
        //         ))
        //         .map(drop)
        // }
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
