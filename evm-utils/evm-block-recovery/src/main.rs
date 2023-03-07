pub mod blocks_json;
pub mod cli;
pub mod error;
pub mod extensions;
pub mod ledger;
pub mod routines;

use clap::Parser;
use cli::{Cli, Command::*};
use error::AppError;
use routines::{find::WhatFound, *};
use serde_json::json;

lazy_static::lazy_static! {
    pub static ref IS_EMBED: bool = std::env::args().any(|arg| &arg == "--embed");
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    let dotenv = dotenvy::dotenv();

    match std::env::var("RUST_LOG") {
        Ok(value) => {
            env_logger::init();
            log::info!(r#"RUST_LOG is set to "{value}""#);
        }
        Err(_err) => {
            std::env::set_var("RUST_LOG", "evm_block_recovery");
            env_logger::init();
            log::warn!(r#"Environment variable "RUST_LOG" not found."#);
        }
    }

    match dotenv {
        Ok(path) => {
            log::info!(r#""{}" successfully loaded"#, path.display())
        }
        Err(e) => {
            log::warn!(r#"".env" file not found: {e:?}""#)
        }
    }

    let execution_result = match cli.subcommand {
        FindEvm(args) => report(find_evm(cli.creds, cli.instance, args).await),
        FindNative(args) => report(find_native(cli.creds, cli.instance, args).await),
        RestoreChain(args) => restore_chain(cli.creds, cli.instance, args).await,
        CheckNative(args) => check_native(cli.creds, cli.instance, args).await,
        CheckEvm(args) => check_evm(cli.creds, cli.instance, args).await,
        CompareNative(args) => compare_native(args).await,
        Upload(args) => upload(cli.creds, cli.instance, args).await,
        RepeatEvm(args) => repeat_evm(args).await,
        RepeatNative(args) => repeat_native(args).await,
        Completion(args) => completion(args),
    };

    let exit_code = match execution_result {
        Ok(()) => 0,
        Err(error) => error.exit_code(),
    };

    std::process::exit(exit_code);
}

fn report(found: Result<WhatFound, AppError>) -> Result<(), AppError> {
    fn print_task_ok() {
        println!("{}", json!({"status": "ok"}))
    }

    fn print_task_alert() {
        println!("{}", json!({"status": "alert"}))
    }

    fn print_task_error(error_kind: i32) {
        println!("{}", json!({"status": "error", "kind": error_kind}))
    }

    if *crate::IS_EMBED {
        match &found {
            Ok(WhatFound::AllGood) => print_task_ok(),
            Ok(WhatFound::ThereAreMisses(_)) => print_task_alert(),
            Err(error) => print_task_error(error.exit_code()),
        }
    }

    found.map(|_| ())
}
