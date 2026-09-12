pub mod blocks_json;
pub mod cli;
pub mod error;
pub mod extensions;
pub mod ledger;
pub mod routines;

use {
    clap::Parser,
    cli::{Cli, Command::*},
    env_logger::{Builder, Target},
    error::AppError,
    routines::{find::WhatFound, *},
    serde_json::json,
};

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    let dotenv = dotenvy::dotenv();

    match std::env::var("RUST_LOG") {
        Ok(value) => {
            log::info!(r#"RUST_LOG is set to "{value}""#);
        }
        Err(_err) => {
            std::env::set_var("RUST_LOG", "evm_block_recovery");
            log::warn!(r#"Environment variable "RUST_LOG" not found."#);
        }
    }

    let mut builder = Builder::from_default_env();
    builder.target(Target::Stderr);
    builder.init();

    match dotenv {
        Ok(path) => {
            log::info!(r#""{}" successfully loaded"#, path.display())
        }
        Err(e) => {
            log::warn!(r#"".env" file not found: {e:?}""#)
        }
    }

    let execution_result = match cli.subcommand {
        FindEvm(args) => report(cli.embed, find_evm(cli.creds, cli.instance, args).await),
        FindNative(args) => report(cli.embed, find_native(cli.creds, cli.instance, args).await),
        RestoreChain(args) => restore_chain(cli.creds, cli.instance, args).await,
        CheckNative(args) => check_native(cli.creds, cli.instance, args).await,
        CheckEvm(args) => check_evm(cli.creds, cli.instance, args).await,
        CompareNative(args) => compare_native(args).await,
        Upload(args) => upload(cli.creds, cli.instance, args).await,
        RepeatEvm(args) => repeat_evm(args).await,
        RepeatNative(args) => repeat_native(args).await,
        ScanEvmStateRoots(ref args) => scan_evm_state_roots::command(args).await,
        ScratchPad => scratchpad::command().await,
        Completion(args) => completion(args),
    };

    let exit_code = match execution_result {
        Ok(()) => 0,
        Err(error) => {
            eprintln!("error {:?}", error);
            error.exit_code()
        }
    };

    std::process::exit(exit_code);
}

fn report(is_embed: bool, found: Result<WhatFound, AppError>) -> Result<(), AppError> {
    fn print_task_ok() {
        println!("{}", json!({"status": "ok"}))
    }

    fn print_task_alert() {
        println!("{}", json!({"status": "alert"}))
    }

    fn print_task_error(error: &AppError) {
        println!(
            "{}",
            json!({
                "status": "error",
                "code": error.exit_code(),
                "details": error.to_string()
            })
        )
    }

    if is_embed {
        match &found {
            Ok(WhatFound::AllGood) => print_task_ok(),
            Ok(WhatFound::ThereAreMisses(_)) => print_task_alert(),
            Err(error) => print_task_error(error),
        }
    }

    found.map(|_| ())
}
