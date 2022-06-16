pub mod cli;
pub mod extensions;
pub mod ledger;
pub mod routines;
pub mod timestamp;

use clap::Parser;
use cli::{Cli, Commands};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let dotenv = dotenv::dotenv();

    match std::env::var("RUST_LOG") {
        Ok(value) => {
            env_logger::init();
            log::info!(r#"RUST_LOG is set to "{value}""#);
        }
        Err(_err) => {
            std::env::set_var("RUST_LOG", "info");
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

    let cli = Cli::parse();
    match cli.command {
        Commands::FindEvm { start, limit } => {
            routines::find_evm(
                ledger::with_params(cli.creds, cli.instance).await?,
                start,
                limit,
            )
            .await
        }
        Commands::FindNative { start, limit } => {
            routines::find_native(
                ledger::with_params(cli.creds, cli.instance).await?,
                start,
                limit,
            )
            .await
        }
        Commands::RestoreChain {
            first,
            last,
            archive_url: rpc_address,
            modify_ledger,
            force_resume,
            output_dir,
        } => {
            routines::restore_chain(
                ledger::with_params(cli.creds, cli.instance).await?,
                routines::find::BlockRange::new(first, last),
                rpc_address,
                modify_ledger,
                force_resume,
                output_dir,
            )
            .await
        }
        Commands::CheckNative { block_number } => {
            routines::check_native(
                ledger::with_params(cli.creds, cli.instance).await?,
                block_number,
            )
            .await
        }
        Commands::CheckEvm { block_number } => {
            routines::check_evm(
                ledger::with_params(cli.creds, cli.instance).await?,
                block_number,
            )
            .await
        }
        Commands::Upload { collection } => {
            routines::upload(
                ledger::with_params(cli.creds, cli.instance).await?,
                collection,
            )
            .await
        }
        Commands::RepeatEvm {
            block_number,
            limit,
            src_creds,
            src_instance,
            dst_creds,
            dst_instance,
        } => {
            routines::repeat_evm(
                block_number,
                limit,
                ledger::with_params(Some(src_creds), src_instance).await?,
                ledger::with_params(Some(dst_creds), dst_instance).await?,
            )
            .await
        }
        Commands::RepeatNative {
            block_number,
            limit,
            src_creds,
            src_instance,
            dst_creds,
            dst_instance,
        } => {
            routines::repeat_native(
                block_number,
                limit,
                ledger::with_params(Some(src_creds), src_instance).await?,
                ledger::with_params(Some(dst_creds), dst_instance).await?,
            )
            .await
        }
    }
}
