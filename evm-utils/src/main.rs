
use std::collections::BTreeMap;
use primitive_types::{H160, H256, U256};
use evm::backend::{MemoryVicinity, MemoryAccount, MemoryBackend, Apply};
use evm::executor::{StackExecutor};
use evm::Handler;
use evm::{Transfer, Context, Capture, CreateScheme};
use std::cell::{RefCell};
use std::rc::Rc;
use log::*;
use keccak_hash::keccak_256;

// With the "paw" feature enabled in structopt
#[derive(Debug, structopt::StructOpt)]
struct Args {
    /// Bytecode file.
    #[structopt(short = "f", long = "file")]
    file: Option<String>,
}

#[paw::main]
fn main(args: Args) -> Result<(), std::io::Error> {
    env_logger::init();
    // solana_evm_loader_program::processor::EVMProcessor::write_account(address, account);
    info!("{:?}", args);
    Ok(())
}
