use std::{thread, time::Duration};

use byteorder::{LittleEndian, ReadBytesExt};
use log::*;
use solana_sdk::{
    instruction::InstructionError, keyed_account::KeyedAccount,
    pubkey::Pubkey,
};
use solana_program_runtime::invoke_context::InvokeContext;

solana_sdk::declare_builtin!(
    "S1eep11111111111111111111111111111111111111",
    solana_sleep_program,
    process_instruction
);
const MAX_SLEEP_MS: u32 = 1000;

pub fn process_instruction(
    program_id: &Pubkey,
    keyed_accounts: &[KeyedAccount],
    data: &[u8],
    _invoke_context: &mut  InvokeContext,
) -> Result<(), InstructionError> {
    solana_logger::setup();
    trace!("sleep: program_id: {:?}", program_id);
    trace!("sleep: keyed_accounts: {:#?}", keyed_accounts);

    if data.len() != 4 {
        error!("data len should be 4 bytes");
        return Err(InstructionError::InvalidInstructionData);
    }
    let mut data = data;
    let ms = data.read_u32::<LittleEndian>().unwrap();

    let sleep_ms = ms % MAX_SLEEP_MS;
    trace!("Sleep: sleeping ms {}", sleep_ms);
    thread::sleep(Duration::from_millis(sleep_ms.into()));
    Ok(())
}
