mod error;
mod instruction;
mod processor;
mod state;

use processor::process_instruction;
use solana_program::entrypoint;

// Declare and export the program's entrypoint
entrypoint!(process_instruction);
