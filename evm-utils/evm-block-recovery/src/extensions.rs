use solana_evm_loader_program::instructions::EvmInstruction;
use solana_sdk::{evm_loader::ID as STATIC_PROGRAM_ID, instruction::CompiledInstruction};
use solana_transaction_status::{
    ConfirmedBlockWithOptionalMetadata, TransactionWithOptionalMetadata,
};

#[derive(Debug)]
pub struct ParsedInstructions {
    pub instructions: Vec<EvmInstruction>,
    pub only_trivial_instructions: bool,
}

impl ParsedInstructions {
    pub fn instr_evm_swap_to_native(&self) -> usize {
        self.instructions
            .iter()
            .filter(|i| matches!(i, EvmInstruction::SwapNativeToEther { .. }))
            .count()
    }

    pub fn instr_evm_free_ownership(&self) -> usize {
        self.instructions
            .iter()
            .filter(|i| matches!(i, EvmInstruction::FreeOwnership {}))
            .count()
    }

    pub fn instr_evm_big_transaction(&self) -> usize {
        self.instructions
            .iter()
            .filter(|i| matches!(i, EvmInstruction::EvmBigTransaction(_)))
            .count()
    }

    pub fn instr_execute_transaction(&self) -> usize {
        self.instructions
            .iter()
            .filter(|i| matches!(i, EvmInstruction::ExecuteTransaction { .. }))
            .count()
    }
}

pub trait NativeBlockExt {
    fn parse_instructions(&self) -> ParsedInstructions;
}

impl NativeBlockExt for ConfirmedBlockWithOptionalMetadata {
    fn parse_instructions(&self) -> ParsedInstructions {
        let mut only_trivial_instructions = true;
        let mut instructions = vec![];

        for TransactionWithOptionalMetadata { transaction, .. } in &self.transactions {
            for CompiledInstruction {
                data,
                program_id_index,
                ..
            } in &transaction.message.instructions
            {
                if transaction.message.account_keys[*program_id_index as usize] == STATIC_PROGRAM_ID
                {
                    let instruction: EvmInstruction = bincode::deserialize(&data).unwrap();
                    if !matches!(instruction, EvmInstruction::EvmTransaction { .. }) {
                        only_trivial_instructions = false;
                    }
                    instructions.push(instruction);
                }
            }
        }

        ParsedInstructions {
            instructions,
            only_trivial_instructions,
        }
    }
}
