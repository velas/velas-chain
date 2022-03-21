use evm_state as evm;
use solana_evm_loader_program::instructions::EvmInstruction;
use solana_sdk::{evm_loader::ID as STATIC_PROGRAM_ID, instruction::CompiledInstruction};
use solana_transaction_status::{ConfirmedBlock, TransactionWithStatusMeta};

#[derive(Debug, PartialEq, Eq)]
pub struct EvmBlockRange {
    pub first: evm::BlockNum,
    pub last: evm::BlockNum,
}

impl EvmBlockRange {
    pub fn new(first: evm::BlockNum, last: evm::BlockNum) -> Self {
        Self { first, last }
    }
}

#[derive(Debug)]
pub struct EvmContent {
    pub instructions: Vec<EvmInstruction>,
}

impl EvmContent {
    pub fn from_native_block(native: ConfirmedBlock) -> Self {
        let mut instructions = vec![];

        for TransactionWithStatusMeta { transaction, .. } in native.transactions {
            for CompiledInstruction {
                data,
                program_id_index,
                ..
            } in transaction.message.instructions
            {
                // FreeOwnership will not be included with following filter
                if transaction.message.account_keys[program_id_index as usize] == STATIC_PROGRAM_ID
                {
                    let evm_instruction: EvmInstruction = bincode::deserialize(&data).unwrap();
                    instructions.push(evm_instruction);
                }
            }
        }

        Self { instructions }
    }

    pub fn instr_evm_transaction(&self) -> usize {
        self.instructions
            .iter()
            .filter(|i| match i {
                EvmInstruction::EvmTransaction { .. } => true,
                _ => false,
            })
            .count()
    }

    pub fn instr_evm_swap_to_native(&self) -> usize {
        self.instructions
            .iter()
            .filter(|i| match i {
                EvmInstruction::SwapNativeToEther { .. } => true,
                _ => false,
            })
            .count()
    }

    pub fn instr_evm_free_ownership(&self) -> usize {
        self.instructions
            .iter()
            .filter(|i| match i {
                EvmInstruction::FreeOwnership {} => true,
                _ => false,
            })
            .count()
    }

    pub fn instr_evm_big_transaction(&self) -> usize {
        self.instructions
            .iter()
            .filter(|i| match i {
                EvmInstruction::EvmBigTransaction(_) => true,
                _ => false,
            })
            .count()
    }

    pub fn instr_evm_authorized_transaction(&self) -> usize {
        self.instructions
            .iter()
            .filter(|i| match i {
                EvmInstruction::EvmAuthorizedTransaction { .. } => true,
                _ => false,
            })
            .count()
    }
}
