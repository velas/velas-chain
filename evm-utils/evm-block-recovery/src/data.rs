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
                if transaction.message.account_keys[program_id_index as usize] == STATIC_PROGRAM_ID
                {
                    instructions.push(bincode::deserialize(&data).unwrap());
                }
            }
        }

        Self { instructions }
    }

    pub fn instr_evm_transaction(&self) -> usize {
        self.instructions
            .iter()
            .filter(|i| matches!(i, EvmInstruction::EvmTransaction { .. }))
            .count()
    }

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

    pub fn instr_evm_authorized_transaction(&self) -> usize {
        self.instructions
            .iter()
            .filter(|i| matches!(i, EvmInstruction::EvmAuthorizedTransaction { .. }))
            .count()
    }
}
