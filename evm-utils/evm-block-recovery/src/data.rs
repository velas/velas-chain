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
    instructions: Vec<EvmInstruction>,
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
                    let evm_instruction: EvmInstruction = bincode::deserialize(&data).unwrap();
                    // match evm_instruction {
                    //     EvmInstruction::EvmTransaction { evm_tx } => todo!(),
                    //     EvmInstruction::SwapNativeToEther {
                    //         lamports,
                    //         evm_address,
                    //     } => todo!(),
                    //     EvmInstruction::FreeOwnership {} => todo!(),
                    //     EvmInstruction::EvmBigTransaction(_) => todo!(),
                    //     EvmInstruction::EvmAuthorizedTransaction { from, unsigned_tx } => todo!(),
                    // }
                    instructions.push(evm_instruction);
                }
            }
        }

        Self { instructions }
    }

    // pub fn instr_evm_transaction(&self) -> Vec<evm::Transaction> {
    //     self.instructions
    //         .iter()
    //         .filter_map(|i| match i {
    //             EvmInstruction::EvmTransaction { evm_tx } => Some(evm_tx),
    //             _ => None,
    //         })
    //         .collect()
    // }

    // pub fn instr_swap_native_to_ether(&self) -> Vec<(u64, H160)> {
    //     self.instructions
    //         .into_iter()
    //         .filter_map(|i| match i {
    //             EvmInstruction::SwapNativeToEther { lamports, evm_address } => Some((lamports, evm_address)),
    //             _ => None,
    //         })
    //         .collect()
    // }
}
