use evm_rpc::RPCTransaction;
use evm_state::TransactionInReceipt;
use solana_evm_loader_program::instructions::EvmInstruction;
use solana_sdk::{evm_loader::ID as STATIC_PROGRAM_ID, instruction::CompiledInstruction};
use solana_transaction_status::{ConfirmedBlock, TransactionWithStatusMeta};

/// Converts transactions from the native block into RPC transactions
/// Returns `None` if the native block contains instructions other than trivial EVM transactions
pub trait NativeBlockExt {
    fn parse_trivial_transactions(&self) -> Option<Vec<(RPCTransaction, Vec<String>)>>;
}

impl NativeBlockExt for ConfirmedBlock {
    fn parse_trivial_transactions(&self) -> Option<Vec<(RPCTransaction, Vec<String>)>> {
        let mut rpc_txs = vec![];

        for TransactionWithStatusMeta { transaction, .. } in self.transactions {
            for CompiledInstruction {
                data,
                program_id_index,
                ..
            } in transaction.message.instructions
            {
                if transaction.message.account_keys[program_id_index as usize] == STATIC_PROGRAM_ID
                {
                    let evm_instr: EvmInstruction = bincode::deserialize(&data).unwrap();
                    match evm_instr {
                        EvmInstruction::EvmTransaction { evm_tx } => {
                            let rpc_transaction = RPCTransaction::from_transaction(TransactionInReceipt::Signed(evm_tx)).unwrap();
                            rpc_txs.push((rpc_transaction, vec![]));
                        },
                        _ => return None
                    }
                    
                }
            }
        }

        Some(rpc_txs)
    }
}