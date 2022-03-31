
use evm_state as evm;
use solana_evm_loader_program::instructions::EvmInstruction;
use solana_storage_bigtable::LedgerStorage;
use solana_transaction_status::ConfirmedBlock;

use crate::data::EvmContent;

#[derive(Debug)]
pub enum Consistency {
    Matches,
    Differs,
}

/// Checks the consistency of transactions from the Evm block and the native block
pub async fn integrity_check(ledger: &LedgerStorage, evm_block_id: evm::BlockNum) -> Consistency {
    // TODO: Cover with tests
    fn compare_blocks(evm_block: evm::Block, native_block: ConfirmedBlock) -> Consistency {
        let mut tx_from_evm = vec![];
        for (_hash, tx) in evm_block.transactions {
            match tx.transaction {
                evm::TransactionInReceipt::Signed(signed_tx) => {
                    tx_from_evm.push(signed_tx);
                }
                evm::TransactionInReceipt::Unsigned(unsigned) => {
                    log::info!(
                        "EVM block {} cointains unsigned transaction(s): {:?}",
                        evm_block.header.block_number,
                        unsigned
                    );
                    return Consistency::Differs;
                }
            }
        }

        let mut tx_from_native = vec![];
        for i in EvmContent::from_native_block(native_block).instructions {
            match i {
                EvmInstruction::EvmTransaction { evm_tx } => {
                    tx_from_native.push(evm_tx);
                }
                evm_instruction => {
                    log::info!(
                        "Native block {} contains not trivial EVM Instruction: {:?}",
                        evm_block.header.native_chain_slot,
                        evm_instruction
                    );
                    return Consistency::Differs;
                }
            }
        }

        match tx_from_evm == tx_from_native {
            true => Consistency::Matches,
            false => Consistency::Differs,
        }
    }

    let evm_block = ledger
        .get_evm_confirmed_full_block(evm_block_id)
        .await
        .unwrap();

    let native_block = ledger
        .get_confirmed_block(evm_block.header.native_chain_slot)
        .await
        .unwrap();

    compare_blocks(evm_block, native_block)
}