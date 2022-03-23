use evm_state as evm;
use solana_evm_loader_program::instructions::EvmInstruction;
use solana_storage_bigtable::LedgerStorage;

use crate::data::EvmContent;

#[derive(Debug)]
pub enum Consistency {
    Matches,
    Differs,
}

/// Checks the consistency of transactions from the Evm block and the native block
pub async fn integrity_check(ledger: &LedgerStorage, evm_block_id: evm::BlockNum) -> Consistency {
    let evm_block = ledger
        .get_evm_confirmed_full_block(evm_block_id)
        .await
        .unwrap();

    let mut tx_from_evm = vec![];
    for (_hash, tx) in evm_block.transactions {
        match tx.transaction {
            evm::TransactionInReceipt::Signed(signed_tx) => {
                tx_from_evm.push(signed_tx);
            },
            evm::TransactionInReceipt::Unsigned(_) => return Consistency::Differs,
        }
    }

    let native_slot = evm_block.header.native_chain_slot;

    let native_block = ledger.get_confirmed_block(native_slot).await.unwrap();

    let mut tx_from_native = vec![];
    for i in EvmContent::from_native_block(native_block).instructions {
        match i {
            EvmInstruction::EvmTransaction { evm_tx } => {
                tx_from_native.push(evm_tx);
            },
            _ => return Consistency::Differs
        }
    }

    match tx_from_evm == tx_from_native {
        true => Consistency::Matches,
        false => Consistency::Differs
    }
}
