use evm_state::{TransactionInReceipt, BlockNum, BlockHeader};
use solana_storage_bigtable::LedgerStorage;

use crate::data::EvmContent;

pub async fn restore_block_header(ledger: LedgerStorage, _block: BlockNum) -> BlockHeader {
    let evm_block_header = ledger
        .get_evm_confirmed_full_block(15662812)
        .await
        .unwrap()
        .header;

    println!("BLOCK HEADER:\n{}\n", serde_json::to_string_pretty(&evm_block_header).unwrap());

    let native_block = ledger.get_confirmed_block(evm_block_header.native_chain_slot).await.unwrap();
    let evm_content = EvmContent::from_native_block(native_block);
    
    let e = evm_content.instructions.into_iter().nth(0).unwrap();
    
    match e {
        solana_evm_loader_program::instructions::EvmInstruction::EvmTransaction { evm_tx } => {
            let tx = evm_rpc::RPCTransaction::from_transaction(TransactionInReceipt::Signed(evm_tx)).unwrap();
            println!("RPCTransaction:\n{}\n", serde_json::to_string_pretty(&tx).unwrap());
        },
        _ => panic!("Unexpected EVM Instruction"),
    }

    todo!()
}