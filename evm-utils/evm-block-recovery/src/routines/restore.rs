use evm_state::{BlockHeader, BlockNum, TransactionInReceipt};
use solana_storage_bigtable::LedgerStorage;

use crate::data::EvmContent;

pub async fn command(ledger: &LedgerStorage, _block: BlockNum, dry_run: bool) {
    let evm_block_header = ledger
        .get_evm_confirmed_full_block(15662812)
        .await
        .unwrap()
        .header;

    println!(
        "BLOCK HEADER:\n{}\n",
        serde_json::to_string_pretty(&evm_block_header).unwrap()
    );

    let native_block = ledger
        .get_confirmed_block(evm_block_header.native_chain_slot)
        .await
        .unwrap();
    let evm_content = EvmContent::from_native_block(native_block);

    let e = evm_content.instructions.into_iter().nth(0).unwrap();

    let header = match e {
        solana_evm_loader_program::instructions::EvmInstruction::EvmTransaction { evm_tx } => {
            let tx =
                evm_rpc::RPCTransaction::from_transaction(TransactionInReceipt::Signed(evm_tx))
                    .unwrap();
            println!(
                "RPCTransaction:\n{}\n",
                serde_json::to_string_pretty(&tx).unwrap()
            );
            todo!()
        }
        _ => panic!("Unexpected EVM Instruction"),
    };

    if dry_run {
        return;
    }
    write_header(&ledger, header).await;
}

async fn write_header(ledger: &LedgerStorage, header: BlockHeader) {
    // write header to bigtable
    todo!()
}
