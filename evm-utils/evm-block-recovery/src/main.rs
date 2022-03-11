use evm_state::BlockNum;
use solana_sdk::clock::Slot;
use solana_storage_bigtable::LedgerStorage;
use solana_transaction_status::TransactionWithStatusMeta;

use solana_sdk::evm_loader::ID as STATIC_PROGRAM_ID;

#[tokio::main]
async fn main() {
    dotenv::dotenv().expect("`.env` file expected");
    env_logger::init();

    let bigtable = LedgerStorage::new(false, None)
        .await
        .expect("Failed to connect to storage");

    let mut missing_blocks = Vec::new();

    missing_blocks.extend(
        find_uncommitted_blocks(&bigtable, 15662810, 30)
            .await
            .unwrap(),
    );
    missing_blocks.extend(
        find_uncommitted_blocks(&bigtable, 15880820, 20)
            .await
            .unwrap(),
    );
    missing_blocks.extend(
        find_uncommitted_blocks(&bigtable, 17206780, 10)
            .await
            .unwrap(),
    );

    println!("Missing blocks: {missing_blocks:?}");
}

async fn find_uncommitted_blocks(
    ledger: &LedgerStorage,
    start_block: BlockNum,
    limit: usize,
) -> Result<Vec<BlockNum>, ()> {
    let mut result = Vec::new();

    let blocks = ledger
        .get_evm_confirmed_blocks(start_block, limit)
        .await
        .map_err(|_| ())?;

    for i in 0..blocks.len() - 1 {
        let previous = blocks[i];
        let current = blocks[i + 1];

        if current - previous != 1 {
            log::info!("Found missing block(s): {previous}, ...missing block(s)..., {current}");
            result.extend(previous + 1..current);
        }
    }

    Ok(result)
}

async fn _read_block(ledger: &LedgerStorage, slot: Slot) {
    let block = ledger.get_confirmed_block(slot).await.unwrap();

    for TransactionWithStatusMeta { transaction, .. } in block.transactions {
        for instruction in transaction.message.instructions {
            // let CompiledInstruction { program_id_index, accounts, data } = instruction;
            let _id = instruction.program_id(&[STATIC_PROGRAM_ID]);
            // ...
        }
    }
}
