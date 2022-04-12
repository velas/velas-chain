use anyhow::*;
use evm_state::BlockNum;
use solana_storage_bigtable::LedgerStorage;

// pub async fn check_evm(ledger: &LedgerStorage, block: BlockNum) -> Result<()> {
//     let evm_block = ledger.get_evm_confirmed_full_block(block)
//         .await
//         .unwrap();

//     let native_block = ledger.get_confirmed_block(evm_block.header.native_chain_slot)
//         .await
//         .unwrap();

//     log::info!("EVM Block Timestamp: {}", evm_block.header.timestamp);
//     log::info!("Native Block Timestamp: {}", native_block.block_time.unwrap());
//     Ok(())
// }

pub async fn check_evm(ledger: &LedgerStorage, block: BlockNum) -> Result<()> {
    let mut statistics = std::collections::HashMap::new();

    for b in 15_600_001..15_602_200 {
        println!("Block {b}...");
        let evm_block = ledger.get_evm_confirmed_block_header(b)
            .await
            .unwrap();
    
        let native_block = ledger.get_confirmed_block(evm_block.native_chain_slot)
            .await
            .unwrap();

        let diff = native_block.block_time.unwrap() as i64 - evm_block.timestamp as i64;

        match statistics.get_mut(&diff) {
            Some(mut amount) => *amount += 1,
            None => { statistics.insert(diff, 1); },
        }
    }

    log::info!("Statistics: {:?}", &statistics);
    Ok(())
}

// $ evm-block-recovery check-evm -b 15662918`
// [2022-04-11T21:15:14Z INFO  evm_block_recovery::routines::check_evm] EVM Block Timestamp: 1642792797
// [2022-04-11T21:15:14Z INFO  evm_block_recovery::routines::check_evm] Native Block Timestamp: 1642792798