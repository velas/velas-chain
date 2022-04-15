use std::{str::FromStr, time::SystemTime};

use anyhow::*;
use evm_rpc::RPCTransaction;
use evm_state::{Block, BlockHeader, TransactionInReceipt, H256};
use serde_json::json;
use solana_client::{rpc_client::RpcClient, rpc_request::RpcRequest};
use solana_evm_loader_program::instructions::EvmInstruction;
use solana_sdk::pubkey::Pubkey;
use solana_storage_bigtable::LedgerStorage;

use crate::extensions::NativeBlockExt;

use super::find::BlockRange;

pub async fn restore_chain(
    ledger: &LedgerStorage,
    evm_missing: BlockRange,
    rpc_address: String,
    modify_ledger: bool,
) -> Result<()> {
    let rpc_client = RpcClient::new(rpc_address);

    let mut header_template = ledger
        .get_evm_confirmed_block_header(evm_missing.first - 1)
        .await
        .context(format!(
            "Unable to get EVM block header {}",
            evm_missing.first - 1
        ))?;

    let head = ledger
        .get_evm_confirmed_block_header(evm_missing.last + 1)
        .await
        .context(format!(
            "Unable to get EVM block header {}",
            evm_missing.last + 1
        ))?;

    let mut native_blocks = vec![];

    for slot in header_template.native_chain_slot + 1..=head.native_chain_slot {
        let native_block = ledger
            .get_confirmed_block(slot)
            .await
            .context(format!("Unable to get Native Block {}", slot))?;
        native_blocks.push(native_block);
    }

    let timestamps = crate::timestamp::load_timestamps().unwrap();
    let mut restored_blocks = vec![];

    for nb in native_blocks.into_iter() {
        let parsed_instructions = nb.parse_instructions();
        if !parsed_instructions.only_trivial_instructions {
            // FIXME: get correct native block ID
            return Err(anyhow!(
                "Native block {} contains non-trivial instructions",
                nb.block_height.unwrap()
            ));
        }

        header_template.parent_hash = header_template.hash();
        header_template.native_chain_slot += 1;
        header_template.native_chain_hash =
            H256(Pubkey::from_str(&nb.blockhash).unwrap().to_bytes());
        header_template.block_number += 1;
        // FIXME: 5hrs EST timezome correction
        header_template.timestamp = *timestamps.get(&header_template.block_number).unwrap() - 18000;

        let txs: Vec<(RPCTransaction, Vec<String>)> = parsed_instructions
            .instructions
            .iter()
            .map(|v| match v {
                EvmInstruction::EvmTransaction { evm_tx } => (
                    RPCTransaction::from_transaction(TransactionInReceipt::Signed(evm_tx.clone()))
                        .unwrap(),
                    Vec::<String>::new(),
                ),
                _ => unreachable!(),
            })
            .collect();

        let last_hashes: Vec<H256> = vec![H256::zero(); 256];
        let state_root = header_template.state_root;
        let restored_block =
            request_restored_block(&rpc_client, txs, last_hashes, header_template, state_root)
                .await
                .unwrap();

        header_template = restored_block.header.clone();
        restored_blocks.push(restored_block);

        std::thread::sleep(std::time::Duration::from_secs(2));
    }

    log::debug!("Amount of restored blocks: {}", restored_blocks.len());
    log::debug!(
        "Last Restored Block Header: {:#?}",
        &restored_blocks.iter().last().unwrap().header
    );
    log::debug!(
        "Last Restored Block Header Hash: {}",
        &restored_blocks.iter().last().unwrap().header.hash()
    );
    log::debug!("EVM Head: {:#?}", &head);
    log::debug!("EVM Head Hash: {}", head.hash());

    if head.hash() == restored_blocks.iter().last().unwrap().header.hash() {
        log::info!("✅✅✅ Hashes match! ✅✅✅");

        restored_blocks.pop();

        // FIXME: set all paths etc at CLI
        let unixtime = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let path = format!(
            "/home/maksimv/Desktop/restored-blocks-{}-{}-{}.json",
            evm_missing.first, evm_missing.last, unixtime
        );
        std::fs::write(path, serde_json::to_string(&restored_blocks).unwrap()).unwrap();

        if modify_ledger {
            for block in restored_blocks {
                write_block(&ledger, block).await?;
            }
        }
    } else {
        log::warn!("❌❌❌ Hashes do not match! ❌❌❌")
    }

    Ok(())
}

async fn request_restored_block(
    rpc_client: &RpcClient,
    txs: Vec<(RPCTransaction, Vec<String>)>,
    last_hashes: Vec<H256>,
    block_header: BlockHeader,
    state_root: H256,
) -> Result<Block> {
    let params = json!([txs, last_hashes, block_header, state_root]);

    let result: Block = rpc_client
        .send(RpcRequest::DebugRecoverBlockHeader, params)
        .unwrap();

    Ok(result)
}

async fn write_block(ledger: &LedgerStorage, full_block: Block) -> Result<()> {
    log::info!(
        "Writing block {} with hash {} to t he Ledger...",
        full_block.header.block_number,
        full_block.header.hash()
    );

    let block_num = full_block.header.block_number;

    ledger
        .upload_evm_block(block_num, full_block)
        .await
        .context(format!("Unable to write block {block_num} to bigtable"))?;

    Ok(())
}
