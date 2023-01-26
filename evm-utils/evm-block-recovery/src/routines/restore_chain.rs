use std::{path::PathBuf, str::FromStr, time::SystemTime};

use anyhow::*;
use evm_rpc::{Hex, RPCTransaction};
use evm_state::{Block, BlockHeader, TransactionInReceipt, H256};
use serde_json::json;
use solana_client::{rpc_client::RpcClient, rpc_request::RpcRequest};
use solana_evm_loader_program::instructions::v0;
use solana_sdk::pubkey::Pubkey;
use solana_storage_bigtable::LedgerStorage;

use crate::extensions::NativeBlockExt;

use super::write_blocks_collection;

pub async fn restore_chain(
    ledger: LedgerStorage,
    first_block: u64,
    last_block: u64,
    archive_url: String,
    modify_ledger: bool,
    force_resume: bool,
    timestamps: String,
    existent_check: bool,
    output_dir: Option<String>,
) -> Result<()> {
    let rpc_client = RpcClient::new(archive_url);

    let tail = ledger
        .get_evm_confirmed_block_header(last_block + 1)
        .await
        .context(format!("Unable to get EVM block header {}", last_block + 1))?;

    let mut header_template = ledger
        .get_evm_confirmed_block_header(first_block - 1)
        .await
        .context(format!(
            "Unable to get EVM block header {}",
            first_block - 1
        ))?;

    let start_slot = header_template.native_chain_slot;
    let end_slot = tail.native_chain_slot;
    let limit = (end_slot - start_slot + 1) as usize;
    let mut slot_ids = ledger
        .get_confirmed_blocks(start_slot, limit)
        .await
        .context(format!(
            "Unable to get native blocks ids, start_slot={}, limit={}",
            start_slot, limit
        ))?;
    slot_ids.retain(|slot| *slot > start_slot && *slot < end_slot);

    let mut native_blocks = vec![];

    for slot in slot_ids.iter() {
        let native_block = ledger
            .get_confirmed_block(*slot)
            .await
            .context(format!("Unable to get Native Block {}", slot))?;
        native_blocks.push(native_block);
    }

    let mut native_dict = slot_ids
        .into_iter()
        .zip(native_blocks.into_iter())
        .collect::<std::collections::HashMap<_, _>>();
    native_dict.retain(|_id, nb| nb.parse_instructions().instr_evm_transaction() > 0);

    let evm_blocks_to_recover_amount = (last_block - first_block + 1) as usize;
    let native_blocks_amount = native_dict.len();

    if native_blocks_amount != evm_blocks_to_recover_amount {
        bail!(format!(
            "The number of Native and EVM does not match. Native: {}, evm: {}",
            native_blocks_amount, evm_blocks_to_recover_amount
        ))
    }

    let timestamps = crate::timestamp::load_timestamps(timestamps).unwrap();
    let mut restored_blocks = vec![];

    for (id, nb) in native_dict.into_iter() {
        let parsed_instructions = nb.parse_instructions();
        if !parsed_instructions.only_trivial_instructions {
            return Err(anyhow!(
                "Native block {} contains non-trivial instructions",
                nb.block_height.unwrap()
            ));
        }
        header_template.parent_hash = header_template.hash();
        header_template.native_chain_slot = id;
        header_template.native_chain_hash =
            H256(Pubkey::from_str(&nb.blockhash).unwrap().to_bytes());
        header_template.block_number += 1;

        if existent_check {
            let existent_block = ledger
                .get_evm_confirmed_block_header(header_template.block_number)
                .await?;
            header_template.timestamp = existent_block.timestamp
        } else {
        header_template.timestamp = *timestamps.get(&header_template.block_number).unwrap();
        }

        let txs: Vec<(RPCTransaction, Vec<String>)> = parsed_instructions
            .instructions
            .iter()
            .map(|v| match v {
                v0::EvmInstruction::EvmTransaction { evm_tx } => (
                    RPCTransaction::from_transaction(TransactionInReceipt::Signed(evm_tx.clone()))
                        .unwrap(),
                    Vec::<String>::new(),
                ),
                _ => unreachable!(),
            })
            .collect();

        let last_hashes: Vec<H256> = vec![H256::zero(); 256];
        let state_root = header_template.state_root;
        let (restored_block, warns) =
            request_restored_block(&rpc_client, txs, last_hashes, header_template, state_root)
                .await
                .unwrap();

        header_template = restored_block.header.clone();

        match (warns, force_resume) {
            (warns, _) if warns.is_empty() => {
                log::info!(
                    "EVM Block {} (slot {}) restored with no warnings",
                    &restored_block.header.block_number,
                    header_template.native_chain_slot
                );
                restored_blocks.push(restored_block);
            }
            (warns, false) => {
                log::error!(
                    "Unable to restore EVM block {} (slot {})",
                    &restored_block.header.block_number,
                    header_template.native_chain_slot
                );
                log::error!("Failed transactions {:?}", &warns);
                return Err(anyhow!("Block restore failed: try `--force-resume` mode"));
            }
            (warns, true) => {
                log::warn!(
                    "EVM Block {} (slot {}) restored with warnings",
                    &restored_block.header.block_number,
                    header_template.native_chain_slot
                );
                log::warn!("Failed transactions: {:?}", &warns);
                restored_blocks.push(restored_block);
            }
        }
    }

    log::info!("{} blocks restored.", restored_blocks.len());
    log::debug!("{:?}", &restored_blocks);

    if tail.parent_hash != restored_blocks.iter().last().unwrap().header.hash() {
        log::error!("❌❌❌ Hashes do not match! ❌❌❌");
        return Ok(());
    }

    log::info!("✅✅✅ Hashes match! ✅✅✅");

    if let Some(output_dir) = output_dir {
        let unixtime = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let blocks_path = PathBuf::new().join(&output_dir).join(format!(
            "restored-blocks-{}-{}-{}.json",
            first_block, last_block, unixtime
        ));

        let _ = std::fs::create_dir_all(&output_dir);

        std::fs::write(
            blocks_path,
            serde_json::to_string(&restored_blocks).unwrap(),
        )
        .unwrap();
    }

    if modify_ledger {
        write_blocks_collection(&ledger, restored_blocks).await?;
    }

    Ok(())
}

async fn request_restored_block(
    rpc_client: &RpcClient,
    txs: Vec<(RPCTransaction, Vec<String>)>,
    last_hashes: Vec<H256>,
    block_header: BlockHeader,
    state_root: H256,
) -> Result<(Block, Vec<Hex<H256>>)> {
    let params = json!([txs, last_hashes, block_header, state_root]);

    let result: (Block, Vec<Hex<H256>>) = rpc_client
        .send(RpcRequest::DebugRecoverBlockHeader, params)
        .unwrap();

    Ok(result)
}
