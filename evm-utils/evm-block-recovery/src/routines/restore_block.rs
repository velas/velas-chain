use std::str::FromStr;

use anyhow::*;
use evm_rpc::{Hex, RPCTransaction};
use evm_state::{
    Block, BlockHeader, BlockNum, ExitReason, ExitSucceed, TransactionInReceipt,
    TransactionReceipt, H256,
};
use serde_json::json;
use solana_client::{rpc_client::RpcClient, rpc_request::RpcRequest};
use solana_evm_loader_program::instructions::EvmInstruction;
use solana_sdk::pubkey::Pubkey;
use solana_storage_bigtable::LedgerStorage;

use crate::extensions::{NativeBlockExt, ParsedInstructions};

pub async fn restore_block(
    ledger: &LedgerStorage,
    rpc_address: String,
    restoring_block: BlockNum,
    dry_run: bool,
) -> Result<()> {
    let state_block_id = restoring_block - 1;
    let mut block_header = ledger
        .get_evm_confirmed_block_header(state_block_id)
        .await
        .context(format!(
            "Unable to get EVM header for block {}",
            state_block_id
        ))?;

    // FIXME: maybe more than + 1
    let native_block_id = block_header.native_chain_slot + 1;

    let native_block = ledger
        .get_confirmed_block(native_block_id)
        .await
        .context(format!(
            "Unable to get Native confirmed block {}",
            native_block_id
        ))?;
    let parsed_instructions = native_block.parse_instructions();

    if !parsed_instructions.only_trivial_instructions {
        return Err(anyhow!(
            "Native block {native_block_id} contains non-trivial instructions"
        ));
    }

    // FIXME: maybe more than + 1
    block_header.native_chain_slot += 1;

    block_header.native_chain_hash = H256(
        Pubkey::from_str(&native_block.blockhash)
            .unwrap()
            .to_bytes(),
    );

    // TODO: additional checks required
    block_header.timestamp = native_block.block_time.unwrap() as u64;

    // block_header.timestamp = 1649438213 as u64; // :(

    block_header.block_number += 1;

    // FIXME: generate parent_hash properly
    block_header.parent_hash =
        H256::from_str("c5af87ed427d114a2cfdfdc3bb03b02a7428ee937a0c6e2b616f2ee326f167f4").unwrap();

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
    let state_root = block_header.state_root;

    let header = request_restored_header(rpc_address, txs, last_hashes, block_header, state_root)
        .await
        .unwrap();

    // let full_block = create_block(header, restoring_block, parsed_instructions);

    log::info!("Restored EVM header:\n{:#?}", &header);

    /// DEBUG BLOCK
    let compare_header = ledger
        .get_evm_confirmed_block_header(restoring_block)
        .await
        .unwrap();

    log::info!("Original EVM block\n{:#?}", compare_header);
    /// DEBUG BLOCK
    if dry_run {
        return Ok(());
    }

    // write_block(&ledger, restoring_block, full_block).await?;

    Ok(())
}

async fn request_restored_header(
    rpc_address: String,
    txs: Vec<(RPCTransaction, Vec<String>)>,
    last_hashes: Vec<H256>,
    block_header: BlockHeader,
    state_root: H256,
) -> Result<BlockHeader> {
    let rpc_client = RpcClient::new(rpc_address);

    let params = json!([txs, last_hashes, block_header, state_root]);

    let result: BlockHeader = rpc_client
        .send(RpcRequest::DebugRecoverBlockHeader, params)
        .unwrap();

    Ok(result)
}

async fn write_block(ledger: &LedgerStorage, block_num: BlockNum, full_block: Block) -> Result<()> {
    ledger
        .upload_evm_block(block_num, full_block)
        .await
        .context(format!("Unable to write block {block_num} to bigtable"))?;

    Ok(())
}

fn create_block(
    header: BlockHeader,
    block_number: BlockNum,
    parsed_instructions: ParsedInstructions,
) -> Block {
    let transactions = parsed_instructions
        .instructions
        .into_iter()
        .map(|instr| match instr {
            EvmInstruction::EvmTransaction { evm_tx } => (
                H256::zero(), // FIXME
                TransactionReceipt::new(
                    TransactionInReceipt::Signed(evm_tx),
                    0, // FIXME
                    block_number,
                    0,      // FIXME
                    vec![], // FIXME
                    (
                        ExitReason::Succeed(ExitSucceed::Stopped), // FIXME
                        vec![],                                    // FIXME
                    ),
                ),
            ),
            _ => unreachable!(),
        })
        .collect::<Vec<_>>();

    Block {
        header,
        transactions,
    }
}
