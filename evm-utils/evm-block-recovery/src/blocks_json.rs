use std::{collections::HashMap, path::Path};

use anyhow::*;
use chrono::{DateTime, Utc};
use evm_state::BlockNum;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
struct BlockDto {
    number: u64,
    timestamp: Option<DateTime<Utc>>,
    unixtime: Option<u64>,
    txs: Option<Vec<evm_rpc::RPCTransaction>>,
}

pub struct BlockInfo {
    pub timestamp: u64,
    pub txs: Option<Vec<evm_rpc::RPCTransaction>>,
}

/// FIXME: Source timestamp file exported with Time Zone error
pub const HR_TIMESTAMP: i64 = 60 * 60;

pub fn load_blocks(
    path: impl AsRef<Path>,
    timestamp_offset: i64,
) -> Result<HashMap<BlockNum, BlockInfo>> {
    let timestamps = std::fs::read_to_string(path).unwrap();

    let result: HashMap<BlockNum, BlockInfo> = serde_json::from_str::<Vec<BlockDto>>(&timestamps)
        .unwrap()
        .into_iter()
        .map(|block| {
            let block_number = block.number;

            // Extract time from "unixtime" prop., or try to parse ISO 8601 "timestamp" prop.
            let time = block
                .unixtime
                .or_else(|| {
                    block
                        .timestamp
                        .map(|t| (t.timestamp() + timestamp_offset) as u64)
                })
                .unwrap();
            (
                block_number,
                BlockInfo {
                    timestamp: time,
                    txs: block.txs,
                },
            )
        })
        .collect();

    Ok(result)
}
