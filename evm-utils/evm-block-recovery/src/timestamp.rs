use std::collections::HashMap;

use anyhow::*;
use chrono::{DateTime, Utc};
use evm_state::BlockNum;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
struct BlockDto {
    number: u64,
    timestamp: DateTime<Utc>,
}

/// FIXME: Source timestamp file exported with Time Zone error
const FIVE_HRS: u64 = 18000;

pub fn load_timestamps() -> Result<HashMap<BlockNum, u64>> {
    let timestamps = std::fs::read_to_string("./timestamps/blocks.json").unwrap();

    Ok(serde_json::from_str::<Vec<BlockDto>>(&timestamps)
        .unwrap()
        .into_iter()
        .map(|block| (block.number, block.timestamp.timestamp() as u64 - FIVE_HRS))
        .collect())
}
