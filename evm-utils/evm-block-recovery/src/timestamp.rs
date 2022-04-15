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

pub fn load_timestamps() -> Result<HashMap<BlockNum, u64>> {
    let timestamps = std::fs::read_to_string("./timestamps/blocks.json").unwrap();

    Ok(serde_json::from_str::<Vec<BlockDto>>(&timestamps)
        .unwrap()
        .into_iter()
        .map(|block| (block.number, block.timestamp.timestamp() as u64))
        .collect())
}
