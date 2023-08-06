use {
    crate::error::AppError,
    chrono::{DateTime, Utc},
    evm_state::BlockNum,
    serde::{Deserialize, Serialize},
    std::{collections::HashMap, path::Path},
};

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

pub fn load_blocks(
    path: impl AsRef<Path>,
    timestamp_offset: i64,
) -> Result<HashMap<BlockNum, BlockInfo>, AppError> {
    log::info!("Reading file: '{}'...", path.as_ref().display());
    let timestamps = std::fs::read_to_string(&path).map_err(AppError::ReadFile)?;

    let result: HashMap<BlockNum, BlockInfo> = serde_json::from_str::<Vec<BlockDto>>(&timestamps)
        .map_err(AppError::JsonDeserialize)?
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
