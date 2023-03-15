mod cached_height_index;
mod range_map;
mod storage;

use async_trait::async_trait;
use evm_state::{BlockNum, H256};

use range_map::MasterRange;

use crate::{cli::ScanEvmStateRootsArgs, error::AppError};

#[async_trait]
pub trait EvmHeightIndex {
    async fn get_evm_confirmed_state_root(&self, block_num: BlockNum) -> Option<H256>;
    async fn schedule_height(
        &self,
        height: BlockNum,
    ) -> Result<(), tokio::sync::mpsc::error::SendError<BlockNum>>;
}

async fn routine(
    vec: Vec<BlockNum>,
    storage: storage::Storage,
    range: MasterRange,
) -> Result<(), Box<dyn std::error::Error + 'static + Send + Sync>> {
    let handle = tokio::runtime::Handle::current();
    let (bigtable, _jh) = cached_height_index::CachedHeightIndexSpunOff::new(&handle).await?;

    let vec_double = vec.clone();
    let bigtable_double = bigtable.clone();
    let _bg_push = handle.spawn(async move {
        for el in vec_double {
            let res = bigtable_double.schedule_height(el).await;
            if res.is_err() {
                panic!("send failed {:?}", res);
            }
        }
    });

    for height in vec {
        let key = bigtable.get_evm_confirmed_state_root(height).await;
        let result = if let Some(key) = key {
            let present = storage.check_node(key)?;
            if present {
                Some("X")
            } else {
                None
            }
        } else {
            Some("N")
        };
        if let Some(result) = result {
            range.update(height, result.to_string())?;
            println!("{} -> {:?}, {}", height, key, result,);
        }
    }
    Ok(())
}

pub async fn command(args: &ScanEvmStateRootsArgs) -> Result<(), AppError> {
    let ScanEvmStateRootsArgs {
        start,
        end_exclusive,
        evm_state_path,
        workers,
        secondary,
        gc,
        rangemap_json,
    } = args;
    let handle = tokio::runtime::Handle::current();
    let vec = Vec::from_iter(*start..*end_exclusive);
    let fork_joins: Vec<_> = vec.chunks(vec.len() / (*workers as usize)).collect();
    let mut ranges = vec![];
    let storage = storage::Storage::new(evm_state_path, *secondary, *gc)?;

    let rangemap = range_map::MasterRange::new(rangemap_json)?;
    println!("total chunks: {}", fork_joins.len());
    for el in fork_joins {
        println!("spawning chunk {}", el.len());
        let storage_double = storage.clone();
        let rangemap_doule = rangemap.clone();
        let range_jh = handle.spawn(routine(el.to_vec(), storage_double, rangemap_doule));
        ranges.push(range_jh);
    }

    for range in ranges {
        let res = range.await;
        eprintln!("{:?}", res);
    }

    Ok(())
}
