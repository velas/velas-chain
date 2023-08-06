use {
    super::write_blocks_collection,
    crate::{
        cli::UploadArgs,
        error::{AppError, RoutineResult},
        ledger,
    },
    evm_state::Block,
};

pub async fn upload(creds: Option<String>, instance: String, args: UploadArgs) -> RoutineResult {
    let UploadArgs { collection } = args;
    let ledger = ledger::with_params(creds, instance).await?;

    log::info!("Reading file: '{}'...", &collection);
    let content = std::fs::read_to_string(&collection).map_err(AppError::ReadFile)?;

    log::info!("{} length string read.", content.len());
    log::info!("Deserializing data...");
    let blocks: Vec<Block> = serde_json::from_str(&content).map_err(AppError::JsonDeserialize)?;

    if blocks.is_empty() {
        log::warn!("Blocks collection is empty, nothing to upload, exiting...");
        return Ok(());
    }

    log::info!("Blocks in collection: {}", blocks.len());

    let block_ids = blocks
        .iter()
        .map(|b| b.header.block_number)
        .collect::<Vec<_>>();

    log::info!("Block numbers: {:?}", &block_ids);

    write_blocks_collection(&ledger, blocks).await?;

    Ok(())
}
