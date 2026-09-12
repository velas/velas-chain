use crate::error::AppError;

pub async fn command() -> Result<(), AppError> {
    println!("scratchpad");
    Ok(())
}
