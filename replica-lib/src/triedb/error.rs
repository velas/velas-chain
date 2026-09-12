use thiserror::Error;

pub mod client;
mod common;
pub mod server;

pub use common::evm_height;
pub use common::lock;

#[cfg(test)]
mod tests;

#[derive(Error, Debug)]
pub enum RangeJsonInitError {
    #[error(transparent)]
    IoError(#[from] std::io::Error),
    #[error(transparent)]
    SerdeJson(#[from] serde_json::Error),
}

pub fn source_matches_type<T: std::error::Error + 'static>(
    mut err: &(dyn std::error::Error + 'static),
) -> bool {
    let type_name = std::any::type_name::<T>();
    loop {
        if let Some(transport) = err.downcast_ref::<T>() {
            log::error!("matching source type `{:?}`: `{}`", transport, type_name);
            break true;
        }
        if let Some(source) = err.source() {
            log::debug!("Caused by: {}", source);
            err = source;
        } else {
            break false;
        }
    }
}
