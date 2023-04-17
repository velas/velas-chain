use std::{
    thread::{self, sleep},
    time,
};

use crate::triedb::{range::RangeJSON, EvmHeightIndex, ReadRange};

use super::Client;

mod bootstrap;
mod common;
mod range_processor;

impl<S> Client<S>
where
    S: EvmHeightIndex + Clone + Sync + Send + 'static,
{
    pub async fn sync(&mut self) {
        loop {
            let server_range = match self.get_server_range_retried().await {
                Err(err) => {
                    log::error!("get_block_range error after multiple retries {:?}", err);
                    sleep(time::Duration::new(30, 0));
                    continue;
                }
                Ok(range) => range,
            };
            if server_range.is_empty() {
                log::error!("server range empty");
                sleep(time::Duration::new(100, 0));
                continue;
            }
            let self_range = self.range.get().await.expect("get range");
            if self_range.is_empty() {
                match self.bootstrap_state(server_range.start).await {
                    Err(err) => {
                        log::error!("after some tries {:?}", err);
                        sleep(time::Duration::new(30, 0));
                        continue;
                    }
                    Ok(_) => continue,
                }
            } else {
                let right_diff = RangeJSON::diff(
                    self_range.clone(),
                    server_range,
                    self_range.end - 1,
                    self.max_height_gap,
                );
                let result = match right_diff.is_empty() {
                    true => {
                        log::error!("server range is too far away");
                        sleep(time::Duration::new(100, 0));
                        continue;
                    }
                    false => self.process_ranges(right_diff, self_range.end - 1).await,
                };
                if let Err(err) = result {
                    log::error!("{:?}", err);
                    thread::sleep(time::Duration::new(30, 0));
                }
            }
        }
    }
}
