use std::{sync::Arc, time::Duration};

use evm_state::Storage;
use tokio::sync::{
    mpsc::{Receiver, Sender},
    Semaphore,
};
use triedb::gc::DbCounter;

use crate::triedb::{
    client::sync::range_processor::{kickstart_point::KickStartPoint, kilosievert::diff_stages},
    collection,
    error::{DiffRequest, StageOneError, StageTwoError},
};

use super::StageOnePayload;

#[derive(Debug)]
pub struct StageTwoPayload {
    pub apply_duration: Duration,
    pub request: DiffRequest,
    pub changeset_len: usize,
    pub result_root_gc_count: usize,
}

pub async fn process(
    kickstart_point: KickStartPoint,
    storage: Storage,
    mut stage_two_input: Receiver<Result<StageOnePayload, StageOneError>>,
    stage_two_output: Sender<Result<StageTwoPayload, StageTwoError>>,
    db_workers: u32,
) {
    let s = Arc::new(Semaphore::new(db_workers as usize));
    while let Some(stage_one_result) = stage_two_input.recv().await {
        let stage_one = match stage_one_result {
            Err(err) => {
                let send_res = stage_two_output.send(Err(err.into())).await;
                if send_res.is_err() {
                    log::error!("stage three input closed");
                }
                continue;
            }
            Ok(stage_one) => stage_one,
        };
        log::debug!(
            "< {:?} {:?} {} > - {:#?} ",
            stage_one.ledger_storage_dur,
            stage_one.diff_request_dur,
            stage_one.changeset.len(),
            stage_one.request
        );

        let permit = s
            .clone()
            .acquire_owned()
            .await
            .expect("semaphore closed?!?");
        let _jh = tokio::task::spawn({
            let stage_two_output = stage_two_output.clone();
            let storage = storage.clone();
            let kickstart_point = kickstart_point.clone();

            async move {
                let changeset_len = stage_one.changeset.len();
                //
                // rocksdb's `ColumnFamily` being not `Send` prevents it being used across `await` point
                //
                let result = tokio::task::spawn_blocking(move || {
                    let result: Result<StageTwoPayload, StageTwoError> = {
                        let collection = collection(&storage);
                        let apply_result =
                            diff_stages::two((stage_one.request, stage_one.changeset), &collection);
                        match apply_result {
                            Ok((duration, root_guard)) => {
                                let target = root_guard.leak_root();
                                assert_eq!(stage_one.request.expected_hashes.1, target);

                                collection.database.gc_pin_root(target);
                                let result_count = collection.database.gc_count(target);
                                kickstart_point.update(stage_one.request.heights.1, target);
                                Ok(StageTwoPayload {
                                    apply_duration: duration,
                                    changeset_len,
                                    request: stage_one.request,
                                    result_root_gc_count: result_count,
                                })
                            }
                            Err(err) => Err(err.into()),
                        }
                        // let guard =
                    };
                    result
                })
                .await;
                let result = match result {
                    Err(err) => Err(err.into()),
                    Ok(result) => result,
                };

                let send_res = stage_two_output.send(result).await;

                if send_res.is_err() {
                    log::error!("stage three input closed");
                }
                drop(permit);
            }
        });
    }
}
