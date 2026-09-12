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
    error::client::range_sync::stages,
    DiffRequest, DB_SEMAPHORE_PERMITS_PER_LARGE_DIFF,
};

use super::StageOnePayload;

#[derive(Debug)]
pub struct StageTwoPayload {
    pub apply_duration: Duration,
    pub request: DiffRequest,
    pub changeset_len: usize,
    pub result_root_gc_count: usize,
}

const SEMAPHORE_PERMITS_THRESHOLD: u64 = 100_000;

pub async fn process(
    kickstart_point: KickStartPoint,
    storage: Storage,
    mut stage_two_input: Receiver<Result<StageOnePayload, stages::one::Error>>,
    stage_two_output: Sender<Result<StageTwoPayload, stages::two::Error>>,
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

        let n_permits = if (stage_one.request.heights.1 - stage_one.request.heights.0)
            > SEMAPHORE_PERMITS_THRESHOLD
        {
            DB_SEMAPHORE_PERMITS_PER_LARGE_DIFF
        } else {
            1
        };
        let permit = s
            .clone()
            .acquire_many_owned(n_permits)
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
                    let result: Result<StageTwoPayload, stages::two::Error> = {
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
                            Err(err) => {
                                let err = stages::two::Error::Apply(stage_one.request, err);
                                Err(err)
                            }
                        }
                        // let guard =
                    };
                    result
                })
                .await;
                let result = match result {
                    Err(err) => {
                        let err = stages::two::Error::TaskPanicked(stage_one.request, err);

                        Err(err)
                    }
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
