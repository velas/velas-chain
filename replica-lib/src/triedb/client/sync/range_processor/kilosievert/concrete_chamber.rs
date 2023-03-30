use std::{
    ops::Range,
    sync::Arc,
    time::{Duration, Instant},
};

use evm_state::BlockNum;
use tokio::sync::{mpsc::Sender, Semaphore};

use crate::triedb::{
    client::{
        proto::app_grpc::backend_client::BackendClient,
        sync::range_processor::kickstart_point::KickStartPoint,
    },
    debug_elapsed,
    error::{DiffRequest, StageOneError},
    EvmHeightIndex,
};

use super::diff_stages;

pub mod steel_container;

#[derive(Debug)]
pub struct StageOnePayload {
    pub ledger_storage_dur: Duration,
    pub diff_request_dur: Duration,
    pub request: DiffRequest,
    pub changeset: Vec<triedb::DiffChange>,
}

pub async fn process<S>(
    client: &BackendClient<tonic::transport::Channel>,
    block_storage: &S,
    range: Range<BlockNum>,
    kickstart_point: KickStartPoint,
    state_rpc_address: String,
    stage_one_output: Sender<Result<StageOnePayload, StageOneError>>,
    request_workers: u32,
) where
    S: EvmHeightIndex + Clone + Sync + Send + 'static,
{
    let s = Arc::new(Semaphore::new(request_workers as usize));

    for target in range {
        let permit = s
            .clone()
            .acquire_owned()
            .await
            .expect("semaphore closed?!?");

        let job_for_a_cowboy = client.clone();
        let kickstart_point_clone = kickstart_point.clone();
        let stage_one_output_clone = stage_one_output.clone();
        let rpc_addr = state_rpc_address.clone();
        let block_storage_clone = block_storage.clone();
        let _jh = tokio::task::spawn(async move {
            let from = kickstart_point_clone.get();

            let mut instant = Instant::now();
            let target_hash = block_storage_clone
                .get_evm_confirmed_state_root_retried(target)
                .await;
            let ledger_storage_dur = debug_elapsed(&mut instant);
            let target_hash = match target_hash {
                Ok(hash) => hash,
                Err(err) => {
                    let send_res = stage_one_output_clone.send(Err(err.into())).await;
                    if send_res.is_err() {
                        log::error!("stage two input closed");
                    }
                    return;
                }
            };

            let request = DiffRequest {
                heights: (from.height, target),
                expected_hashes: (from.hash, target_hash),
            };
            let result = diff_stages::one::<S>(&job_for_a_cowboy, request, &rpc_addr).await;
            let result = result.map(|(diff_request_dur, request, changeset)| StageOnePayload {
                ledger_storage_dur,
                diff_request_dur,
                request,
                changeset,
            });

            let send_res = stage_one_output_clone
                .send(result.map_err(Into::into))
                .await;
            if send_res.is_err() {
                log::error!("stage two input closed");
            }

            drop(permit);
        });
    }
}
