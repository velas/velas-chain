use log::info;

use evm_state::H256;

use super::Server;
use app_grpc::backend_server::{Backend, BackendServer};
use tonic::{Request, Response, Status};

use app_grpc::PingReply;
pub mod app_grpc {
    tonic::include_proto!("triedb_repl");
}
mod helpers;
mod storage;

use crate::triedb::EvmHeightIndex;

trait TryConvert<S>: Sized {
    type Error;

    fn try_from(value: S) -> Result<Self, Self::Error>;
}

const MAX_CHUNK: usize = 100000;

#[tonic::async_trait]
impl<S: EvmHeightIndex + Sync + Send + 'static> Backend for Server<S> {
    async fn ping(&self, request: Request<()>) -> Result<Response<PingReply>, Status> {
        info!("got a ping request: {:?}", request);

        let reply = app_grpc::PingReply {
            message: "ABDULA STATUS 7".to_string(),
        };

        Ok(Response::new(reply))
    }

    async fn get_array_of_nodes(
        &self,
        request: Request<app_grpc::GetArrayOfNodesRequest>,
    ) -> Result<Response<app_grpc::GetArrayOfNodesReply>, Status> {
        let request = request.into_inner();
        info!(
            "got a get_array_of_nodes request: {:?}",
            request.hashes.len()
        );
        if request.hashes.len() > MAX_CHUNK {
            return Err(Status::failed_precondition(format!(
                "chunk size {}",
                request.hashes.len()
            )));
        }
        let mut nodes = vec![];
        for hash in request.hashes {
            let key = <H256 as TryConvert<_>>::try_from(hash)?;
            let bytes = self.get_node_body(key)?;
            nodes.push(bytes);
        }

        let reply = app_grpc::GetArrayOfNodesReply { nodes };

        Ok(Response::new(reply))
    }

    async fn get_state_diff(
        &self,
        request: Request<app_grpc::GetStateDiffRequest>,
    ) -> Result<Response<app_grpc::GetStateDiffReply>, Status> {
        info!("got a state_diff request: {:?}", request);

        let inner = request.into_inner();
        let height_diff = if inner.to >= inner.from {
            inner.to - inner.from
        } else {
            inner.from - inner.to
        };
        if height_diff > self.block_threshold {
            return Err(Status::invalid_argument(format!(
                "blocks too far {}",
                inner.to - inner.from
            )));
        }
        let (from, to) = self
            .fetch_state_roots(inner.from, inner.to)
            .await
            .map_err(|err| {
                log::error!("fetch_state_roots encountered err {:?}", err);
                Status::internal("failure to fetch state roots")
            })?;
        self.state_diff_body(from, to)
    }

    async fn get_block_range(
        &self,
        _request: tonic::Request<()>,
    ) -> Result<tonic::Response<app_grpc::GetBlockRangeReply>, tonic::Status> {
        let r: std::ops::Range<evm_state::BlockNum> = self.range.get();
        let reply = app_grpc::GetBlockRangeReply {
            start: r.start,
            end: r.end,
        };

        Ok(Response::new(reply))
    }
}

impl<S: EvmHeightIndex + Sync + Send + 'static> BackendServer<Server<S>> {
    pub fn join(&self) -> Result<(), Box<(dyn std::error::Error + 'static)>> {
        Ok(())
    }
}
