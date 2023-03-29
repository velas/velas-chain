use evm_rpc::FormatHex;
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

use crate::triedb::{
    error::{ServerError, ServerProtoError},
    EvmHeightIndex, TryConvert, MAX_CHUNK_HASHES,
};

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
        if request.hashes.len() > MAX_CHUNK_HASHES {
            return Err(ServerProtoError::ExceededMaxChunkGetArrayOfNodes {
                actual: request.hashes.len(),
                max: MAX_CHUNK_HASHES,
            })?;
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
            return Err(ServerProtoError::StateDiffBlocksTooFar {
                to: inner.to,
                from: inner.from,
            })?;
        }
        let (from_hash, to_hash) = self.fetch_state_roots(inner.from, inner.to).await?;

        helpers::check_hash(inner.from, inner.first_root, from_hash)?;
        helpers::check_hash(inner.to, inner.second_root, to_hash)?;
        Ok(self.state_diff_body(from_hash, to_hash)?)
    }

    async fn get_block_range(
        &self,
        _request: tonic::Request<()>,
    ) -> Result<tonic::Response<app_grpc::GetBlockRangeReply>, tonic::Status> {
        info!("got a get_block_range request");
        let r: std::ops::Range<evm_state::BlockNum> = self.range.get();
        let reply = app_grpc::GetBlockRangeReply {
            start: r.start,
            end: r.end,
        };

        Ok(Response::new(reply))
    }

    async fn prefetch_height(
        &self,
        request: tonic::Request<app_grpc::PrefetchHeightRequest>,
    ) -> Result<tonic::Response<app_grpc::PrefetchHeightReply>, tonic::Status> {
        info!("got a prefetch_height request {:?}", request);
        let hash = self
            .block_storage
            .get_evm_confirmed_state_root(request.into_inner().height)
            .await
            .map_err(Into::<ServerError>::into)?;

        // we have to minimally ensure a client has some basis to try to start work from
        // otherwise a well-behaving client can trigger long chunks of work, all of which
        // are doomed to fail
        self.get_node_body(hash)?;
        Ok(Response::new(app_grpc::PrefetchHeightReply {
            hash: Some(app_grpc::Hash {
                value: hash.format_hex(),
            }),
        }))
    }

    async fn prefetch_range(
        &self,
        request: tonic::Request<app_grpc::PrefetchRangeRequest>,
    ) -> Result<tonic::Response<()>, tonic::Status> {
        info!("got a prefetch_range request {:?}", request);
        let req = request.into_inner();
        let requested = req.start..req.end;
        let self_range = self.range.get();
        if !self_range.contains(&requested.start) || !self_range.contains(&(requested.end - 1)) {
            return Err(ServerError::PrefetchRange {
                ours: self_range,
                requested,
            })?;
        }

        self.block_storage
            .prefetch_roots(&requested)
            .await
            .map_err(Into::<ServerError>::into)?;
        Ok(Response::new(()))
    }
}

impl<S: EvmHeightIndex + Sync + Send + 'static> BackendServer<Server<S>> {
    pub fn join(&self) -> Result<(), Box<(dyn std::error::Error + 'static)>> {
        Ok(())
    }
}
