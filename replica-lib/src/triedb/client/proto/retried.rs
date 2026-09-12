use std::ops::Range;

use evm_state::{BlockNum, H256};

use crate::triedb::{client::Client, error::client::bootstrap::fetch_nodes, retry_logged};

use super::app_grpc::{self, backend_client::BackendClient};

impl<S> Client<S> {
    pub(crate) async fn get_server_range_retried(&self) -> Result<Range<BlockNum>, tonic::Status> {
        let res = retry_logged(
            || {
                let mut client = self.client.clone();
                async move { Self::get_block_range(&mut client, &self.state_rpc_address).await }
            },
            format!("fetch servers_range {}", self.state_rpc_address),
            log::Level::Trace,
        )
        .await?;

        Ok(res.into())
    }

    pub(crate) async fn prefetch_height_retried(
        &self,
        height: BlockNum,
    ) -> Result<Option<app_grpc::PrefetchHeightReply>, tonic::Status> {
        let res =
            retry_logged(
                || {
                    let mut client = self.client.clone();
                    async move {
                        Self::prefetch_height(&mut client, height, &self.state_rpc_address).await
                    }
                },
                format!(
                    "issue prefetch_height request {}, {height}",
                    self.state_rpc_address
                ),
                log::Level::Info,
            )
            .await?;

        Ok(res)
    }

    pub(crate) async fn prefetch_range_retried(
        &self,
        range: &Range<BlockNum>,
    ) -> Result<(), tonic::Status> {
        retry_logged(
                || {
                    let mut client = self.client.clone();
                    async move {
                        Self::prefetch_range(&mut client, range, &self.state_rpc_address).await
                    }
                },
                format!(
                    "send prefetch_range request {} {:?}",
                    self.state_rpc_address, range
                ),
                log::Level::Info,
            )
            .await?;

        Ok(())
    }

    pub(crate) async fn get_array_of_nodes_retried(
        client: &BackendClient<tonic::transport::Channel>,
        rpc_address: &String,
        hashes: Vec<H256>,
    ) -> Result<
        Result<app_grpc::GetArrayOfNodesReply, fetch_nodes::get::FastError>,
        fetch_nodes::get::SlowError,
    > {
        let res = retry_logged(
            || {
                let hashes = hashes.clone();
                let mut client = client.clone();
                async move {
                    let result = Self::get_array_of_nodes(&mut client, hashes).await;
                    match result {
                        Ok(res) => Ok(Ok(res)),
                        Err(err) => match err.into() {
                            fetch_nodes::get::Error::Fast(fast) => Ok(Err(fast)),
                            fetch_nodes::get::Error::Slow(slow) => Err(slow),
                        },
                    }
                }
            },
            format!(
                "get_array_of_nodes request {} {}",
                rpc_address,
                hashes.len()
            ),
            log::Level::Trace,
        )
        .await?;

        Ok(res)
    }
}
