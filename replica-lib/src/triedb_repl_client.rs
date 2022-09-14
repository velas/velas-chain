use app_grpc::backend_client::BackendClient;
use evm_rpc::RPCBlock;
// use solana_sdk::example_mocks::solana_client;
use solana_client::rpc_client::RpcClient;

use std::net::SocketAddr;

pub mod app_grpc {
    tonic::include_proto!("triedb_repl");
}

pub async fn get_earliest_block() -> Result<String, solana_client::client_error::ClientError> {
    use serde_json::{json, Value};

    let addr = SocketAddr::from(([64, 52, 81, 175], 8899));
    let client = solana_client::rpc_client::RpcClient::new_socket(addr);

    let response = client.send::<Option<evm_rpc::RPCBlock>>(
            solana_client::rpc_request::RpcRequest::EthGetBlockByNumber,
            json!(["earliest",true])
        )?;

    if let Some(block) = response {
        Ok(format!("{:?}", block))
    } else {
        Ok(String::from("NOT FOUND"))
    }
}

pub async fn get_next_block(block_number: String) -> Result<String, solana_client::client_error::ClientError> {
    use serde_json::{json, Value};

    let client = solana_client::rpc_client::RpcClient::new("64.52.81.175:8899".to_string());

    let response = client.send::<Option<evm_rpc::RPCBlock>>(
            solana_client::rpc_request::RpcRequest::EthGetBlockByNumber,
            json!(["earliest",true])
        )?;

    if let Some(block) = response {
        Ok(format!("{:?}", block))
    } else {
        Ok(String::from("NOT FOUND"))
    }
}

async fn ping() -> Result<(), Box<dyn std::error::Error>> {
    let mut client = BackendClient::connect("http://127.0.0.1:8000").await?;
    let request = tonic::Request::new(());
    let response = client.ping(request).await?;
    println!("PING | RESPONSE={:?}", response);
    Ok(())
}

// async fn get_block() -> Result<(), Box<dyn std::error::Error>> {
//     let mut client = BackendClient::connect("http://127.0.0.1:8000").await?;
//     let hash_of_root : String = std::fs::read_to_string("./.tmp/state_root.txt")?.parse()?;
//     let request = tonic::Request::new(app_grpc::GetBlockRequest {
//         hash: hash_of_root
//     });
//     let response = client.get_block(request).await?;
//     println!("GET BLOCK | RESPONSE={:?}", response);
//     Ok(())
// }
