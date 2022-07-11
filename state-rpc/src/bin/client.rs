use app_grpc::backend_client::BackendClient;
pub mod app_grpc {
    tonic::include_proto!("rpcserver");
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut client = BackendClient::connect("http://127.0.0.1:8000").await?;
    let request = tonic::Request::new(());
    let response = client.ping(request).await?;
    println!("RESPONSE={:?}", response);

    get_block().await;

    Ok(())
}

async fn get_block() -> Result<(), Box<dyn std::error::Error>> {
    let mut client = BackendClient::connect("http://127.0.0.1:8000").await?;
    let request = tonic::Request::new(app_grpc::GetBlockRequest {
        hash: "4387483748378473".to_string()
    });
    let response = client.get_block(request).await?;
    println!("RESPONSE={:?}", response);
    Ok(())
}
