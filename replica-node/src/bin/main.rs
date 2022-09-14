use solana_replica_lib::triedb_repl_client;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let val = triedb_repl_client::get_earliest_block().await;

    println!("{:?}", val);
    Ok(())
}
