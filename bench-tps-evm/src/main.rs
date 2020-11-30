use log::*;
use solana_bench_tps_evm::bench::generate_and_fund_keypairs;
use solana_bench_tps_evm::bench_evm;
use solana_bench_tps_evm::cli;
use solana_core::gossip_service::{discover_cluster, get_client, get_multi_client};
use std::{process::exit, sync::Arc};

/// Number of signatures for all transactions in ~1 week at ~100K TPS
pub const NUM_SIGNATURES_FOR_TXS: u64 = 100_000 * 60 * 60 * 24 * 7;

fn main() {
    solana_logger::setup_with_default("solana=info");
    solana_metrics::set_panic_hook("bench-tps");

    let matches = cli::build_args(solana_version::version!()).get_matches();
    let cli_config = cli::extract_args(&matches);

    let cli::Config {
        entrypoint_addr,
        faucet_addr,
        id,
        num_nodes,
        tx_count,
        keypair_multiplier,
        multi_client,
        num_lamports_per_account,
        target_node,
        ..
    } = &cli_config;

    let keypair_count = *tx_count * keypair_multiplier;

    info!("Connecting to the cluster");
    let nodes = discover_cluster(&entrypoint_addr, *num_nodes).unwrap_or_else(|err| {
        eprintln!("Failed to discover {} nodes: {:?}", num_nodes, err);
        exit(1);
    });

    let client = if *multi_client {
        let (client, num_clients) = get_multi_client(&nodes);
        if nodes.len() < num_clients {
            eprintln!(
                "Error: Insufficient nodes discovered.  Expecting {} or more",
                num_nodes
            );
            exit(1);
        }
        Arc::new(client)
    } else if let Some(target_node) = target_node {
        info!("Searching for target_node: {:?}", target_node);
        let mut target_client = None;
        for node in nodes {
            if node.id == *target_node {
                target_client = Some(Arc::new(get_client(&[node])));
                break;
            }
        }
        target_client.unwrap_or_else(|| {
            eprintln!("Target node {} not found", target_node);
            exit(1);
        })
    } else {
        Arc::new(get_client(&nodes))
    };

    // let keypairs = if *read_from_client_file {
    //     let path = Path::new(&client_ids_and_stake_file);
    //     let file = File::open(path).unwrap();

    //     info!("Reading {}", client_ids_and_stake_file);
    //     let accounts: HashMap<String, Base64Account> = serde_yaml::from_reader(file).unwrap();
    //     let mut keypairs = vec![];
    //     let mut last_balance = 0;

    //     accounts
    //         .into_iter()
    //         .for_each(|(keypair, primordial_account)| {
    //             let bytes: Vec<u8> = serde_json::from_str(keypair.as_str()).unwrap();
    //             keypairs.push(Keypair::from_bytes(&bytes).unwrap());
    //             last_balance = primordial_account.balance;
    //         });

    //     if keypairs.len() < keypair_count {
    //         eprintln!(
    //             "Expected {} accounts in {}, only received {} (--tx_count mismatch?)",
    //             keypair_count,
    //             client_ids_and_stake_file,
    //             keypairs.len(),
    //         );
    //         exit(1);
    //     }
    //     // Sort keypairs so that do_bench_tps() uses the same subset of accounts for each run.
    //     // This prevents the amount of storage needed for bench-tps accounts from creeping up
    //     // across multiple runs.
    //     keypairs.sort_by_key(|x| x.pubkey().to_string());
    //     keypairs
    // } else {
    let keypairs = generate_and_fund_keypairs(
        client.clone(),
        Some(*faucet_addr),
        &id,
        keypair_count,
        *num_lamports_per_account,
    )
    .unwrap_or_else(|e| {
        eprintln!("Error could not fund keys: {:?}", e);
        exit(1);
    });
    let keypairs = bench_evm::generate_and_fund_evm_keypairs(
        client.clone(),
        Some(*faucet_addr),
        keypairs,
        keypair_count,
        *num_lamports_per_account,
    )
    .unwrap_or_else(|e| {
        eprintln!("Error could not fund evm keys: {:?}", e);
        exit(1);
    });
    // };

    bench_evm::do_bench_tps(client, cli_config, keypairs);
}
