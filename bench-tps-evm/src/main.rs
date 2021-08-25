use log::*;
use std::{process::exit, sync::Arc};

use solana_bench_tps_evm::bench::generate_and_fund_keypairs;
use solana_bench_tps_evm::bench_evm::{self, Peer};
use solana_bench_tps_evm::cli;
use solana_core::gossip_service::{discover_cluster, get_client, get_multi_client};

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
    let nodes = discover_cluster(entrypoint_addr, *num_nodes).unwrap_or_else(|err| {
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

    let keypairs = generate_and_fund_keypairs(
        client.clone(),
        Some(*faucet_addr),
        id,
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
        *num_lamports_per_account,
    )
    .unwrap_or_else(|e| {
        eprintln!("Error could not fund evm keys: {:?}", e);
        exit(1);
    });

    // Init nonce = 0
    let keypairs = keypairs
        .into_iter()
        .map(|(k, s)| Peer(std::sync::Arc::new(k), s, 0))
        .collect();
    bench_evm::do_bench_tps(client, cli_config, keypairs);
}
