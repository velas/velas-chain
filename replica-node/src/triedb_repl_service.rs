use {
    crate::accountsdb_repl_service::AccountsDbReplService,
    crossbeam_channel::unbounded,
    log::*,
    solana_download_utils::download_snapshot_archive,
    solana_genesis_utils::download_then_check_genesis_hash,
    solana_gossip::{cluster_info::ClusterInfo, contact_info::ContactInfo},
    solana_ledger::{
        blockstore::Blockstore, blockstore_db::AccessType, blockstore_processor,
        leader_schedule_cache::LeaderScheduleCache,
    },
    solana_replica_lib::accountsdb_repl_client::AccountsDbReplClientServiceConfig,
    solana_replica_lib::triedb_repl_server,
    solana_rpc::{
        max_slots::MaxSlots,
        optimistically_confirmed_bank_tracker::{
            OptimisticallyConfirmedBank, OptimisticallyConfirmedBankTracker,
        },
        rpc::JsonRpcConfig,
        rpc_pubsub_service::{PubSubConfig, PubSubService},
        rpc_service::JsonRpcService,
        rpc_subscriptions::RpcSubscriptions,
    },
    solana_runtime::{
        accounts_index::AccountSecondaryIndexes, bank_forks::BankForks,
        commitment::BlockCommitmentCache, hardened_unpack::MAX_GENESIS_ARCHIVE_UNPACKED_SIZE,
        snapshot_config::SnapshotConfig, snapshot_package::SnapshotType, snapshot_utils,
    },
    solana_sdk::{clock::Slot, exit::Exit, genesis_config::GenesisConfig, hash::Hash},
    solana_send_transaction_service::send_transaction_service,
    solana_streamer::socket::SocketAddrSpace,
    std::{
        fs,
        net::SocketAddr,
        path::PathBuf,
        sync::{
            atomic::{AtomicBool, AtomicU64},
            Arc, RwLock,
        },
    },
};

// TODO: Entry point to start state-rpc service
// Needs to accept ENV variable and do not panic!
// This file is just an example how to run the service
pub fn start_triedb_repl() {
    use std::path::PathBuf;
    let archive_path = PathBuf::from("./tmp-ledger-path/archive");

    let config = triedb_repl_server::StateRpcServiceConfig::from_str_addr_and_thread_number("0.0.0.0:8888".to_string(), 2, archive_path);
    let backend_server = triedb_repl_server::TriedbReplServer::new_backend_server(&config);
    println!("starting the thread");
    triedb_repl_server::TriedbReplService::new(config, backend_server.into()).join();
}
