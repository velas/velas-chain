use crate::cli::Config;
use log::*;
use rayon::prelude::*;
use std::{
    collections::{HashSet, VecDeque},
    net::SocketAddr,
    sync::{
        atomic::{AtomicBool, AtomicIsize, AtomicUsize, Ordering},
        Arc, Mutex, RwLock,
    },
    thread::{sleep, Builder, JoinHandle},
    time::{Duration, Instant},
};

use crate::bench::Result;
use crate::bench::SharedTransactions;
use solana_measure::measure::Measure;
use solana_metrics::{self, datapoint_info};
use solana_sdk::{
    client::Client,
    hash::Hash,
    message::Message,
    pubkey::Pubkey,
    signature::{Keypair, Signer},
    timing::{duration_as_ms, duration_as_s, duration_as_us, timestamp},
    transaction::Transaction,
};

pub const MAX_SPENDS_PER_TX: u64 = 4;
use solana_evm_loader_program::scope::evm::FromKey;
use solana_evm_loader_program::scope::evm::U256;
use solana_evm_loader_program::scope::*;

pub const BENCH_SEED: &str = "authority";

#[derive(Clone, Debug)]
pub struct Peer(pub std::sync::Arc<Keypair>, pub evm::SecretKey, pub u64);

pub fn generate_evm_key(seed_keypair: &Keypair) -> evm::SecretKey {
    use solana_evm_loader_program::scope::evm::rand::SeedableRng;

    let mut seed = [0u8; 32];
    seed.copy_from_slice(&seed_keypair.to_bytes()[..32]);
    let mut rng = rand_isaac::IsaacRng::from_seed(seed);

    evm::SecretKey::new(&mut rng)
}

pub fn generate_and_fund_evm_keypairs<T: 'static + Client + Send + Sync>(
    client: Arc<T>,
    _faucet_addr: Option<SocketAddr>,
    sources: Vec<Keypair>,
    lamports_per_account: u64,
) -> Result<Vec<(Keypair, evm::SecretKey)>> {
    info!("Creating {} keypairs...", sources.len());
    let keypairs: Vec<_> = sources
        .into_iter()
        .map(|key| {
            let evm_key = generate_evm_key(&key);
            (key, evm_key)
        })
        .collect();
    info!("Get lamports...");

    // Sample the first keypair, to prevent lamport loss on repeated solana-bench-tps executions
    let first_key = keypairs[0].1;
    let first_keypair_balance = client
        .get_evm_balance(&first_key.to_address())
        .unwrap_or_default();

    // Sample the last keypair, to check if funding was already completed
    let last_key = keypairs[keypairs.len() - 1].1;
    let last_keypair_balance = client
        .get_evm_balance(&last_key.to_address())
        .unwrap_or_default();

    let enough_gweis = evm::lamports_to_gwei(lamports_per_account);
    if first_keypair_balance < enough_gweis || last_keypair_balance < enough_gweis {
        info!("Funding evm keys.",);
        fund_evm_keys(client, &keypairs, lamports_per_account);
    }

    Ok(keypairs)
}

fn verify_funding_transfer<T: Client>(
    client: &Arc<T>,
    evm_key: evm::Address,
    _tx: &Transaction,
    amount: u64,
) -> bool {
    match client.get_evm_balance(&evm_key) {
        Ok(balance) => return balance >= U256::from(amount),
        Err(err) => error!("failed to get balance {:?}", err),
    }
    false
}

trait FundingTransactions<'a> {
    fn fund<T: 'static + Client + Send + Sync>(
        &mut self,
        client: &Arc<T>,
        to_fund: &'a [(Keypair, evm::SecretKey)],
        to_lamports: u64,
    );
    fn make(&mut self, to_fund: &'a [(Keypair, evm::SecretKey)], to_lamports: u64);
    fn sign(&mut self, blockhash: Hash);
    fn send<T: Client>(&self, client: &Arc<T>);
    fn verify<T: 'static + Client + Send + Sync>(&mut self, client: &Arc<T>, to_lamports: u64);
}

impl<'a> FundingTransactions<'a> for Vec<(&'a Keypair, &'a evm::SecretKey, Transaction)> {
    fn fund<T: 'static + Client + Send + Sync>(
        &mut self,
        client: &Arc<T>,
        to_fund: &'a [(Keypair, evm::SecretKey)],
        to_lamports: u64,
    ) {
        self.make(to_fund, to_lamports);

        let mut tries = 0;
        while !self.is_empty() {
            info!(
                "{} {} each to {} accounts in {} txs",
                if tries == 0 {
                    "transferring"
                } else {
                    " retrying"
                },
                to_lamports,
                self.len() * MAX_SPENDS_PER_TX as usize,
                self.len(),
            );

            let (blockhash, _fee_calculator) = crate::bench::get_recent_blockhash(client.as_ref());

            // re-sign retained to_fund_txes with updated blockhash
            self.sign(blockhash);
            self.send(client);

            // Sleep a few slots to allow transactions to process
            if cfg!(not(test)) {
                sleep(Duration::from_secs(1));
            }

            self.verify(client, to_lamports);

            // retry anything that seems to have dropped through cracks
            //  again since these txs are all or nothing, they're fine to
            //  retry
            tries += 1;
        }
        info!("transferred");
    }

    fn make(&mut self, to_fund: &'a [(Keypair, evm::SecretKey)], to_lamports: u64) {
        let mut make_txs = Measure::start("make_txs");
        let to_fund_txs: Vec<(&Keypair, &evm::SecretKey, Transaction)> = to_fund
            .par_iter()
            .map(|(k, evm)| {
                let instructions = solana_evm_loader_program::transfer_native_to_evm_ixs(
                    k.pubkey(),
                    to_lamports,
                    evm.to_address(),
                );
                let message = Message::new(&instructions, Some(&k.pubkey()));
                (k, evm, Transaction::new_unsigned(message))
            })
            .collect();
        make_txs.stop();
        debug!(
            "make {} unsigned txs: {}us",
            to_fund_txs.len(),
            make_txs.as_us()
        );
        self.extend(to_fund_txs);
    }

    fn sign(&mut self, blockhash: Hash) {
        let mut sign_txs = Measure::start("sign_txs");
        self.par_iter_mut().for_each(|(k, _, tx)| {
            tx.sign(&[*k], blockhash);
        });
        sign_txs.stop();
        debug!("sign {} txs: {}us", self.len(), sign_txs.as_us());
    }

    fn send<T: Client>(&self, client: &Arc<T>) {
        let mut send_txs = Measure::start("send_txs");
        self.iter().for_each(|(_, _, tx)| {
            client.async_send_transaction(tx.clone()).expect("transfer");
        });
        send_txs.stop();
        debug!("send {} txs: {}us", self.len(), send_txs.as_us());
    }

    fn verify<T: 'static + Client + Send + Sync>(&mut self, client: &Arc<T>, to_lamports: u64) {
        let starting_txs = self.len();
        let verified_txs = Arc::new(AtomicUsize::new(0));
        let too_many_failures = Arc::new(AtomicBool::new(false));
        let loops = if starting_txs < 1000 { 3 } else { 1 };
        // Only loop multiple times for small (quick) transaction batches
        let time = Arc::new(Mutex::new(Instant::now()));
        for _ in 0..loops {
            let time = time.clone();
            let failed_verify = Arc::new(AtomicUsize::new(0));
            let client = client.clone();
            let verified_txs = &verified_txs;
            let failed_verify = &failed_verify;
            let too_many_failures = &too_many_failures;
            let verified_set: HashSet<Pubkey> = self
                .par_iter()
                .filter_map(move |(k, evm_secret, tx)| {
                    if too_many_failures.load(Ordering::Relaxed) {
                        return None;
                    }

                    let verified = if verify_funding_transfer(
                        &client,
                        evm_secret.to_address(),
                        tx,
                        to_lamports,
                    ) {
                        verified_txs.fetch_add(1, Ordering::Relaxed);
                        Some(k.pubkey())
                    } else {
                        failed_verify.fetch_add(1, Ordering::Relaxed);
                        None
                    };

                    let verified_txs = verified_txs.load(Ordering::Relaxed);
                    let failed_verify = failed_verify.load(Ordering::Relaxed);
                    let remaining_count = starting_txs.saturating_sub(verified_txs + failed_verify);
                    if failed_verify > 100 && failed_verify > verified_txs {
                        too_many_failures.store(true, Ordering::Relaxed);
                        warn!(
                            "Too many failed transfers... {} remaining, {} verified, {} failures",
                            remaining_count, verified_txs, failed_verify
                        );
                    }
                    if remaining_count > 0 {
                        let mut time_l = time.lock().unwrap();
                        if time_l.elapsed().as_secs() > 2 {
                            info!(
                                "Verifying transfers... {} remaining, {} verified, {} failures",
                                remaining_count, verified_txs, failed_verify
                            );
                            *time_l = Instant::now();
                        }
                    }

                    verified
                })
                .collect();

            self.retain(|(k, _, _)| !verified_set.contains(&k.pubkey()));
            if self.is_empty() {
                break;
            }
            info!("Looping verifications");

            let verified_txs = verified_txs.load(Ordering::Relaxed);
            let failed_verify = failed_verify.load(Ordering::Relaxed);
            let remaining_count = starting_txs.saturating_sub(verified_txs + failed_verify);
            info!(
                "Verifying transfers... {} remaining, {} verified, {} failures",
                remaining_count, verified_txs, failed_verify
            );
            sleep(Duration::from_millis(100));
        }
    }
}

pub fn fund_evm_keys<T: 'static + Client + Send + Sync>(
    client: Arc<T>,
    keys: &[(Keypair, evm::SecretKey)],
    lamports_per_account: u64,
) {
    // try to transfer a "few" at a time with recent blockhash
    //  assume 4MB network buffers, and 512 byte packets
    const FUND_CHUNK_LEN: usize = 4 * 1024 * 1024 / 512;

    keys.chunks(FUND_CHUNK_LEN).for_each(|chunk| {
        Vec::<(&Keypair, _, Transaction)>::with_capacity(chunk.len()).fund(
            &client,
            chunk,
            lamports_per_account,
        );
    });

    info!("evm funded: {}", keys.len(),);
}

fn generate_system_txs(
    source: &mut [Peer],
    dest: &mut VecDeque<Peer>,
    reclaim: bool,
    blockhash: &Hash,
    chain_id: Option<u64>,
) -> Vec<(Transaction, u64)> {
    let mut pairs: Vec<_> = if !reclaim {
        source.iter_mut().zip(dest.iter_mut()).collect()
    } else {
        dest.iter_mut().zip(source.iter_mut()).collect()
    };

    pairs
        .par_iter_mut()
        .map(|(from, to)| {
            let tx_address = to.1.to_address();

            let tx_call = evm::UnsignedTransaction {
                nonce: from.2.into(),
                gas_price: 0.into(),
                gas_limit: 300000.into(),
                action: evm::TransactionAction::Call(tx_address),
                value: 1.into(),
                input: vec![],
            };

            let tx_call = tx_call.sign(&from.1, chain_id);

            from.2 += 1;
            let ix = solana_evm_loader_program::send_raw_tx(from.0.pubkey(), tx_call, None);

            let message = Message::new(&[ix], Some(&from.0.pubkey()));

            (
                Transaction::new(&[&*from.0], message, *blockhash),
                timestamp(),
            )
        })
        .collect()
}

fn generate_txs(
    shared_txs: &SharedTransactions,
    blockhash: &Arc<RwLock<Hash>>,
    source: &mut [Peer],
    dest: &mut VecDeque<Peer>,
    threads: usize,
    reclaim: bool,
    chain_id: Option<u64>,
) {
    let blockhash = *blockhash.read().unwrap();
    let tx_count = source.len();
    info!(
        "Signing transactions... {} (reclaim={}, blockhash={})",
        tx_count, reclaim, &blockhash
    );
    let signing_start = Instant::now();

    let transactions = generate_system_txs(source, dest, reclaim, &blockhash, chain_id);

    let duration = signing_start.elapsed();
    let ns = duration.as_secs() * 1_000_000_000 + u64::from(duration.subsec_nanos());
    let bsps = (tx_count) as f64 / ns as f64;
    let nsps = ns as f64 / (tx_count) as f64;
    info!(
        "Done. {:.2} thousand signatures per second, {:.2} us per signature, {} ms total time, {}",
        bsps * 1_000_000_f64,
        nsps / 1_000_f64,
        duration_as_ms(&duration),
        blockhash,
    );
    datapoint_info!(
        "bench-tps-generate_txs",
        ("duration", duration_as_us(&duration), i64)
    );

    let sz = transactions.len() / threads;
    let chunks: Vec<_> = transactions.chunks(sz).collect();
    {
        let mut shared_txs_wl = shared_txs.write().unwrap();
        for chunk in chunks {
            shared_txs_wl.push_back(chunk.to_vec());
        }
    }
}

pub fn do_bench_tps<T>(client: Arc<T>, config: Config, gen_keypairs: Vec<Peer>) -> u64
where
    T: 'static + Client + Send + Sync,
{
    let Config {
        id,
        threads,
        thread_batch_sleep_ms,
        duration,
        tx_count,
        sustained,
        target_slots_per_epoch,
        chain_id,
        ..
    } = config;

    let mut source_keypair_chunks: Vec<Vec<_>> = Vec::new();
    let mut dest_keypair_chunks: Vec<VecDeque<_>> = Vec::new();
    assert!(gen_keypairs.len() >= 2 * tx_count);
    for chunk in gen_keypairs.chunks_exact(2 * tx_count) {
        source_keypair_chunks.push(chunk[..tx_count].to_vec());
        dest_keypair_chunks.push(chunk[tx_count..].iter().cloned().collect());
    }

    let first_tx_count = loop {
        match client.get_transaction_count() {
            Ok(count) => break count,
            Err(err) => {
                info!("Couldn't get transaction count: {:?}", err);
                sleep(Duration::from_secs(1));
            }
        }
    };
    info!("Initial transaction count {}", first_tx_count);

    let exit_signal = Arc::new(AtomicBool::new(false));

    // Setup a thread per validator to sample every period
    // collect the max transaction rate and total tx count seen
    let maxes = Arc::new(RwLock::new(Vec::new()));
    let sample_period = 1; // in seconds
    let sample_thread =
        crate::bench::create_sampler_thread(&client, &exit_signal, sample_period, &maxes);

    let shared_txs: SharedTransactions = Arc::new(RwLock::new(VecDeque::new()));

    let recent_blockhash = Arc::new(RwLock::new(
        crate::bench::get_recent_blockhash(client.as_ref()).0,
    ));
    let shared_tx_active_thread_count = Arc::new(AtomicIsize::new(0));
    let total_tx_sent_count = Arc::new(AtomicUsize::new(0));

    let blockhash_thread = {
        let exit_signal = exit_signal.clone();
        let recent_blockhash = recent_blockhash.clone();
        let client = client.clone();
        let id = id.pubkey();
        Builder::new()
            .name("solana-blockhash-poller".to_string())
            .spawn(move || {
                crate::bench::poll_blockhash(&exit_signal, &recent_blockhash, &client, &id);
            })
            .unwrap()
    };

    let s_threads = create_sender_threads(
        &client,
        &shared_txs,
        thread_batch_sleep_ms,
        &total_tx_sent_count,
        threads,
        &exit_signal,
        &shared_tx_active_thread_count,
    );

    crate::bench::wait_for_target_slots_per_epoch(target_slots_per_epoch, &client);

    let start = Instant::now();

    generate_chunked_transfers(
        recent_blockhash,
        &shared_txs,
        shared_tx_active_thread_count,
        source_keypair_chunks,
        dest_keypair_chunks,
        threads,
        duration,
        sustained,
        chain_id,
    );

    // Stop the sampling threads so it will collect the stats
    exit_signal.store(true, Ordering::Relaxed);

    info!("Waiting for sampler threads...");
    if let Err(err) = sample_thread.join() {
        info!("  join() failed with: {:?}", err);
    }

    // join the tx send threads
    info!("Waiting for transmit threads...");
    for t in s_threads {
        if let Err(err) = t.join() {
            info!("  join() failed with: {:?}", err);
        }
    }

    info!("Waiting for blockhash thread...");
    if let Err(err) = blockhash_thread.join() {
        info!("  join() failed with: {:?}", err);
    }

    let balance = client.get_balance(&id.pubkey()).unwrap_or(0);
    crate::bench::metrics_submit_lamport_balance(balance);

    crate::bench::compute_and_report_stats(
        &maxes,
        sample_period,
        &start.elapsed(),
        total_tx_sent_count.load(Ordering::Relaxed),
    );

    let r_maxes = maxes.read().unwrap();
    r_maxes.first().unwrap().1.txs
}

fn generate_chunked_transfers(
    recent_blockhash: Arc<RwLock<Hash>>,
    shared_txs: &SharedTransactions,
    shared_tx_active_thread_count: Arc<AtomicIsize>,
    mut source_keypair_chunks: Vec<Vec<Peer>>,
    mut dest_keypair_chunks: Vec<VecDeque<Peer>>,
    threads: usize,
    duration: Duration,
    sustained: bool,
    chain_id: Option<u64>,
) {
    // generate and send transactions for the specified duration
    let start = Instant::now();
    let keypair_chunks = source_keypair_chunks.len();
    let mut reclaim_lamports_back_to_source_account = false;
    let mut chunk_index = 0;
    while start.elapsed() < duration {
        generate_txs(
            shared_txs,
            &recent_blockhash,
            &mut source_keypair_chunks[chunk_index],
            &mut dest_keypair_chunks[chunk_index],
            threads,
            reclaim_lamports_back_to_source_account,
            chain_id,
        );

        // In sustained mode, overlap the transfers with generation. This has higher average
        // performance but lower peak performance in tested environments.
        if sustained {
            // Ensure that we don't generate more transactions than we can handle.
            while shared_txs.read().unwrap().len() > 2 * threads {
                sleep(Duration::from_millis(1));
            }
        } else {
            while !shared_txs.read().unwrap().is_empty()
                || shared_tx_active_thread_count.load(Ordering::Relaxed) > 0
            {
                sleep(Duration::from_millis(1));
            }
        }

        // Rotate destination keypairs so that the next round of transactions will have different
        // transaction signatures even when blockhash is reused.
        dest_keypair_chunks[chunk_index].rotate_left(1);

        // Move on to next chunk
        chunk_index = (chunk_index + 1) % keypair_chunks;

        // Switch directions after transfering for each "chunk"
        if chunk_index == 0 {
            reclaim_lamports_back_to_source_account = !reclaim_lamports_back_to_source_account;
        }
    }
}

fn do_tx_transfers<T: Client>(
    exit_signal: &Arc<AtomicBool>,
    shared_txs: &SharedTransactions,
    shared_tx_thread_count: &Arc<AtomicIsize>,
    total_tx_sent_count: &Arc<AtomicUsize>,
    thread_batch_sleep_ms: usize,
    client: &Arc<T>,
) {
    loop {
        if thread_batch_sleep_ms > 0 {
            sleep(Duration::from_millis(thread_batch_sleep_ms as u64));
        }
        let txs = {
            let mut shared_txs_wl = shared_txs.write().expect("write lock in do_tx_transfers");
            shared_txs_wl.pop_front()
        };
        if let Some(txs0) = txs {
            shared_tx_thread_count.fetch_add(1, Ordering::Relaxed);
            info!(
                "Transferring 1 unit {} times... to {}",
                txs0.len(),
                client.as_ref().tpu_addr(),
            );
            let tx_len = txs0.len();
            let transfer_start = Instant::now();
            let mut old_transactions = false;
            for tx in txs0 {
                let now = timestamp();
                // Transactions that are too old will be rejected by the cluster Don't bother
                // sending them.
                if now > tx.1 && now - tx.1 > 1000 * crate::bench::MAX_TX_QUEUE_AGE {
                    old_transactions = true;
                    continue;
                }
                client
                    .async_send_transaction(tx.0)
                    .expect("async_send_transaction in do_tx_transfers");
            }
            if old_transactions {
                let mut shared_txs_wl = shared_txs.write().expect("write lock in do_tx_transfers");
                shared_txs_wl.clear();
            }
            shared_tx_thread_count.fetch_add(-1, Ordering::Relaxed);
            total_tx_sent_count.fetch_add(tx_len, Ordering::Relaxed);
            info!(
                "Tx send done. {} ms {} tps",
                duration_as_ms(&transfer_start.elapsed()),
                tx_len as f32 / duration_as_s(&transfer_start.elapsed()),
            );
            datapoint_info!(
                "bench-tps-do_tx_transfers",
                ("duration", duration_as_us(&transfer_start.elapsed()), i64),
                ("count", tx_len, i64)
            );
        }
        if exit_signal.load(Ordering::Relaxed) {
            break;
        }
        println!("Sleeping 1 sec");
        sleep(Duration::from_secs(1));
    }
}

fn create_sender_threads<T>(
    client: &Arc<T>,
    shared_txs: &SharedTransactions,
    thread_batch_sleep_ms: usize,
    total_tx_sent_count: &Arc<AtomicUsize>,
    threads: usize,
    exit_signal: &Arc<AtomicBool>,
    shared_tx_active_thread_count: &Arc<AtomicIsize>,
) -> Vec<JoinHandle<()>>
where
    T: 'static + Client + Send + Sync,
{
    (0..threads)
        .map(|_| {
            let exit_signal = exit_signal.clone();
            let shared_txs = shared_txs.clone();
            let shared_tx_active_thread_count = shared_tx_active_thread_count.clone();
            let total_tx_sent_count = total_tx_sent_count.clone();
            let client = client.clone();
            Builder::new()
                .name("solana-client-sender".to_string())
                .spawn(move || {
                    do_tx_transfers(
                        &exit_signal,
                        &shared_txs,
                        &shared_tx_active_thread_count,
                        &total_tx_sent_count,
                        thread_batch_sleep_ms,
                        &client,
                    );
                })
                .unwrap()
        })
        .collect()
}
