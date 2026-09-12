use solana_client::rpc_config::RpcSendTransactionConfig;
use solana_evm_loader_program::{free_ownership, transfer_native_to_evm_ixs};
use solana_sdk::{commitment_config::CommitmentLevel, fee_calculator::FeeRateGovernor};

use {
    bincode::serialize,
    crossbeam_channel::unbounded,
    evm_rpc::{BlockId, Hex, RPCLogFilter, RPCTransaction},
    evm_state::TransactionInReceipt,
    futures_util::StreamExt,
    log::*,
    primitive_types::{H256, U256},
    reqwest::{self, header::CONTENT_TYPE},
    serde_json::{json, Value},
    solana_account_decoder::UiAccount,
    solana_client::{
        client_error::{ClientErrorKind, Result as ClientResult},
        connection_cache::{ConnectionCache, DEFAULT_TPU_CONNECTION_POOL_SIZE},
        nonblocking::pubsub_client::PubsubClient,
        rpc_client::RpcClient,
        rpc_config::{RpcAccountInfoConfig, RpcSignatureSubscribeConfig},
        rpc_request::RpcError,
        rpc_response::{Response as RpcResponse, RpcSignatureResult, SlotUpdate},
        tpu_client::{TpuClient, TpuClientConfig},
    },
    solana_evm_loader_program::{instructions::FeePayerType, send_raw_tx},
    solana_rpc::rpc::JsonRpcConfig,
    solana_sdk::{
        commitment_config::CommitmentConfig,
        hash::Hash,
        pubkey::Pubkey,
        rent::Rent,
        signature::{Keypair, Signature, Signer},
        system_instruction::assign,
        system_transaction,
        transaction::Transaction,
    },
    solana_streamer::socket::SocketAddrSpace,
    solana_test_validator::{TestValidator, TestValidatorGenesis},
    solana_transaction_status::TransactionStatus,
    std::{
        collections::HashSet,
        net::UdpSocket,
        str::FromStr,
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        },
        thread::sleep,
        time::{Duration, Instant},
    },
    tokio::runtime::Runtime,
};

macro_rules! json_req {
    ($method: expr, $params: expr) => {{
        json!({
           "jsonrpc": "2.0",
           "id": 1,
           "method": $method,
           "params": $params,
        })
    }}
}

fn post_rpc(request: Value, rpc_url: &str) -> Value {
    let client = reqwest::blocking::Client::new();
    let response = client
        .post(rpc_url)
        .header(CONTENT_TYPE, "application/json")
        .body(request.to_string())
        .send()
        .unwrap();
    serde_json::from_str(&response.text().unwrap()).unwrap()
}

fn get_blockhash(rpc_url: &str) -> Hash {
    let req = json_req!(
        "getRecentBlockhash",
        json!([json!(CommitmentConfig {
            commitment: CommitmentLevel::Finalized
        })])
    );
    let json = post_rpc(req, &rpc_url);
    json["result"]["value"]["blockhash"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap()
}

fn wait_finalization(rpc_url: &str, signatures: &[&Value]) -> bool {
    let request = json_req!("getSignatureStatuses", [signatures]);

    for _ in 0..solana_sdk::clock::DEFAULT_TICKS_PER_SLOT {
        let json = post_rpc(request.clone(), &rpc_url);
        let values = json["result"]["value"].as_array().unwrap();
        if values.iter().all(|v| !v.is_null()) {
            if values.iter().all(|v| {
                assert_eq!(v["err"], Value::Null);
                v["confirmationStatus"].as_str().unwrap() == "finalized"
            }) {
                warn!("All signatures confirmed: {:?}", dbg!(values));
                return true;
            }
        }

        sleep(Duration::from_secs(1));
    }
    false
}

#[test]
fn test_batch_request() {
    solana_logger::setup();

    let alice = Keypair::new();
    let test_validator = TestValidatorGenesis::default()
        .rpc_config(JsonRpcConfig {
            max_batch_duration: Some(Duration::from_secs(0)),
            ..JsonRpcConfig::default_for_test()
        })
        .start_with_mint_address(alice.pubkey(), SocketAddrSpace::Unspecified)
        .expect("validator start failed");
    let rpc_url = test_validator.rpc_url();

    warn!("Sending batch...");
    let batch: Vec<_> = (1..10)
        .map(|id| {
            json!({
               "jsonrpc": "2.0",
               "id": id,
               "method": "getRecentBlockhash",
               "params": json!([]),
            })
        })
        .collect();
    let res: Value = post_rpc(json!(batch), &rpc_url);
    let results = res.as_array().unwrap();
    let (success, failures) = results.split_first().unwrap();
    assert!(success["result"].is_object());
    for failure in failures {
        assert!(failure["error"].is_object());
    }
}

#[test]
fn test_rpc_send_tx() {
    solana_logger::setup();

    let alice = Keypair::new();
    let test_validator =
        TestValidator::with_no_fees(alice.pubkey(), None, SocketAddrSpace::Unspecified);
    let rpc_url = test_validator.rpc_url();

    let bob_pubkey = solana_sdk::pubkey::new_rand();

    let req = json_req!("getRecentBlockhash", json!([]));
    let json = post_rpc(req, &rpc_url);

    let blockhash: Hash = json["result"]["value"]["blockhash"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();

    info!("blockhash: {:?}", blockhash);
    let tx = system_transaction::transfer(
        &alice,
        &bob_pubkey,
        Rent::default().minimum_balance(0),
        blockhash,
    );
    let serialized_encoded_tx = bs58::encode(serialize(&tx).unwrap()).into_string();

    let req = json_req!("sendTransaction", json!([serialized_encoded_tx]));
    let json: Value = post_rpc(req, &rpc_url);

    let signature = &json["result"];

    let mut confirmed_tx = false;

    let request = json_req!("getSignatureStatuses", [[signature]]);

    for _ in 0..solana_sdk::clock::DEFAULT_TICKS_PER_SLOT {
        let json = post_rpc(request.clone(), &rpc_url);

        let result: Option<TransactionStatus> =
            serde_json::from_value(json["result"]["value"][0].clone()).unwrap();
        if let Some(result) = result.as_ref() {
            if result.err.is_none() {
                confirmed_tx = true;
                break;
            }
        }

        sleep(Duration::from_millis(500));
    }

    assert!(confirmed_tx);

    use {
        solana_account_decoder::UiAccountEncoding, solana_client::rpc_config::RpcAccountInfoConfig,
    };
    let config = RpcAccountInfoConfig {
        encoding: Some(UiAccountEncoding::Base64),
        commitment: None,
        data_slice: None,
        min_context_slot: None,
    };
    let req = json_req!(
        "getAccountInfo",
        json!([bs58::encode(bob_pubkey).into_string(), config])
    );
    let json: Value = post_rpc(req, &rpc_url);
    info!("{:?}", json["result"]["value"]);
}

#[test]
fn test_rpc_send_transaction_with_native_fee_and_zero_gas_price() {
    solana_logger::setup_with_default("warn");

    let evm_secret_key = evm_state::SecretKey::from_slice(&[1; 32]).unwrap();
    let evm_address = evm_state::addr_from_public_key(&evm_state::PublicKey::from_secret_key(
        evm_state::SECP256K1,
        &evm_secret_key,
    ));

    let alice = Keypair::new();
    let test_validator = TestValidatorGenesis::default()
        .fee_rate_governor(FeeRateGovernor::new(0, 0))
        .rent(Rent {
            lamports_per_byte_year: 1,
            exemption_threshold: 1.0,
            ..Rent::default()
        })
        .enable_evm_state_archive()
        .rpc_config(JsonRpcConfig {
            enable_rpc_transaction_history: true,
            ..JsonRpcConfig::default_for_test()
        })
        .start_with_mint_address(alice.pubkey(), SocketAddrSpace::Unspecified)
        .expect("validator start failed");
    let rpc_url = test_validator.rpc_url();

    let req = json_req!("eth_chainId", json!([]));
    let json = post_rpc(req, &rpc_url);
    let chain_id = Hex::from_hex(json["result"].as_str().unwrap()).unwrap().0;

    let blockhash = dbg!(get_blockhash(&rpc_url));
    let ixs = transfer_native_to_evm_ixs(alice.pubkey(), 1000000, evm_address);
    let tx = Transaction::new_signed_with_payer(&ixs, None, &[&alice], blockhash);
    let serialized_encoded_tx = bs58::encode(serialize(&tx).unwrap()).into_string();

    let req = json_req!("sendTransaction", json!([serialized_encoded_tx]));
    let json: Value = post_rpc(req, &rpc_url);
    wait_finalization(&rpc_url, &[&json["result"]]);

    let evm_tx = evm_state::UnsignedTransaction {
        nonce: 0.into(),
        gas_price: 0.into(),
        gas_limit: 300000.into(),
        action: evm_state::TransactionAction::Call(evm_address),
        value: 0.into(),
        input: vec![],
    }
    .sign(&evm_secret_key, Some(chain_id));
    let tx_hash = evm_tx.tx_id_hash();

    let blockhash = get_blockhash(&rpc_url);
    let ixs = vec![
        assign(&alice.pubkey(), &solana_sdk::evm_loader::ID),
        send_raw_tx(alice.pubkey(), evm_tx, None, FeePayerType::Native),
        free_ownership(alice.pubkey()),
    ];
    let tx = Transaction::new_signed_with_payer(&ixs, None, &[&alice], blockhash);
    let serialized_encoded_tx = bs58::encode(serialize(&tx).unwrap()).into_string();
    let req = json_req!("sendTransaction", json!([serialized_encoded_tx]));
    let json = dbg!(post_rpc(req, &rpc_url));
    wait_finalization(&rpc_url, &[&json["result"]]);

    let request = json_req!("trace_replayTransaction", json!([tx_hash, ["trace"]]));
    let json = post_rpc(request.clone(), &rpc_url);
    warn!("trace_replayTransaction: {}", dbg!(json.clone()));
    assert!(!json["result"].is_null());

    let evm_tx = evm_state::UnsignedTransaction {
        nonce: 1.into(),
        gas_price: 0.into(),
        gas_limit: 300000.into(),
        action: evm_state::TransactionAction::Call(evm_address),
        value: 0.into(),
        input: vec![],
    }
    .sign(&evm_secret_key, Some(chain_id));
    let blockhash = get_blockhash(&rpc_url);
    let ixs = vec![
        assign(&alice.pubkey(), &solana_sdk::evm_loader::ID),
        send_raw_tx(alice.pubkey(), evm_tx, None, FeePayerType::Evm),
        free_ownership(alice.pubkey()),
    ];
    let tx = Transaction::new_signed_with_payer(&ixs, None, &[&alice], blockhash);
    let serialized_encoded_tx = bs58::encode(serialize(&tx).unwrap()).into_string();
    let req = json_req!("sendTransaction", json!([serialized_encoded_tx]));
    let json = dbg!(post_rpc(req, &rpc_url));
    // Transaction with zero gas price and Evm fee will fail
    assert!(!json["error"].is_null());
    assert_eq!(
        json["error"]["message"].as_str().unwrap(),
        "Transaction simulation failed: Error processing Instruction 1: custom program error: 0x3"
    );
}

#[test]
fn test_rpc_replay_transaction() {
    // let filter = "warn,solana_runtime::message_processor=debug,evm=debug";
    solana_logger::setup_with_default("warn");

    let evm_secret_key = evm_state::SecretKey::from_slice(&[1; 32]).unwrap();
    let evm_address = evm_state::addr_from_public_key(&evm_state::PublicKey::from_secret_key(
        evm_state::SECP256K1,
        &evm_secret_key,
    ));

    let alice = Keypair::new();
    let test_validator = TestValidatorGenesis::default()
        .fee_rate_governor(FeeRateGovernor::new(0, 0))
        .rent(Rent {
            lamports_per_byte_year: 1,
            exemption_threshold: 1.0,
            ..Rent::default()
        })
        .enable_evm_state_archive()
        .rpc_config(JsonRpcConfig {
            enable_rpc_transaction_history: true,
            ..JsonRpcConfig::default_for_test()
        })
        .start_with_mint_address(alice.pubkey(), SocketAddrSpace::Unspecified)
        .expect("validator start failed");
    let rpc_url = test_validator.rpc_url();

    let req = json_req!("eth_chainId", json!([]));
    let json = post_rpc(req, &rpc_url);
    let chain_id = Hex::from_hex(json["result"].as_str().unwrap()).unwrap().0;

    let blockhash = dbg!(get_blockhash(&rpc_url));
    let ixs = transfer_native_to_evm_ixs(alice.pubkey(), 1000000, evm_address);
    let tx = Transaction::new_signed_with_payer(&ixs, None, &[&alice], blockhash);
    let serialized_encoded_tx = bs58::encode(serialize(&tx).unwrap()).into_string();

    let req = json_req!("sendTransaction", json!([serialized_encoded_tx]));
    let json: Value = post_rpc(req, &rpc_url);
    wait_finalization(&rpc_url, &[&json["result"]]);

    let evm_txs: Vec<_> = (0u64..3)
        .map(|nonce| {
            evm_state::UnsignedTransaction {
                nonce: nonce.into(),
                gas_price: 2000000000.into(),
                gas_limit: 300000.into(),
                action: evm_state::TransactionAction::Call(evm_address),
                value: 0.into(),
                input: vec![],
            }
            .sign(&evm_secret_key, Some(chain_id))
        })
        .collect();
    let tx_hashes: Vec<_> = evm_txs.iter().map(|tx| tx.tx_id_hash()).collect();

    let blockhash = get_blockhash(&rpc_url);
    let ixs: Vec<_> = evm_txs
        .into_iter()
        .map(|evm_tx| send_raw_tx(alice.pubkey(), evm_tx, None, FeePayerType::Evm))
        .collect();
    let tx = Transaction::new_signed_with_payer(&ixs, None, &[&alice], blockhash);
    let serialized_encoded_tx = bs58::encode(serialize(&tx).unwrap()).into_string();
    let req = json_req!("sendTransaction", json!([serialized_encoded_tx]));
    let json = dbg!(post_rpc(req, &rpc_url));
    wait_finalization(&rpc_url, &[&json["result"]]);

    for tx_hash in tx_hashes {
        let request = json_req!("trace_replayTransaction", json!([tx_hash, ["trace"]]));
        let json = post_rpc(request.clone(), &rpc_url);
        warn!("trace_replayTransaction: {}", dbg!(json.clone()));
        assert!(!json["result"].is_null());
    }
}

#[test]
fn test_rpc_block_transaction() {
    solana_logger::setup_with_default("warn");

    let evm_secret_key = evm_state::SecretKey::from_slice(&[1; 32]).unwrap();
    let evm_address = evm_state::addr_from_public_key(&evm_state::PublicKey::from_secret_key(
        evm_state::SECP256K1,
        &evm_secret_key,
    ));

    let alice = Keypair::new();
    let test_validator = TestValidatorGenesis::default()
        .fee_rate_governor(FeeRateGovernor::new(0, 0))
        .rpc_config(JsonRpcConfig {
            enable_rpc_transaction_history: true,
            ..JsonRpcConfig::default_for_test()
        })
        .start_with_mint_address(alice.pubkey(), SocketAddrSpace::Unspecified)
        .expect("validator start failed");
    let rpc_url = test_validator.rpc_url();

    let req = json_req!("eth_chainId", json!([]));
    let json = post_rpc(req, &rpc_url);
    let chain_id = Hex::from_hex(json["result"].as_str().unwrap()).unwrap().0;

    let blockhash = dbg!(get_blockhash(&rpc_url));
    let ixs = transfer_native_to_evm_ixs(alice.pubkey(), 1000000, evm_address);
    let tx = Transaction::new_signed_with_payer(&ixs, None, &[&alice], blockhash);
    let serialized_encoded_tx = bs58::encode(serialize(&tx).unwrap()).into_string();

    let req = json_req!("sendTransaction", json!([serialized_encoded_tx]));
    let json: Value = post_rpc(req, &rpc_url);
    wait_finalization(&rpc_url, &[&json["result"]]);

    let evm_txs: Vec<_> = (0u64..3)
        .map(|nonce| {
            evm_state::UnsignedTransaction {
                nonce: nonce.into(),
                gas_price: 2000000000.into(),
                gas_limit: 300000.into(),
                action: evm_state::TransactionAction::Call(evm_address),
                value: 0.into(),
                input: vec![],
            }
            .sign(&evm_secret_key, Some(chain_id))
        })
        .collect();
    let _tx_hashes: Vec<_> = evm_txs.iter().map(|tx| tx.tx_id_hash()).collect();

    let blockhash = get_blockhash(&rpc_url);
    let ixs: Vec<_> = evm_txs
        .into_iter()
        .map(|evm_tx| send_raw_tx(alice.pubkey(), evm_tx, None, FeePayerType::Evm))
        .collect();
    let tx = Transaction::new_signed_with_payer(&ixs, None, &[&alice], blockhash);
    let serialized_encoded_tx = bs58::encode(serialize(&tx).unwrap()).into_string();
    let req = json_req!("sendTransaction", json!([serialized_encoded_tx]));
    let json = dbg!(post_rpc(req, &rpc_url));
    wait_finalization(&rpc_url, &[&json["result"]]);

    let request = json_req!("eth_getBlockTransactionCountByNumber", json!(["0x02"]));
    let json = post_rpc(request.clone(), &rpc_url);
    let num_tx: u64 = Hex::from_hex(json["result"].as_str().unwrap()).unwrap().0;
    assert_eq!(num_tx, 3u64);

    let request = json_req!("eth_getBlockByNumber", json!(["0x02", true]));
    let json = post_rpc(request.clone(), &rpc_url);
    let evm_blockhash: H256 = Hex::from_hex(json["result"]["hash"].as_str().unwrap())
        .unwrap()
        .0;
    let request = json_req!("eth_getBlockTransactionCountByHash", json!([evm_blockhash]));
    let json = post_rpc(request.clone(), &rpc_url);
    let num_tx: u64 = Hex::from_hex(json["result"].as_str().unwrap()).unwrap().0;
    assert_eq!(num_tx, 3u64);

    let request = json_req!(
        "eth_getTransactionByBlockHashAndIndex",
        json!([evm_blockhash, "0x02"])
    );
    let json = post_rpc(request.clone(), &rpc_url);
    assert_eq!(
        evm_address,
        Hex::from_hex(json["result"]["from"].as_str().unwrap())
            .unwrap()
            .0
    );
    assert_eq!(
        evm_address,
        Hex::from_hex(json["result"]["to"].as_str().unwrap())
            .unwrap()
            .0
    );

    let request = json_req!(
        "eth_getTransactionByBlockNumberAndIndex",
        json!(["0x02", "0x02"])
    );
    let json = post_rpc(request.clone(), &rpc_url);
    assert_eq!(
        evm_address,
        Hex::from_hex(json["result"]["from"].as_str().unwrap())
            .unwrap()
            .0
    );
    assert_eq!(
        evm_address,
        Hex::from_hex(json["result"]["to"].as_str().unwrap())
            .unwrap()
            .0
    );
}

#[test]
fn test_rpc_replay_transaction_timestamp() {
    solana_logger::setup_with_default("warn");

    let evm_secret_key = evm_state::SecretKey::from_slice(&[1; 32]).unwrap();
    let evm_address = evm_state::addr_from_public_key(&evm_state::PublicKey::from_secret_key(
        evm_state::SECP256K1,
        &evm_secret_key,
    ));

    let alice = Keypair::new();
    let test_validator = TestValidatorGenesis::default()
        .fee_rate_governor(FeeRateGovernor::new(0, 0))
        .rent(Rent {
            lamports_per_byte_year: 1,
            exemption_threshold: 1.0,
            ..Rent::default()
        })
        .enable_evm_state_archive()
        .rpc_config(JsonRpcConfig {
            enable_rpc_transaction_history: true,
            ..JsonRpcConfig::default_for_test()
        })
        .start_with_mint_address(alice.pubkey(), SocketAddrSpace::Unspecified)
        .expect("validator start failed");
    let rpc_url = test_validator.rpc_url();

    let req = json_req!("eth_chainId", json!([]));
    let json = post_rpc(req, &rpc_url);
    let chain_id = Hex::from_hex(json["result"].as_str().unwrap()).unwrap().0;

    let blockhash = dbg!(get_blockhash(&rpc_url));
    let ixs = transfer_native_to_evm_ixs(alice.pubkey(), 1000000, evm_address);
    let tx = Transaction::new_signed_with_payer(&ixs, None, &[&alice], blockhash);
    let serialized_encoded_tx = bs58::encode(serialize(&tx).unwrap()).into_string();

    let req = json_req!("sendTransaction", json!([serialized_encoded_tx]));
    let json: Value = post_rpc(req, &rpc_url);
    wait_finalization(&rpc_url, &[&json["result"]]);

    // Contract with empty method that will revert after 60 seconds since creation
    const TEST_CONTRACT: &str = "608060405234801561001057600080fd5b50426000819055506101ce806100276000396000f3fe608060405234801561001057600080fd5b506004361061002b5760003560e01c8063e0c6190d14610030575b600080fd5b61003861003a565b005b603c60005461004991906100e0565b421061008a576040517f08c379a0000000000000000000000000000000000000000000000000000000008152600401610081906100af565b60405180910390fd5b565b60006100996007836100cf565b91506100a48261016f565b602082019050919050565b600060208201905081810360008301526100c88161008c565b9050919050565b600082825260208201905092915050565b60006100eb82610136565b91506100f683610136565b9250827fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0382111561012b5761012a610140565b5b828201905092915050565b6000819050919050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052601160045260246000fd5b7f455850495245440000000000000000000000000000000000000000000000000060008201525056fea2646970667358221220ab2757ebc2b2a29957de6784b28b802df45baf56c759e3bcfcd4b01365438e5864736f6c63430008070033";
    let tx_create = evm_state::UnsignedTransaction {
        nonce: 0.into(),
        gas_price: 2000000000.into(),
        gas_limit: 300000.into(),
        action: evm_state::TransactionAction::Create,
        value: 0.into(),
        input: hex::decode(TEST_CONTRACT).unwrap(),
    }
    .sign(&evm_secret_key, Some(chain_id));
    let contract_address = tx_create.address().unwrap();
    let tx_call = evm_state::UnsignedTransaction {
        nonce: 1.into(),
        gas_price: 2000000000.into(),
        gas_limit: 300000.into(),
        action: evm_state::TransactionAction::Call(contract_address),
        value: 0.into(),
        input: hex::decode("e0c6190d").unwrap(),
    }
    .sign(&evm_secret_key, Some(chain_id));
    let tx_call_hash = tx_call.tx_id_hash();

    let blockhash = dbg!(get_blockhash(&rpc_url));
    let ixs = vec![send_raw_tx(
        alice.pubkey(),
        tx_create,
        None,
        FeePayerType::Evm,
    )];
    let tx = Transaction::new_signed_with_payer(&ixs, None, &[&alice], blockhash);
    let serialized_encoded_tx = bs58::encode(serialize(&tx).unwrap()).into_string();
    let req = json_req!("sendTransaction", json!([serialized_encoded_tx]));
    let json = dbg!(post_rpc(req, &rpc_url));
    wait_finalization(&rpc_url, &[&json["result"]]);

    let recent_blockhash = get_blockhash(&rpc_url);
    let ixs = vec![send_raw_tx(
        alice.pubkey(),
        tx_call,
        None,
        FeePayerType::Evm,
    )];
    let tx = Transaction::new_signed_with_payer(&ixs, None, &[&alice], recent_blockhash);
    let serialized_encoded_tx = bs58::encode(serialize(&tx).unwrap()).into_string();
    let req = json_req!("sendTransaction", json!([serialized_encoded_tx]));
    let json = dbg!(post_rpc(req, &rpc_url));
    wait_finalization(&rpc_url, &[&json["result"]]);

    let request = json_req!("trace_replayTransaction", json!([tx_call_hash, ["trace"]]));
    let json = post_rpc(request.clone(), &rpc_url);
    warn!("trace_replayTransaction: {}", dbg!(json.clone()));
    assert!(!json["result"].is_null());
    assert!(json["result"]["trace"]
        .as_array()
        .unwrap()
        .iter()
        .all(|v| { !v.as_object().unwrap().contains_key("error") }));
}

#[test]
fn test_rpc_replay_transaction_gas_used() {
    solana_logger::setup_with_default("warn");

    let evm_secret_key = evm_state::SecretKey::from_slice(&[1; 32]).unwrap();
    let evm_address = evm_state::addr_from_public_key(&evm_state::PublicKey::from_secret_key(
        evm_state::SECP256K1,
        &evm_secret_key,
    ));

    let alice = Keypair::new();
    let test_validator = TestValidatorGenesis::default()
        .fee_rate_governor(FeeRateGovernor::new(0, 0))
        .rent(Rent {
            lamports_per_byte_year: 1,
            exemption_threshold: 1.0,
            ..Rent::default()
        })
        .enable_evm_state_archive()
        .rpc_config(JsonRpcConfig {
            enable_rpc_transaction_history: true,
            ..JsonRpcConfig::default_for_test()
        })
        .start_with_mint_address(alice.pubkey(), SocketAddrSpace::Unspecified)
        .expect("validator start failed");
    let rpc_url = test_validator.rpc_url();

    let req = json_req!("eth_chainId", json!([]));
    let json = post_rpc(req, &rpc_url);
    let chain_id = Hex::from_hex(json["result"].as_str().unwrap()).unwrap().0;
    warn!("chain_id: {}", chain_id);

    let blockhash = dbg!(get_blockhash(&rpc_url));
    let ixs = transfer_native_to_evm_ixs(alice.pubkey(), 10000000, evm_address);
    let tx = Transaction::new_signed_with_payer(&ixs, None, &[&alice], blockhash);
    let serialized_encoded_tx = bs58::encode(serialize(&tx).unwrap()).into_string();

    let req = json_req!("sendTransaction", json!([serialized_encoded_tx]));
    let json: Value = post_rpc(req, &rpc_url);
    wait_finalization(&rpc_url, &[&json["result"]]);

    // Contract with empty method that will revert after 60 seconds since creation
    const TEST_CONTRACT: &str = "608060405234801561001057600080fd5b506101d0806100206000396000f3fe608060405234801561001057600080fd5b506004361061002b5760003560e01c8063c41b95d114610030575b600080fd5b61004a600480360381019061004591906100eb565b61004c565b005b81600052600060205260406000208181558260005260016020526040600020905081815582600052600260205260406000209050818155826000526003602052604060002090508181558260005260046020526040600020905081815582600052600560205260406000209050818155505050565b6000813590506100d08161016c565b92915050565b6000813590506100e581610183565b92915050565b6000806040838503121561010257610101610167565b5b6000610110858286016100c1565b9250506020610121858286016100d6565b9150509250929050565b60006101368261013d565b9050919050565b600073ffffffffffffffffffffffffffffffffffffffff82169050919050565b6000819050919050565b600080fd5b6101758161012b565b811461018057600080fd5b50565b61018c8161015d565b811461019757600080fd5b5056fea264697066735822122036bbd0224659aebd8570f0c915a7fb3e556fb74eb7fd5af4a2fde6020dfe6a2864736f6c63430008070033";
    let tx_create_1 = evm_state::UnsignedTransaction {
        nonce: 0.into(),
        gas_price: 2000000000.into(),
        gas_limit: 300000.into(),
        action: evm_state::TransactionAction::Create,
        value: 0.into(),
        input: hex::decode(TEST_CONTRACT).unwrap(),
    }
    .sign(&evm_secret_key, Some(chain_id));
    let tx_create_2 = evm_state::UnsignedTransaction {
        nonce: 1.into(),
        gas_price: 2000000000.into(),
        gas_limit: 300000.into(),
        action: evm_state::TransactionAction::Create,
        value: 0.into(),
        input: hex::decode(TEST_CONTRACT).unwrap(),
    }
    .sign(&evm_secret_key, Some(chain_id));
    let contract_address_1 = tx_create_1.address().unwrap();
    let contract_address_2 = tx_create_2.address().unwrap();

    info!(
        "Deploy contracts {}, {}",
        contract_address_1, contract_address_2
    );
    // deploy first contract
    let blockhash = dbg!(get_blockhash(&rpc_url));
    let ixs = vec![send_raw_tx(
        alice.pubkey(),
        tx_create_1,
        None,
        FeePayerType::Evm,
    )];
    let tx = Transaction::new_signed_with_payer(&ixs, None, &[&alice], blockhash);
    let serialized_encoded_tx = bs58::encode(serialize(&tx).unwrap()).into_string();
    let req = json_req!("sendTransaction", json!([serialized_encoded_tx]));
    let json = dbg!(post_rpc(req, &rpc_url));
    wait_finalization(&rpc_url, &[&json["result"]]);

    // deploy second contract
    let blockhash = dbg!(get_blockhash(&rpc_url));
    let ixs = vec![send_raw_tx(
        alice.pubkey(),
        tx_create_2,
        None,
        FeePayerType::Evm,
    )];
    let tx = Transaction::new_signed_with_payer(&ixs, None, &[&alice], blockhash);
    let serialized_encoded_tx = bs58::encode(serialize(&tx).unwrap()).into_string();
    let req = json_req!("sendTransaction", json!([serialized_encoded_tx]));
    let json = dbg!(post_rpc(req, &rpc_url));
    wait_finalization(&rpc_url, &[&json["result"]]);

    // the first two txs are setting up contract state
    // the last tx clears state of the first contract so we can get gas_used from receipt
    let tx_calls = vec![
        evm_state::UnsignedTransaction {
            nonce: 2.into(),
            gas_price: 2000000000.into(),
            gas_limit: 300000.into(),
            action: evm_state::TransactionAction::Call(contract_address_1),
            value: 0.into(),
            input: hex::decode("c41b95d1000000000000000000000000141a4802f84bb64c0320917672ef7d92658e964e0000000000000000000000000000000000000000000000000000000000000001").unwrap(),
        }
            .sign(&evm_secret_key, Some(chain_id)),
        evm_state::UnsignedTransaction {
            nonce: 3.into(),
            gas_price: 2000000000.into(),
            gas_limit: 300000.into(),
            action: evm_state::TransactionAction::Call(contract_address_2),
            value: 0.into(),
            input: hex::decode("c41b95d1000000000000000000000000141a4802f84bb64c0320917672ef7d92658e964e0000000000000000000000000000000000000000000000000000000000000001").unwrap(),
        }
            .sign(&evm_secret_key, Some(chain_id)),
        evm_state::UnsignedTransaction {
            nonce: 4.into(),
            gas_price: 2000000000.into(),
            gas_limit: 300000.into(),
            action: evm_state::TransactionAction::Call(contract_address_1),
            value: 0.into(),
            input: hex::decode("c41b95d1000000000000000000000000141a4802f84bb64c0320917672ef7d92658e964e0000000000000000000000000000000000000000000000000000000000000000").unwrap(),
        }
            .sign(&evm_secret_key, Some(chain_id)),
    ];
    let tx_call_hashes: Vec<_> = tx_calls.iter().map(|tx| tx.tx_id_hash()).collect();

    let recent_blockhash = get_blockhash(&rpc_url);
    let ixs: Vec<_> = tx_calls
        .into_iter()
        .map(|tx| send_raw_tx(alice.pubkey(), tx, None, FeePayerType::Evm))
        .collect();
    let tx = Transaction::new_signed_with_payer(&ixs, None, &[&alice], recent_blockhash);
    let serialized_encoded_tx = bs58::encode(serialize(&tx).unwrap()).into_string();
    let req = json_req!("sendTransaction", json!([serialized_encoded_tx]));
    let json = dbg!(post_rpc(req, &rpc_url));
    wait_finalization(&rpc_url, &[&json["result"]]);

    let request = json_req!("eth_getTransactionReceipt", json!([tx_call_hashes[2]]));
    let json = post_rpc(request.clone(), &rpc_url);
    let target_gas_limit: U256 = Hex::from_hex(json["result"]["gasUsed"].as_str().unwrap())
        .unwrap()
        .0;

    // Create transaction to pass with estimate=false and fail otherwise
    let tx_with_limit = evm_state::UnsignedTransaction {
        nonce: 5.into(),
        gas_price: 2000000000.into(),
        gas_limit: target_gas_limit * 2,
        action: evm_state::TransactionAction::Call(contract_address_2),
        value: 0.into(),
        input: hex::decode("c41b95d1000000000000000000000000141a4802f84bb64c0320917672ef7d92658e964e0000000000000000000000000000000000000000000000000000000000000000").unwrap(),
    }
        .sign(&evm_secret_key, Some(chain_id));
    let tx_with_limit_hash = tx_with_limit.tx_id_hash();
    let rpc_tx =
        RPCTransaction::from_transaction(TransactionInReceipt::Signed(tx_with_limit.clone()))
            .unwrap();
    let recent_blockhash = get_blockhash(&rpc_url);
    let ixs = vec![send_raw_tx(
        alice.pubkey(),
        tx_with_limit,
        None,
        FeePayerType::Evm,
    )];
    let tx = Transaction::new_signed_with_payer(&ixs, None, &[&alice], recent_blockhash);
    let serialized_encoded_tx = bs58::encode(serialize(&tx).unwrap()).into_string();
    let req = json_req!(
        "sendTransaction",
        json!([
            serialized_encoded_tx,
            RpcSendTransactionConfig {
                skip_preflight: true,
                ..RpcSendTransactionConfig::default()
            }
        ])
    );
    let json = dbg!(post_rpc(req, &rpc_url));
    wait_finalization(&rpc_url, &[&json["result"]]);

    // check that replayTransaction works
    let request = json_req!(
        "trace_replayTransaction",
        json!([tx_with_limit_hash, ["trace"]])
    );
    let json = post_rpc(request.clone(), &rpc_url);
    warn!(
        ">>>>> trace_replayTransaction: {}",
        dbg!(&json["result"]["trace"].as_array().unwrap()[0]["result"])
    );
    assert!(!json["result"].is_null());
    assert!(json["result"]["trace"]
        .as_array()
        .unwrap()
        .iter()
        .all(|v| { !v.as_object().unwrap().contains_key("error") }));

    // check that call fails
    let request = json_req!("trace_call", json!([rpc_tx, vec!["trace"], Some("0x04")]));
    let json = post_rpc(request.clone(), &rpc_url);
    warn!("trace_call: {}", json["result"]);
    assert_eq!(
        json["result"]["trace"].as_array().unwrap()[0]["error"]
            .as_str()
            .unwrap(),
        "Out of gas"
    );
}

#[test]
fn test_rpc_get_logs() {
    solana_logger::setup();

    let evm_secret_key = evm_state::SecretKey::from_slice(&[1; 32]).unwrap();
    let evm_address = evm_state::addr_from_public_key(&evm_state::PublicKey::from_secret_key(
        evm_state::SECP256K1,
        &evm_secret_key,
    ));

    let alice = Keypair::new();
    let test_validator = TestValidatorGenesis::default()
        .fee_rate_governor(FeeRateGovernor::new(0, 0))
        .rent(Rent {
            lamports_per_byte_year: 1,
            exemption_threshold: 1.0,
            ..Rent::default()
        })
        .enable_evm_state_archive()
        .rpc_config(JsonRpcConfig {
            enable_rpc_transaction_history: true,
            ..JsonRpcConfig::default_for_test()
        })
        .start_with_mint_address(alice.pubkey(), SocketAddrSpace::Unspecified)
        .expect("validator start failed");
    let rpc_url = test_validator.rpc_url();

    let req = json_req!("eth_chainId", json!([]));
    let json = post_rpc(req, &rpc_url);
    let chain_id = Hex::from_hex(json["result"].as_str().unwrap()).unwrap().0;

    let blockhash = dbg!(get_blockhash(&rpc_url));
    let ixs = transfer_native_to_evm_ixs(alice.pubkey(), 1000000, evm_address);
    let tx = Transaction::new_signed_with_payer(&ixs, None, &[&alice], blockhash);
    let serialized_encoded_tx = bs58::encode(serialize(&tx).unwrap()).into_string();

    let req = json_req!("sendTransaction", json!([serialized_encoded_tx]));
    let json: Value = post_rpc(req, &rpc_url);
    wait_finalization(&rpc_url, &[&json["result"]]);

    // Contract with method that will emit 3 events
    const TEST_CONTRACT: &str = "608060405234801561001057600080fd5b506101e4806100206000396000f3fe608060405234801561001057600080fd5b506004361061002b5760003560e01c8063e2a2d66a14610030575b600080fd5b61004a6004803603810190610045919061010b565b61004c565b005b7f47e2689743f14e97f7dcfa5eec10ba1dff02f83b3d1d4b9c07b206cbbda664508360405161007b919061016d565b60405180910390a17fa48a6b249a5084126c3da369fbc9b16827ead8cb5cdc094b717d3f1dcd995e29826040516100b2919061016d565b60405180910390a17fe96585649d926cc4f5031a6113d7494d766198c0ac68b04eb93207460f9d7fd2816040516100e9919061016d565b60405180910390a1505050565b60008135905061010581610197565b92915050565b60008060006060848603121561012457610123610192565b5b6000610132868287016100f6565b9350506020610143868287016100f6565b9250506040610154868287016100f6565b9150509250925092565b61016781610188565b82525050565b6000602082019050610182600083018461015e565b92915050565b6000819050919050565b600080fd5b6101a081610188565b81146101ab57600080fd5b5056fea2646970667358221220b182526d07bd62a4f4b9a9cf112a230cdcb940fc6fc1c3d0d41ee81ef2c26c9d64736f6c63430008070033";
    let tx_create = evm_state::UnsignedTransaction {
        nonce: 0.into(),
        gas_price: 2000000000.into(),
        gas_limit: 300000.into(),
        action: evm_state::TransactionAction::Create,
        value: 0.into(),
        input: hex::decode(TEST_CONTRACT).unwrap(),
    }
    .sign(&evm_secret_key, Some(chain_id));
    let contract_address = tx_create.address().unwrap();
    let tx_call = evm_state::UnsignedTransaction {
        nonce: 1.into(),
        gas_price: 2000000000.into(),
        gas_limit: 300000.into(),
        action: evm_state::TransactionAction::Call(contract_address),
        value: 0.into(),
        input: hex::decode("e2a2d66a000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000003").unwrap(),
    }
        .sign(&evm_secret_key, Some(chain_id));

    let blockhash = dbg!(get_blockhash(&rpc_url));
    let ixs = vec![send_raw_tx(
        alice.pubkey(),
        tx_create,
        None,
        FeePayerType::Evm,
    )];
    let tx = Transaction::new_signed_with_payer(&ixs, None, &[&alice], blockhash);
    let serialized_encoded_tx = bs58::encode(serialize(&tx).unwrap()).into_string();
    let req = json_req!("sendTransaction", json!([serialized_encoded_tx]));
    let json = dbg!(post_rpc(req, &rpc_url));
    wait_finalization(&rpc_url, &[&json["result"]]);

    let recent_blockhash = get_blockhash(&rpc_url);
    let ixs = vec![send_raw_tx(
        alice.pubkey(),
        tx_call,
        None,
        FeePayerType::Evm,
    )];
    let tx = Transaction::new_signed_with_payer(&ixs, None, &[&alice], recent_blockhash);
    let serialized_encoded_tx = bs58::encode(serialize(&tx).unwrap()).into_string();
    let req = json_req!("sendTransaction", json!([serialized_encoded_tx]));
    let json = dbg!(post_rpc(req, &rpc_url));
    wait_finalization(&rpc_url, &[&json["result"]]);

    let log_filter = RPCLogFilter {
        from_block: Some(BlockId::BlockHash {
            block_hash: recent_blockhash.to_bytes().into(),
        }),
        to_block: None,
        address: None,
        topics: None,
    };
    let req = json_req!("eth_getLogs", json!([log_filter]));
    let json = post_rpc(req, &rpc_url);
    // eth_getLogs returns all logs when topics is set to None
    assert_eq!(json["result"].as_array().unwrap().len(), 3);
}

#[test]
fn test_rpc_invalid_requests() {
    solana_logger::setup();

    let alice = Keypair::new();
    let test_validator =
        TestValidator::with_no_fees(alice.pubkey(), None, SocketAddrSpace::Unspecified);
    let rpc_url = test_validator.rpc_url();

    let bob_pubkey = solana_sdk::pubkey::new_rand();

    // test invalid get_balance request
    let req = json_req!("getBalance", json!(["invalid9999"]));
    let json = post_rpc(req, &rpc_url);

    let the_error = json["error"]["message"].as_str().unwrap();
    assert_eq!(the_error, "Invalid param: Invalid");

    // test invalid get_account_info request
    let req = json_req!("getAccountInfo", json!(["invalid9999"]));
    let json = post_rpc(req, &rpc_url);

    let the_error = json["error"]["message"].as_str().unwrap();
    assert_eq!(the_error, "Invalid param: Invalid");

    // test invalid get_account_info request
    let req = json_req!("getAccountInfo", json!([bob_pubkey.to_string()]));
    let json = post_rpc(req, &rpc_url);

    let the_value = &json["result"]["value"];
    assert!(the_value.is_null());
}

#[test]
fn test_rpc_slot_updates() {
    solana_logger::setup();

    let test_validator =
        TestValidator::with_no_fees(Pubkey::new_unique(), None, SocketAddrSpace::Unspecified);

    // Track when slot updates are ready
    let (update_sender, update_receiver) = unbounded::<SlotUpdate>();
    // Create the pub sub runtime
    let rt = Runtime::new().unwrap();
    let rpc_pubsub_url = test_validator.rpc_pubsub_url();

    rt.spawn(async move {
        let pubsub_client = PubsubClient::new(&rpc_pubsub_url).await.unwrap();
        let (mut slot_notifications, slot_unsubscribe) =
            pubsub_client.slot_updates_subscribe().await.unwrap();

        while let Some(slot_update) = slot_notifications.next().await {
            update_sender.send(slot_update).unwrap();
        }
        slot_unsubscribe().await;
    });

    let first_update = update_receiver
        .recv_timeout(Duration::from_secs(2))
        .unwrap();

    // Verify that updates are received in order for an upcoming slot
    let verify_slot = first_update.slot() + 2;
    let mut expected_update_index = 0;
    let expected_updates = vec![
        "CreatedBank",
        "Completed",
        "Frozen",
        "OptimisticConfirmation",
        "Root",
    ];

    let test_start = Instant::now();
    loop {
        assert!(test_start.elapsed() < Duration::from_secs(30));
        let update = update_receiver
            .recv_timeout(Duration::from_secs(2))
            .unwrap();
        if update.slot() == verify_slot {
            let update_name = match update {
                SlotUpdate::CreatedBank { .. } => "CreatedBank",
                SlotUpdate::Completed { .. } => "Completed",
                SlotUpdate::Frozen { .. } => "Frozen",
                SlotUpdate::OptimisticConfirmation { .. } => "OptimisticConfirmation",
                SlotUpdate::Root { .. } => "Root",
                _ => continue,
            };
            assert_eq!(update_name, expected_updates[expected_update_index]);
            expected_update_index += 1;
            if expected_update_index == expected_updates.len() {
                break;
            }
        }
    }
}

#[test]
#[ignore]
fn test_rpc_subscriptions() {
    solana_logger::setup();
    use solana_sdk::signature::Signature;
    let alice = Keypair::new();
    let test_validator =
        TestValidator::with_no_fees(alice.pubkey(), None, SocketAddrSpace::Unspecified);

    let transactions_socket = UdpSocket::bind("0.0.0.0:0").unwrap();
    transactions_socket.connect(test_validator.tpu()).unwrap();

    let rpc_client = RpcClient::new(test_validator.rpc_url());
    let recent_blockhash = rpc_client.get_latest_blockhash().unwrap();

    // Create transaction signatures to subscribe to
    let transfer_amount = Rent::default().minimum_balance(0);
    let transactions: Vec<Transaction> = (0..1000)
        .map(|_| {
            system_transaction::transfer(
                &alice,
                &solana_sdk::pubkey::new_rand(),
                transfer_amount,
                recent_blockhash,
            )
        })
        .collect();
    let mut signature_set: HashSet<Signature> =
        transactions.iter().map(|tx| tx.signatures[0]).collect();
    let mut account_set: HashSet<Pubkey> = transactions
        .iter()
        .map(|tx| tx.message.account_keys[1])
        .collect();

    // Track account notifications are received
    let (account_sender, account_receiver) = unbounded::<(Pubkey, RpcResponse<UiAccount>)>();
    // Track when status notifications are received
    let (status_sender, status_receiver) =
        unbounded::<(Signature, RpcResponse<RpcSignatureResult>)>();

    // Create the pub sub runtime
    let rt = Runtime::new().unwrap();
    let rpc_pubsub_url = test_validator.rpc_pubsub_url();
    let signature_set_clone = signature_set.clone();
    let account_set_clone = account_set.clone();
    let signature_subscription_ready = Arc::new(AtomicUsize::new(0));
    let account_subscription_ready = Arc::new(AtomicUsize::new(0));
    let signature_subscription_ready_clone = signature_subscription_ready.clone();
    let account_subscription_ready_clone = account_subscription_ready.clone();

    rt.spawn(async move {
        let pubsub_client = Arc::new(PubsubClient::new(&rpc_pubsub_url).await.unwrap());

        // Subscribe to signature notifications
        for signature in signature_set_clone {
            let status_sender = status_sender.clone();
            let signature_subscription_ready_clone = signature_subscription_ready_clone.clone();
            tokio::spawn({
                let _pubsub_client = Arc::clone(&pubsub_client);
                async move {
                    let (mut sig_notifications, sig_unsubscribe) = _pubsub_client
                        .signature_subscribe(
                            &signature,
                            Some(RpcSignatureSubscribeConfig {
                                commitment: Some(CommitmentConfig::confirmed()),
                                ..RpcSignatureSubscribeConfig::default()
                            }),
                        )
                        .await
                        .unwrap();

                    signature_subscription_ready_clone.fetch_add(1, Ordering::SeqCst);

                    let response = sig_notifications.next().await.unwrap();
                    status_sender.send((signature, response)).unwrap();
                    sig_unsubscribe().await;
                }
            });
        }

        // Subscribe to account notifications
        for pubkey in account_set_clone {
            let account_sender = account_sender.clone();
            let account_subscription_ready_clone = account_subscription_ready_clone.clone();
            tokio::spawn({
                let _pubsub_client = Arc::clone(&pubsub_client);
                async move {
                    let (mut account_notifications, account_unsubscribe) = _pubsub_client
                        .account_subscribe(
                            &pubkey,
                            Some(RpcAccountInfoConfig {
                                commitment: Some(CommitmentConfig::confirmed()),
                                ..RpcAccountInfoConfig::default()
                            }),
                        )
                        .await
                        .unwrap();

                    account_subscription_ready_clone.fetch_add(1, Ordering::SeqCst);

                    let response = account_notifications.next().await.unwrap();
                    account_sender.send((pubkey, response)).unwrap();
                    account_unsubscribe().await;
                }
            });
        }
    });

    let now = Instant::now();
    while (signature_subscription_ready.load(Ordering::SeqCst) != transactions.len()
        || account_subscription_ready.load(Ordering::SeqCst) != transactions.len())
        && now.elapsed() < Duration::from_secs(15)
    {
        sleep(Duration::from_millis(100))
    }

    // check signature subscription
    let num = signature_subscription_ready.load(Ordering::SeqCst);
    if num != transactions.len() {
        error!(
            "signature subscription didn't setup properly, want: {}, got: {}",
            transactions.len(),
            num
        );
    }

    // check account subscription
    let num = account_subscription_ready.load(Ordering::SeqCst);
    if num != transactions.len() {
        error!(
            "account subscriptions didn't setup properly, want: {}, got: {}",
            transactions.len(),
            num
        );
    }

    let rpc_client = RpcClient::new(test_validator.rpc_url());
    let mut mint_balance = rpc_client
        .get_balance_with_commitment(&alice.pubkey(), CommitmentConfig::processed())
        .unwrap()
        .value;
    assert!(mint_balance >= transactions.len() as u64);

    // Send all transactions to tpu socket for processing
    transactions.iter().for_each(|tx| {
        transactions_socket
            .send(&bincode::serialize(&tx).unwrap())
            .unwrap();
    });

    // Track mint balance to know when transactions have completed
    let now = Instant::now();
    let expected_mint_balance = mint_balance - (transfer_amount * transactions.len() as u64);
    while mint_balance != expected_mint_balance && now.elapsed() < Duration::from_secs(15) {
        mint_balance = rpc_client
            .get_balance_with_commitment(&alice.pubkey(), CommitmentConfig::processed())
            .unwrap()
            .value;
        sleep(Duration::from_millis(100));
    }
    if mint_balance != expected_mint_balance {
        error!("mint-check timeout. mint_balance {:?}", mint_balance);
    }

    // Wait for all signature subscriptions
    let deadline = Instant::now() + Duration::from_secs(30);
    while !signature_set.is_empty() {
        let timeout = deadline.saturating_duration_since(Instant::now());
        match status_receiver.recv_timeout(timeout) {
            Ok((sig, result)) => {
                if let RpcSignatureResult::ProcessedSignature(result) = result.value {
                    assert!(result.err.is_none());
                    assert!(signature_set.remove(&sig));
                } else {
                    panic!("Unexpected result");
                }
            }
            Err(_err) => {
                panic!(
                    "recv_timeout, {}/{} signatures remaining",
                    signature_set.len(),
                    transactions.len()
                );
            }
        }
    }

    let deadline = Instant::now() + Duration::from_secs(5);
    while !account_set.is_empty() {
        let timeout = deadline.saturating_duration_since(Instant::now());
        match account_receiver.recv_timeout(timeout) {
            Ok((pubkey, result)) => {
                assert_eq!(result.value.lamports, Rent::default().minimum_balance(0));
                assert!(account_set.remove(&pubkey));
            }
            Err(_err) => {
                panic!(
                    "recv_timeout, {}/{} accounts remaining",
                    account_set.len(),
                    transactions.len()
                );
            }
        }
    }
}

fn run_tpu_send_transaction(tpu_use_quic: bool) {
    let mint_keypair = Keypair::new();
    let mint_pubkey = mint_keypair.pubkey();
    let test_validator =
        TestValidator::with_no_fees(mint_pubkey, None, SocketAddrSpace::Unspecified);
    let rpc_client = Arc::new(RpcClient::new_with_commitment(
        test_validator.rpc_url(),
        CommitmentConfig::processed(),
    ));
    let connection_cache = match tpu_use_quic {
        true => Arc::new(ConnectionCache::new(DEFAULT_TPU_CONNECTION_POOL_SIZE)),
        false => Arc::new(ConnectionCache::with_udp(DEFAULT_TPU_CONNECTION_POOL_SIZE)),
    };
    let tpu_client = TpuClient::new_with_connection_cache(
        rpc_client.clone(),
        &test_validator.rpc_pubsub_url(),
        TpuClientConfig::default(),
        connection_cache,
    )
    .unwrap();

    let recent_blockhash = rpc_client.get_latest_blockhash().unwrap();
    let tx =
        system_transaction::transfer(&mint_keypair, &Pubkey::new_unique(), 42, recent_blockhash);
    assert!(tpu_client.send_transaction(&tx));

    let timeout = Duration::from_secs(5);
    let now = Instant::now();
    let signatures = vec![tx.signatures[0]];
    loop {
        assert!(now.elapsed() < timeout);
        let statuses = rpc_client.get_signature_statuses(&signatures).unwrap();
        if statuses.value.get(0).is_some() {
            return;
        }
    }
}

#[test]
fn test_tpu_send_transaction() {
    run_tpu_send_transaction(/*tpu_use_quic*/ false)
}

#[test]
fn test_tpu_send_transaction_with_quic() {
    run_tpu_send_transaction(/*tpu_use_quic*/ true)
}

#[test]
fn deserialize_rpc_error() -> ClientResult<()> {
    solana_logger::setup();

    let alice = Keypair::new();
    let validator = TestValidator::with_no_fees(alice.pubkey(), None, SocketAddrSpace::Unspecified);
    let rpc_client = RpcClient::new(validator.rpc_url());

    let bob = Keypair::new();
    let lamports = 50;
    let blockhash = rpc_client.get_latest_blockhash()?;
    let mut tx = system_transaction::transfer(&alice, &bob.pubkey(), lamports, blockhash);

    // This will cause an error
    tx.signatures.clear();

    let err = rpc_client.send_transaction(&tx);
    let err = err.unwrap_err();

    match err.kind {
        ClientErrorKind::RpcError(RpcError::RpcRequestError { .. }) => {
            // This is what used to happen
            panic!()
        }
        ClientErrorKind::RpcError(RpcError::RpcResponseError { .. }) => Ok(()),
        _ => {
            panic!()
        }
    }
}
