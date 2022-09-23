use {
    bincode::serialize,
    log::*,
    reqwest::{self, header::CONTENT_TYPE},
    serde_json::{json, Value},
    solana_account_decoder::UiAccount,
    solana_client::{
        client_error::{ClientErrorKind, Result as ClientResult},
        rpc_client::RpcClient,
        rpc_config::{RpcAccountInfoConfig, RpcSignatureSubscribeConfig},
        rpc_request::RpcError,
        rpc_response::{Response as RpcResponse, RpcSignatureResult, SlotUpdate},
        tpu_client::{TpuClient, TpuClientConfig},
    },
    solana_sdk::{
    commitment_config::{CommitmentConfig, CommitmentLevel},
    fee_calculator::FeeRateGovernor,
        hash::Hash,
        pubkey::Pubkey,
        rent::Rent,
        signature::{Keypair, Signer},
        system_transaction,
        transaction::Transaction,
    },
    solana_streamer::socket::SocketAddrSpace,
    solana_test_validator::TestValidator,
    solana_transaction_status::TransactionStatus,
    std::{
        collections::HashSet,
        net::UdpSocket,
        sync::{mpsc::channel, Arc},
        thread::sleep,
        time::{Duration, Instant},
    },
    tokio::runtime::Runtime,
};
use std::str::FromStr;
use solana_test_validator::TestValidatorGenesis;
use solana_rpc::rpc::JsonRpcConfig;
use solana_client::pubsub_client::PubsubClient;

use primitive_types::{H256, U256};

use evm_rpc::{Hex, RPCTransaction};
use evm_rpc::trace::TraceMeta;
use evm_state::TransactionInReceipt;
use solana_client::rpc_config::RpcSendTransactionConfig;
use solana_evm_loader_program::instructions::FeePayerType;

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
        let values = dbg!(&json["result"])["value"].as_array().unwrap();
        if values.iter().all(|v| !v.is_null()) {
            if values.iter().all(|v| {
                assert_eq!(v["err"], Value::Null);
                v["confirmationStatus"].as_str().unwrap() == "finalized"
            }) {
                info!("All signatures confirmed: {:?}", values);
                return true;
            }
        }

        sleep(Duration::from_secs(1));
    }
    false
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
    };
    let req = json_req!(
        "getAccountInfo",
        json!([bs58::encode(bob_pubkey).into_string(), config])
    );
    let json: Value = post_rpc(req, &rpc_url);
    info!("{:?}", json["result"]["value"]);
}

#[test]
fn test_rpc_replay_transaction() {
    use solana_evm_loader_program::{send_raw_tx, transfer_native_to_evm_ixs};
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
    use solana_evm_loader_program::{send_raw_tx, transfer_native_to_evm_ixs};
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
    let evm_blockhash: H256 = Hex::from_hex(json["result"]["hash"].as_str().unwrap()).unwrap().0;
    let request = json_req!("eth_getBlockTransactionCountByHash", json!([evm_blockhash]));
    let json = post_rpc(request.clone(), &rpc_url);
    let num_tx: u64 = Hex::from_hex(json["result"].as_str().unwrap()).unwrap().0;
    assert_eq!(num_tx, 3u64);

    let request = json_req!("eth_getTransactionByBlockHashAndIndex", json!([evm_blockhash, "0x02"]));
    let json = post_rpc(request.clone(), &rpc_url);
    assert_eq!(evm_address, Hex::from_hex(json["result"]["from"].as_str().unwrap()).unwrap().0);
    assert_eq!(evm_address, Hex::from_hex(json["result"]["to"].as_str().unwrap()).unwrap().0);

    let request = json_req!("eth_getTransactionByBlockNumberAndIndex", json!(["0x02", "0x02"]));
    let json = post_rpc(request.clone(), &rpc_url);
    assert_eq!(evm_address, Hex::from_hex(json["result"]["from"].as_str().unwrap()).unwrap().0);
    assert_eq!(evm_address, Hex::from_hex(json["result"]["to"].as_str().unwrap()).unwrap().0);
}

#[test]
fn test_rpc_replay_transaction_timestamp() {
    use solana_evm_loader_program::{send_raw_tx, transfer_native_to_evm_ixs};
    // let filter = "warn,evm=debug,evm_state::context=info";
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
    let ixs = vec![send_raw_tx(alice.pubkey(), tx_create, None, FeePayerType::Evm)];
    let tx = Transaction::new_signed_with_payer(&ixs, None, &[&alice], blockhash);
    let serialized_encoded_tx = bs58::encode(serialize(&tx).unwrap()).into_string();
    let req = json_req!("sendTransaction", json!([serialized_encoded_tx]));
    let json = dbg!(post_rpc(req, &rpc_url));
    wait_finalization(&rpc_url, &[&json["result"]]);

    let recent_blockhash = get_blockhash(&rpc_url);
    let ixs = vec![send_raw_tx(alice.pubkey(), tx_call, None, FeePayerType::Evm)];
    let tx = Transaction::new_signed_with_payer(&ixs, None, &[&alice], recent_blockhash);
    let serialized_encoded_tx = bs58::encode(serialize(&tx).unwrap()).into_string();
    let req = json_req!("sendTransaction", json!([serialized_encoded_tx]));
    let json = dbg!(post_rpc(req, &rpc_url));
    wait_finalization(&rpc_url, &[&json["result"]]);

    let request = json_req!("trace_replayTransaction", json!([tx_call_hash, ["trace"]]));
    let json = post_rpc(request.clone(), &rpc_url);
    warn!("trace_replayTransaction: {}", dbg!(json.clone()));
    assert!(!json["result"].is_null());
    assert!(json["result"]["trace"].as_array().unwrap().iter().all(|v| {
        !v.as_object().unwrap().contains_key("error")
    }));
}

#[test]
fn test_rpc_replay_transaction_gas_used() {
    use solana_evm_loader_program::{send_raw_tx, transfer_native_to_evm_ixs};
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

    info!("Deploy contracts {}, {}", contract_address_1, contract_address_2);
    // deploy first contract
    let blockhash = dbg!(get_blockhash(&rpc_url));
    let ixs = vec![send_raw_tx(alice.pubkey(), tx_create_1, None, FeePayerType::Evm)];
    let tx = Transaction::new_signed_with_payer(&ixs, None, &[&alice], blockhash);
    let serialized_encoded_tx = bs58::encode(serialize(&tx).unwrap()).into_string();
    let req = json_req!("sendTransaction", json!([serialized_encoded_tx]));
    let json = dbg!(post_rpc(req, &rpc_url));
    wait_finalization(&rpc_url, &[&json["result"]]);

    // deploy second contract
    let blockhash = dbg!(get_blockhash(&rpc_url));
    let ixs = vec![send_raw_tx(alice.pubkey(), tx_create_2, None, FeePayerType::Evm)];
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
    let rpc_txs: Vec<_> = tx_calls
        .iter()
        .map(|tx| RPCTransaction::from_transaction(TransactionInReceipt::Signed(tx.clone())).unwrap())
        .collect();

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
    let target_gas_limit: U256 = Hex::from_hex(json["result"]["gasUsed"].as_str().unwrap()).unwrap().0;

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
    let rpc_tx = RPCTransaction::from_transaction(TransactionInReceipt::Signed(tx_with_limit.clone())).unwrap();
    let recent_blockhash = get_blockhash(&rpc_url);
    let ixs = vec![send_raw_tx(alice.pubkey(), tx_with_limit, None, FeePayerType::Evm)];
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
    let request = json_req!("trace_replayTransaction", json!([tx_with_limit_hash, ["trace"]]));
    let json = post_rpc(request.clone(), &rpc_url);
    warn!(">>>>> trace_replayTransaction: {}", dbg!(&json["result"]["trace"].as_array().unwrap()[0]["result"]));
    assert!(!json["result"].is_null());
    assert!(json["result"]["trace"].as_array().unwrap().iter().all(|v| {
        !v.as_object().unwrap().contains_key("error")
    }));

    // check that call fails
    let request = json_req!("trace_call", json!([rpc_tx, vec!["trace"], Some("0x04")]));
    let json = post_rpc(request.clone(), &rpc_url);
    warn!("trace_call: {}", json["result"]);
    assert_eq!(json["result"]["trace"].as_array().unwrap()[0]["error"].as_str().unwrap(), "Out of gas");
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

    // Create the pub sub runtime
    let rt = Runtime::new().unwrap();
    let rpc_pubsub_url = test_validator.rpc_pubsub_url();
    let (update_sender, update_receiver) = channel::<SlotUpdate>();

    // Subscribe to slot updates
    rt.spawn(async move {

        tokio::spawn(async move {
            let _update_sub = PubsubClient::slot_updates_subscribe(&rpc_pubsub_url, move |response| update_sender.send(response).unwrap()).unwrap();
            loop{tokio::time::sleep(Duration::from_millis(1000)).await;} // wait subscription
        });
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
    let transactions: Vec<Transaction> = (0..1000)
        .map(|_| {
            system_transaction::transfer(
                &alice,
                &solana_sdk::pubkey::new_rand(),
                Rent::default().minimum_balance(0),
                recent_blockhash,
            )
        })
        .collect();
    let mut signature_set: HashSet<String> = transactions
        .iter()
        .map(|tx| tx.signatures[0].to_string())
        .collect();
    let account_set: HashSet<String> = transactions
        .iter()
        .map(|tx| tx.message.account_keys[1].to_string())
        .collect();

    // Track when subscriptions are ready
    let (ready_sender, ready_receiver) = channel::<()>();
    // Track account notifications are received
    let (account_sender, account_receiver) = channel::<RpcResponse<UiAccount>>();
    // Track when status notifications are received
    let (status_sender, status_receiver) = channel::<(String, RpcResponse<RpcSignatureResult>)>();

    // Create the pub sub runtime
    let rt = Runtime::new().unwrap();
    let rpc_pubsub_url = test_validator.rpc_pubsub_url();
    let signature_set_clone = signature_set.clone();
    rt.spawn(async move {
        // Subscribe to signature notifications
        for sig in signature_set_clone {
            let status_sender = status_sender.clone();
            let sig_sub = PubsubClient::signature_subscribe(
                    &rpc_pubsub_url,
                    &Signature::from_str(&sig).unwrap(),
                    Some(RpcSignatureSubscribeConfig {
                        commitment: Some(CommitmentConfig::confirmed()),
                        ..RpcSignatureSubscribeConfig::default()
                    }),
                )
                .unwrap_or_else(|err| panic!("sig sub err: {:#?}", err));

            tokio::spawn(async move {
                let response = sig_sub.1.recv().unwrap();
                status_sender
                    .send((sig.clone(), response))
                    .unwrap();
            });
        }

        // Subscribe to account notifications
        for pubkey in account_set {
            let account_sender = account_sender.clone();
            let client_sub = PubsubClient::account_subscribe(
                    &rpc_pubsub_url,
                    &Pubkey::from_str(&pubkey).unwrap(),
                    Some(RpcAccountInfoConfig {
                        commitment: Some(CommitmentConfig::confirmed()),
                        ..RpcAccountInfoConfig::default()
                    }),
                )
                .unwrap_or_else(|err| panic!("acct sub err: {:#?}", err));
            tokio::spawn(async move {
                let response = client_sub.1.recv().unwrap();
                account_sender.send(response).unwrap();
            });
        }

        // Signal ready after the next slot notification
        let slot_sub = PubsubClient::slot_subscribe(&rpc_pubsub_url,)
            .unwrap_or_else(|err| panic!("sig sub err: {:#?}", err));
        tokio::spawn(async move {
            let _response = slot_sub.1.recv().unwrap();
            ready_sender.send(()).unwrap();
        });
    });

    // Wait for signature subscriptions
    ready_receiver.recv_timeout(Duration::from_secs(2)).unwrap();

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
    let expected_mint_balance = mint_balance - transactions.len() as u64;
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
    let mut account_notifications = transactions.len();
    while account_notifications > 0 {
        let timeout = deadline.saturating_duration_since(Instant::now());
        match account_receiver.recv_timeout(timeout) {
            Ok(result) => {
                assert_eq!(result.value.lamports, Rent::default().minimum_balance(0));
                account_notifications -= 1;
            }
            Err(_err) => {
                panic!(
                    "recv_timeout, {}/{} accounts remaining",
                    account_notifications,
                    transactions.len()
                );
            }
        }
    }
}

#[test]
fn test_tpu_send_transaction() {
    let mint_keypair = Keypair::new();
    let mint_pubkey = mint_keypair.pubkey();
    let test_validator =
        TestValidator::with_no_fees(mint_pubkey, None, SocketAddrSpace::Unspecified);
    let rpc_client = Arc::new(RpcClient::new_with_commitment(
        test_validator.rpc_url(),
        CommitmentConfig::processed(),
    ));

    let tpu_client = TpuClient::new(
        rpc_client.clone(),
        &test_validator.rpc_pubsub_url(),
        TpuClientConfig::default(),
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
