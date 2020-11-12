use log::*;
use solana_client::rpc_client::RpcClient;
use solana_evm_loader_program::instructions::{Deposit, EvmInstruction};
use solana_evm_loader_program::scope::*;
use solana_sdk::{
    commitment_config::CommitmentConfig,
    instruction::{AccountMeta, Instruction},
    message::Message,
    native_token::lamports_to_sol,
    pubkey::Pubkey,
    signature::{read_keypair_file, Keypair, Signer},
    system_instruction, sysvar,
};
use std::fs::File;
use std::io::{Read, Write};

// With the "paw" feature enabled in structopt
#[derive(Debug, structopt::StructOpt)]
enum SubCommands {
    SendRawTx {
        raw_tx: String,
    },
    CreateDeposit {
        account_keypair: Option<String>,
    },
    TransferToEth {
        authority_address: solana::Address,
        lamports: u64,
        ether_address: evm::Address,
    },
    CreateDummy {
        tx_file: String,
        #[structopt(short = "c", long = "code")]
        contract_code: Option<String>,
    },
    CallDummy {
        create_tx: String,
        tx_file: String,
        #[structopt(short = "a", long = "abi")]
        abi: Option<String>,
    },
    ParseArray {
        array: String,
    },
}

#[derive(Debug, structopt::StructOpt)]
struct Args {
    #[structopt(subcommand)]
    subcommand: SubCommands,
}

const SECRET_KEY_DUMMY: [u8; 32] = [1; 32];

fn check_fee_payer_balance(
    rpc_client: &RpcClient,
    pubkey: &Pubkey,
    required_balance: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    let balance = rpc_client.get_balance(pubkey)?;
    if balance < required_balance {
        Err(format!(
            "Fee payer, {}, has insufficient balance: {} required, {} available",
            pubkey,
            lamports_to_sol(required_balance),
            lamports_to_sol(balance)
        )
        .into())
    } else {
        Ok(())
    }
}

#[paw::main]
fn main(args: Args) -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    info!("{:?}", args);

    let keypath = solana_cli_config::Config::default().keypair_path;
    info!("Loading keypair from: {}", keypath);
    let signer = Box::new(read_keypair_file(&keypath).unwrap()) as Box<dyn Signer>;

    let rpc_client = RpcClient::new("http://127.0.0.1:8899".to_string());

    match args.subcommand {
        SubCommands::SendRawTx { raw_tx } => {
            let mut file = File::open(raw_tx).unwrap();
            let mut buf = Vec::new();
            Read::read_to_end(&mut file, &mut buf).unwrap();
            let tx: evm::Transaction =
                solana_sdk::program_utils::limited_deserialize(&buf).unwrap();

            info!("loaded tx = {:?}", tx);

            let account_metas = vec![AccountMeta::new(signer.pubkey(), true)];

            let ix = Instruction::new(
                solana_evm_loader_program::ID,
                &EvmInstruction::EvmTransaction { evm_tx: tx },
                account_metas,
            );

            let message = Message::new(&[ix], Some(&signer.pubkey()));
            let mut create_account_tx = solana::Transaction::new_unsigned(message);

            info!("Getting block hash");
            let (blockhash, _fee_calculator, _) = rpc_client
                .get_recent_blockhash_with_commitment(CommitmentConfig::default())
                .unwrap()
                .value;

            create_account_tx.sign(&vec![&*signer], blockhash);
            info!("Sending tx = {:?}", create_account_tx);
            let result = rpc_client.send_and_confirm_transaction_with_spinner_and_config(
                &create_account_tx,
                CommitmentConfig::default(),
                Default::default(),
            );
            info!("Result = {:?}", result);
            // let mut write_transactions = vec![];
            // for message in write_messages.into_iter() {
            //     let mut tx = Transaction::new_unsigned(message);
            //     tx.try_sign(&signers, blockhash)?;
            //     write_transactions.push(tx);
            // }

            // trace!("Writing program data");
            // send_and_confirm_transactions_with_spinner(&rpc_client, write_transactions, &signers).map_err(
            //     |_| CliError::DynamicProgramError("Data writes to program account failed".to_string()),
            // )?;
        }
        SubCommands::CreateDeposit { account_keypair } => {
            let account = if let Some(account_keypair) = account_keypair {
                Box::new(read_keypair_file(&account_keypair).unwrap())
            } else {
                Box::new(Keypair::new())
            };
            let minimum_balance_for_rent_exemption =
                rpc_client.get_minimum_balance_for_rent_exemption(Deposit::LEN)?;

            let account_metas = vec![
                AccountMeta::new(account.pubkey(), false),
                AccountMeta::new_readonly(sysvar::rent::id(), false),
            ];

            let ix = Instruction::new(
                solana_evm_loader_program::ID,
                &EvmInstruction::CreateDepositAccount {
                    pubkey: signer.pubkey(),
                },
                account_metas,
            );
            info!("Created account = {}", account.pubkey());

            let mut transaction = solana::Transaction::new_with_payer(
                &[
                    system_instruction::create_account(
                        &signer.pubkey(),
                        &account.pubkey(),
                        minimum_balance_for_rent_exemption,
                        Deposit::LEN as u64,
                        &solana_evm_loader_program::ID,
                    ),
                    ix,
                ],
                Some(&signer.pubkey()),
            );

            let (recent_blockhash, fee_calculator) = rpc_client.get_recent_blockhash()?;
            check_fee_payer_balance(
                &rpc_client,
                &signer.pubkey(),
                minimum_balance_for_rent_exemption
                    + fee_calculator.calculate_fee(&transaction.message()),
            )?;
            let signers = vec![signer.as_ref(), account.as_ref()];
            transaction.sign(&signers, recent_blockhash);
            info!("Sending tx = {:?}", transaction);
            let result = rpc_client.send_and_confirm_transaction_with_spinner_and_config(
                &transaction,
                CommitmentConfig::default(),
                Default::default(),
            );
            info!("Result = {:?}", result);
        }
        SubCommands::TransferToEth {
            authority_address,
            lamports,
            ether_address,
        } => {
            let account_metas = vec![
                AccountMeta::new(signer.pubkey(), true),
                AccountMeta::new(authority_address, false),
            ];

            let ix = Instruction::new(
                solana_evm_loader_program::ID,
                &EvmInstruction::SwapNativeToEther {
                    lamports,
                    ether_address,
                },
                account_metas,
            );

            let message = Message::new(&[ix], Some(&signer.pubkey()));
            let mut create_account_tx = solana::Transaction::new_unsigned(message);

            info!("Getting block hash");
            let (blockhash, _fee_calculator, _) = rpc_client
                .get_recent_blockhash_with_commitment(CommitmentConfig::default())
                .unwrap()
                .value;

            create_account_tx.sign(&vec![&*signer], blockhash);
            info!("Sending tx = {:?}", create_account_tx);
            let result = rpc_client.send_and_confirm_transaction_with_spinner_and_config(
                &create_account_tx,
                CommitmentConfig::default(),
                Default::default(),
            );
            info!("Result = {:?}", result);
        }
        SubCommands::CreateDummy {
            tx_file,
            contract_code,
        } => {
            let secret_key = evm::SecretKey::from_slice(&SECRET_KEY_DUMMY).unwrap();
            let tx_create = evm::UnsignedTransaction {
                nonce: 0.into(),
                gas_price: 0.into(),
                gas_limit: 300000.into(),
                action: evm::TransactionAction::Create,
                value: 0.into(),
                input: hex::decode(
                    contract_code
                        .as_deref()
                        .unwrap_or(evm_state::HELLO_WORLD_CODE),
                )
                .unwrap()
                .to_vec(),
            };
            let tx_create = tx_create.sign(&secret_key, None);

            let mut file = File::create(tx_file).unwrap();
            Write::write_all(&mut file, &bincode::serialize(&tx_create).unwrap()).unwrap();
        }
        SubCommands::CallDummy {
            tx_file,
            create_tx,
            abi,
        } => {
            let mut file = File::open(create_tx).unwrap();
            let mut buf = Vec::new();
            Read::read_to_end(&mut file, &mut buf).unwrap();
            let evm_tx: evm::Transaction =
                solana_sdk::program_utils::limited_deserialize(&buf).unwrap();
            let tx_address = evm_tx.address().unwrap();

            let secret_key = evm::SecretKey::from_slice(&SECRET_KEY_DUMMY).unwrap();
            let tx_call = evm::UnsignedTransaction {
                nonce: 0.into(),
                gas_price: 0.into(),
                gas_limit: 300000.into(),
                action: evm::TransactionAction::Call(tx_address),
                value: 0.into(),
                input: hex::decode(abi.as_deref().unwrap_or(evm_state::HELLO_WORLD_ABI))
                    .unwrap()
                    .to_vec(),
            };

            let tx_call = tx_call.sign(&secret_key, None);

            let mut file = File::create(tx_file).unwrap();
            Write::write_all(&mut file, &bincode::serialize(&tx_call).unwrap()).unwrap();
        }
        SubCommands::ParseArray { array } => {
            let bytes: Vec<u8> = serde_json::from_str(&array).unwrap();
            println!("Resulting data HEX = {}", hex::encode(&bytes));
            println!("Resulting data utf8 = {}", String::from_utf8_lossy(&bytes));
        }
    }
    // solana_evm_loader_program::processor::EVMProcessor::write_account(address, account);
    Ok(())
}
