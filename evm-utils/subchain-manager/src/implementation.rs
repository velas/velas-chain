use {
    crate::genesis_json,
    borsh::BorshSerialize,
    log::*,
    solana_client::{
        client_error::ClientErrorKind,
        rpc_request::{RpcError, RpcResponseErrorData},
    },
    solana_evm_loader_program::instructions::{AllocAccount, ExtendedConfig},
    solana_sdk::{
        commitment_config::CommitmentConfig, hash::Hash, packet::PACKET_DATA_SIZE, signer::Signer,
        system_instruction, transaction::Transaction,
    },
    std::{
        collections::BTreeMap,
        io::{Read, Write},
        path::Path,
    },
};

impl genesis_json::GenesisConfig {
    pub fn save(&self, config_path: impl AsRef<Path>) -> Result<(), color_eyre::eyre::Error> {
        let mut file = std::fs::File::create(config_path)?;
        let data = serde_json::to_string_pretty(&self)?;
        file.write_all(data.as_bytes())?;
        Ok(())
    }
    pub fn load(path: &str) -> Result<Self, color_eyre::eyre::Error> {
        let file = std::fs::File::open(path)?;
        let mut buf_reader = std::io::BufReader::new(file);
        let mut contents = String::new();
        buf_reader.read_to_string(&mut contents)?;
        let config: Self = serde_json::from_str(&contents)?;
        Ok(config)
    }

    // Try to process transaction pack
    // Return list of transactions that need to be resent
    #[allow(deprecated)]
    fn deploy_tx_pack<'a>(
        signers: &[&solana_sdk::signer::keypair::Keypair; 2],
        client: &solana_client::rpc_client::RpcClient,
        tx_chunks: Vec<(usize, &'a [u8])>,
        last_blockhash: &Hash,
        storage_pubkey: solana_sdk::pubkey::Pubkey,
        payer_pubkey: solana_sdk::pubkey::Pubkey,
    ) -> Result<Vec<(usize, &'a [u8])>, color_eyre::eyre::Error> {
        let (blockhash, _) = client.get_new_blockhash(&last_blockhash).map_err(|e| {
            color_eyre::eyre::Error::msg(format!("Failed to get new blockhash. Error: {e}"))
        })?;

        let write_data_txs: Vec<Transaction> = tx_chunks
            .iter()
            .map(|(i, chunk)| {
                solana_evm_loader_program::big_tx_write(
                    storage_pubkey,
                    (i * evm_state::TX_MTU) as u64,
                    chunk.to_vec(),
                )
            })
            .map(|instruction| {
                Transaction::new_signed_with_payer(
                    &[instruction],
                    Some(&payer_pubkey),
                    signers,
                    blockhash,
                )
            })
            .collect();

        debug!("Write data txs: {:?}", write_data_txs);

        let mut signatures = Vec::new();
        for transaction in &write_data_txs {
            let sign = client.send_transaction(transaction).map_err(|e| {
                color_eyre::eyre::Error::msg(format!(
                    "Error on write data to storage {}: {}",
                    storage_pubkey, e
                ))
            })?;
            signatures.push(sign);
        }
        println!(
            "Waiting for write data txs for storage {} to be processed",
            storage_pubkey
        );
        let timeout = 1000 + tx_chunks.len() as u64 * 200;
        std::thread::sleep(std::time::Duration::from_millis(timeout));

        let mut resend_data = vec![];
        let statuses = client.get_signature_statuses(&signatures).map_err(|e| {
            color_eyre::eyre::Error::msg(format!("Failed to get signature statuses. Error: {e}"))
        })?;

        for (idx, status) in statuses.value.iter().enumerate() {
            if status.is_none() {
                resend_data.push(tx_chunks[idx])
            }
            let status = status.as_ref().unwrap();
            if let Some(err) = &status.err {
                return Err(color_eyre::eyre::Error::msg(format!(
                    "Error on write data to storage {}: {}",
                    storage_pubkey,
                    err.clone()
                )));
            }
        }
        Ok(resend_data)
    }

    fn deploy_big_config(
        &self,
        keypair: &solana_sdk::signer::keypair::Keypair,
        client: &solana_client::rpc_client::RpcClient,
        data: Vec<u8>,
    ) -> Result<(solana_sdk::signer::keypair::Keypair, Hash), color_eyre::eyre::Error> {
        let payer_pubkey = keypair.pubkey();
        let storage = solana_sdk::signer::keypair::Keypair::new();
        let storage_pubkey = storage.pubkey();
        let signers = [keypair, &storage];
        println!("Config is too big, using multiple transactions to proceed");
        debug!(
            "Storage {} : tx bytes size = {}, chunks crc = {:#x}",
            storage_pubkey,
            data.len(),
            solana_evm_loader_program::tx_chunks::TxChunks::new(data.as_slice()).crc(),
        );

        let min_balance = client
            .get_minimum_balance_for_rent_exemption(data.len())
            .map_err(|e| color_eyre::eyre::eyre!("Failed to get minimum balance. Error: {e}"))?;

        let (blockhash, _height) = client
            .get_latest_blockhash_with_commitment(CommitmentConfig::finalized())
            .map_err(|e| color_eyre::eyre::eyre!("Failed to get latest blockhash. Error: {e}"))?;

        let create_storage_ix = system_instruction::create_account(
            &payer_pubkey,
            &storage_pubkey,
            min_balance,
            data.len() as u64,
            &solana_evm_loader_program::ID,
        );

        let allocate_storage_ix =
            solana_evm_loader_program::big_tx_allocate(storage_pubkey, data.len());

        let create_and_allocate_tx = Transaction::new_signed_with_payer(
            &[create_storage_ix, allocate_storage_ix],
            Some(&payer_pubkey),
            &signers,
            blockhash,
        );

        debug!(
            "Create and allocate tx signatures = {:?}",
            create_and_allocate_tx.signatures
        );

        match client.send_and_confirm_transaction_with_config(&create_and_allocate_tx) {
            Ok(signature) => {
                debug!(
                    "Create and allocate {} tx was done, signature = {:?}",
                    storage_pubkey, signature
                )
            }
            Err(e) if e.already_exist_error() => {
                warn!(
                    "Create and allocate tx processing return AlreadyExist error, trying to continue"
                );
            }
            Err(e) => {
                return Err(color_eyre::eyre::eyre!(
                    "Error create and allocate {} tx: {}",
                    storage_pubkey,
                    e
                ));
            }
        }

        let mut tx_chunks: Vec<_> = data.chunks(evm_state::TX_MTU).enumerate().collect();

        let retry = 20;
        for _ in 0..retry {
            if tx_chunks.is_empty() {
                break;
            }
            tx_chunks = Self::deploy_tx_pack(
                &signers,
                client,
                tx_chunks,
                &blockhash,
                storage_pubkey,
                keypair.pubkey(),
            )?;
        }
        if !tx_chunks.is_empty() {
            println!("Failed to deploy config {} tx chunks left", tx_chunks.len());
            println!("Storage secret key = {}", storage.to_base58_string());
        }

        Ok((storage, blockhash))
    }

    pub fn deploy(
        &self,
        keypair: solana_sdk::signer::keypair::Keypair,
        client: &solana_client::rpc_client::RpcClient,
        dry_run: bool,
    ) -> Result<(), color_eyre::eyre::Error> {
        let chain_id: u64 = self.config.chain_id.into();
        let alloc: BTreeMap<_, AllocAccount> = self
            .alloc
            .0
            .iter()
            .map(|(addr, v)| {
                (*addr, {
                    AllocAccount {
                        balance: v.balance,
                        code: v.code.0.clone(),
                        storage: v.storage.clone(),
                        nonce: v.nonce.into(),
                    }
                })
            })
            .collect();

        let config = solana_evm_loader_program::instructions::SubchainConfig {
            token_name: self.config.token_name.clone(),
            network_name: self.config.network_name.clone(),
            hardfork: match self.config.start_hardfork {
                crate::Hardfork::Istanbul => {
                    solana_evm_loader_program::instructions::Hardfork::Istanbul
                }
            },
            alloc,
            whitelisted: self.config.whitelisted.clone(),
            min_gas_price: self.config.gas_price,
        };
        let owner = keypair.pubkey();
        let ix = solana_evm_loader_program::create_evm_subchain_account(
            owner,
            chain_id,
            config.clone(),
            None,
        );
        let mut transaction = solana_sdk::transaction::Transaction::new_signed_with_payer(
            &[ix],
            Some(&owner),
            &[&keypair],
            client.get_latest_blockhash()?,
        );
        if transaction.message_data().len() > PACKET_DATA_SIZE {
            // redo execution with transaction storage
            let (extended_config, config) = ExtendedConfig::split(config);
            let data =
                BorshSerialize::try_to_vec(&extended_config).expect("Cannot serialize config");

            let (storage, blockchash) = self.deploy_big_config(&keypair, client, data)?;

            let instruction = solana_evm_loader_program::create_evm_subchain_account(
                owner,
                chain_id,
                config.clone(),
                Some(storage.pubkey()),
            );
            let execute_tx = Transaction::new_signed_with_payer(
                &[instruction],
                Some(&keypair.pubkey()),
                &[&keypair, &storage],
                blockchash,
            );
            debug!("Deploy subchain config at storage {} ...", storage.pubkey());
            transaction = execute_tx;
        }
        let simulation = client.simulate_transaction(&transaction)?;
        if let Some(err) = simulation.value.err {
            return Err(color_eyre::eyre::Error::msg(format!(
                "Simulation error: {err}, logs: {:?}",
                simulation.value.logs
            )));
        }

        if dry_run {
            return Ok(());
        }
        client
            .send_and_confirm_transaction_with_spinner_and_commitment(
                &transaction,
                CommitmentConfig::processed(),
            )
            .map_err(|e| {
                let mut output = format!("{}", e);

                let ClientErrorKind::RpcError(r) = e.kind else {
                    return output;
                };
                let RpcError::RpcResponseError { data, .. } = r else {
                    return output;
                };
                let RpcResponseErrorData::SendTransactionPreflightFailure(p) = data else {
                    return output;
                };
                for (number, log) in p.logs.iter().flatten().enumerate() {
                    output.push_str(&format!("\nLog line{number} {}", log, number = number + 1));
                }
                output.push('\n');
                output
            })
            .map_err(color_eyre::eyre::Error::msg)?;

        Ok(())
    }
}
