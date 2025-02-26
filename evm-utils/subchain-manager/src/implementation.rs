use {
    crate::genesis_json,
    solana_client::{
        client_error::ClientErrorKind,
        rpc_request::{RpcError, RpcResponseErrorData},
    },
    solana_evm_loader_program::instructions::AllocAccount,
    solana_sdk::signer::Signer,
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
        let ix = solana_evm_loader_program::create_evm_subchain_account(owner, chain_id, config);
        let transaction = solana_sdk::transaction::Transaction::new_signed_with_payer(
            &[ix],
            Some(&owner),
            &[&keypair],
            client.get_latest_blockhash()?,
        );
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
            .send_and_confirm_transaction(&transaction)
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
