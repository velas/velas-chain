use std::sync::Arc;

use jsonrpc_core::Result;
use log::*;
use serde_json::json;

use solana_client::{rpc_client::RpcClient, rpc_config::*, rpc_request::*, rpc_response::*};
use solana_core::rpc::{self, OptionalContext};
use solana_runtime::commitment::BlockCommitmentArray;
use solana_sdk::{

epoch_schedule::EpochSchedule,
    clock::{Slot, UnixTimestamp},
    commitment_config::CommitmentConfig,
    epoch_info::EpochInfo,
};

use solana_account_decoder::{parse_token::UiTokenAmount, UiAccount};
use solana_transaction_status::{EncodedConfirmedTransaction, TransactionStatus, UiConfirmedBlock};



use crate::{EvmBridge, from_client_error};

macro_rules! proxy_sol_rpc {
    ($rpc: expr, $rpc_call:ident $(, $calls:expr)*) => (
        {
            debug!("proxy received {}", stringify!($rpc_call));

            #[allow(deprecated)]
            // some methods can be deprecated, but because we are proxy, we should support them.
            match RpcClient::send(&$rpc, RpcRequest::$rpc_call, json!([$($calls,)*])) {
                Err(e) => Err(from_client_error(e).into()),
                Ok(o) => Ok(o)
            }
        }
    )
}

pub struct MinimalRpcSolProxy;

impl rpc::rpc_minimal::Minimal for MinimalRpcSolProxy {
    type Metadata = Arc<EvmBridge>; // TODO: Arc<RpcClient>

    fn get_balance(
        &self,
        meta: Self::Metadata,
        pubkey_str: String,
        config: Option<RpcGetBalanceConfig>,
    ) -> Result<Response<UiLamports>> {
        proxy_sol_rpc!(meta.rpc_client, GetBalance, pubkey_str, config)
    }

    fn get_epoch_info(
        &self,
        meta: Self::Metadata,
        commitment: Option<CommitmentConfig>,
    ) -> Result<EpochInfo> {
        proxy_sol_rpc!(meta.rpc_client, GetEpochInfo, commitment)
    }

    fn get_health(&self, meta: Self::Metadata) -> Result<String> {
        proxy_sol_rpc!(meta.rpc_client, GetHealth)
    }

    fn get_identity(&self, meta: Self::Metadata) -> Result<RpcIdentity> {
        proxy_sol_rpc!(meta.rpc_client, GetMinimumBalanceForRentExemption)
    }

    fn get_slot(&self, meta: Self::Metadata, commitment: Option<CommitmentConfig>) -> Result<u64> {
        proxy_sol_rpc!(meta.rpc_client, GetSlot, commitment)
    }

    fn get_block_height(
        &self,
        meta: Self::Metadata,
        commitment: Option<CommitmentConfig>,
    ) -> Result<u64> {
        proxy_sol_rpc!(meta.rpc_client, GetBlockHeight, commitment)
    }

    fn get_snapshot_slot(&self, meta: Self::Metadata) -> Result<Slot> {
        proxy_sol_rpc!(meta.rpc_client, GetSnapshotSlot)
    }
    fn get_transaction_count(
        &self,
        meta: Self::Metadata,
        commitment: Option<CommitmentConfig>,
    ) -> Result<u64> {
        proxy_sol_rpc!(meta.rpc_client, GetTransactionCount, commitment)
    }

    fn get_version(&self, meta: Self::Metadata) -> Result<RpcVersionInfo> {
        proxy_sol_rpc!(meta.rpc_client, GetVersion)
    }

    fn get_vote_accounts(
        &self,
        meta: Self::Metadata,
        commitment: Option<RpcGetVoteAccountsConfig>,
    ) -> Result<RpcVoteAccountStatus> {
        proxy_sol_rpc!(meta.rpc_client, GetVoteAccounts, commitment)
    }

    fn get_leader_schedule(
        &self,
        meta: Self::Metadata,
        options: Option<RpcLeaderScheduleConfigWrapper>,
        config: Option<RpcLeaderScheduleConfig>,
    ) -> Result<Option<RpcLeaderSchedule>> {
        proxy_sol_rpc!(meta.rpc_client, GetLeaderSchedule, options, config)
    }
}

pub struct FullRpcSolProxy;

impl rpc::rpc_full::Full for FullRpcSolProxy {
    type Metadata = Arc<EvmBridge>; // TODO: Arc<RpcClient>

    fn get_account_info(
        &self,
        meta: Self::Metadata,
        pubkey_str: String,
        config: Option<RpcAccountInfoConfig>,
    ) -> Result<Response<Option<UiAccount>>> {
        proxy_sol_rpc!(meta.rpc_client, GetAccountInfo, pubkey_str, config)
    }

    fn get_multiple_accounts(
        &self,
        meta: Self::Metadata,
        pubkey_strs: Vec<String>,
        config: Option<RpcAccountInfoConfig>,
    ) -> Result<Response<Vec<Option<UiAccount>>>> {
        proxy_sol_rpc!(meta.rpc_client, GetMultipleAccounts, pubkey_strs, config)
    }

    fn get_minimum_balance_for_rent_exemption(
        &self,
        meta: Self::Metadata,
        data_len: usize,
        commitment: Option<CommitmentConfig>,
    ) -> Result<u64> {
        proxy_sol_rpc!(
            meta.rpc_client,
            GetMinimumBalanceForRentExemption,
            data_len,
            commitment
        )
    }

    fn get_program_accounts(
        &self,
        meta: Self::Metadata,
        program_id_str: String,
        config: Option<RpcProgramAccountsConfig>,
    ) -> Result<OptionalContext<Vec<RpcKeyedAccount>>> {
        proxy_sol_rpc!(meta.rpc_client, GetProgramAccounts, program_id_str, config)
    }

    fn get_inflation_governor(
        &self,
        meta: Self::Metadata,
        commitment: Option<CommitmentConfig>,
    ) -> Result<RpcInflationGovernor> {
        proxy_sol_rpc!(meta.rpc_client, GetInflationGovernor, commitment)
    }

    fn get_inflation_rate(&self, meta: Self::Metadata) -> Result<RpcInflationRate> {
        proxy_sol_rpc!(meta.rpc_client, GetInflationRate)
    }

    fn get_epoch_schedule(&self, meta: Self::Metadata) -> Result<EpochSchedule> {
        proxy_sol_rpc!(meta.rpc_client, GetEpochSchedule)
    }

    fn get_cluster_nodes(&self, meta: Self::Metadata) -> Result<Vec<RpcContactInfo>> {
        proxy_sol_rpc!(meta.rpc_client, GetClusterNodes)
    }

    fn get_block_commitment(
        &self,
        meta: Self::Metadata,
        block: Slot,
    ) -> Result<RpcBlockCommitment<BlockCommitmentArray>> {
        proxy_sol_rpc!(meta.rpc_client, GetBlockCommitment, block)
    }

    fn get_genesis_hash(&self, meta: Self::Metadata) -> Result<String> {
        proxy_sol_rpc!(meta.rpc_client, GetGenesisHash)
    }

    fn get_recent_blockhash(
        &self,
        meta: Self::Metadata,
        commitment: Option<CommitmentConfig>,
    ) -> Result<Response<RpcBlockhashFeeCalculator>> {
        proxy_sol_rpc!(meta.rpc_client, GetRecentBlockhash, commitment)
    }

    fn get_fees(
        &self,
        meta: Self::Metadata,
        commitment: Option<CommitmentConfig>,
    ) -> Result<Response<RpcFees>> {
        proxy_sol_rpc!(meta.rpc_client, GetFees, commitment)
    }

    fn get_fee_calculator_for_blockhash(
        &self,
        meta: Self::Metadata,
        blockhash: String,
        commitment: Option<CommitmentConfig>,
    ) -> Result<Response<Option<RpcFeeCalculator>>> {
        proxy_sol_rpc!(
            meta.rpc_client,
            GetFeeCalculatorForBlockhash,
            blockhash,
            commitment
        )
    }

    fn get_fee_rate_governor(&self, meta: Self::Metadata) -> Result<Response<RpcFeeRateGovernor>> {
        proxy_sol_rpc!(meta.rpc_client, GetFeeRateGovernor)
    }

    fn get_signature_statuses(
        &self,
        meta: Self::Metadata,
        signature_strs: Vec<String>,
        config: Option<RpcSignatureStatusConfig>,
    ) -> Result<Response<Vec<Option<TransactionStatus>>>> {
        proxy_sol_rpc!(
            meta.rpc_client,
            GetSignatureStatuses,
            signature_strs,
            config
        )
    }

    fn get_total_supply(
        &self,
        meta: Self::Metadata,
        commitment: Option<CommitmentConfig>,
    ) -> Result<u64> {
        proxy_sol_rpc!(meta.rpc_client, GetTotalSupply, commitment)
    }

    fn get_largest_accounts(
        &self,
        meta: Self::Metadata,
        config: Option<RpcLargestAccountsConfig>,
    ) -> Result<Response<Vec<RpcAccountBalance>>> {
        proxy_sol_rpc!(meta.rpc_client, GetLargestAccounts, config)
    }

    fn get_supply(
        &self,
        meta: Self::Metadata,
        commitment: Option<CommitmentConfig>,
    ) -> Result<Response<RpcSupply>> {
        proxy_sol_rpc!(meta.rpc_client, GetSupply, commitment)
    }

    fn request_airdrop(
        &self,
        meta: Self::Metadata,
        pubkey_str: String,
        lamports: u64,
        config: Option<RpcRequestAirdropConfig>,
    ) -> Result<String> {
        proxy_sol_rpc!(
            meta.rpc_client,
            RequestAirdrop,
            pubkey_str,
            lamports,
            config
        )
    }

    fn get_inflation_reward(
        &self,
        meta: Self::Metadata,
        address_strs: Vec<String>,
        config: Option<RpcEpochConfig>,
    ) -> Result<Vec<Option<RpcInflationReward>>> {
        proxy_sol_rpc!(meta.rpc_client, GetInflationReward, address_strs, config)
    }

    fn send_transaction(
        &self,
        meta: Self::Metadata,
        data: String,
        config: Option<RpcSendTransactionConfig>,
    ) -> Result<String> {
        proxy_sol_rpc!(meta.rpc_client, SendTransaction, data, config)
    }

    fn simulate_transaction(
        &self,
        meta: Self::Metadata,
        data: String,
        config: Option<RpcSimulateTransactionConfig>,
    ) -> Result<Response<RpcSimulateTransactionResult>> {
        proxy_sol_rpc!(meta.rpc_client, SimulateTransaction, data, config)
    }

    fn get_slot_leader(
        &self,
        meta: Self::Metadata,
        commitment: Option<CommitmentConfig>,
    ) -> Result<String> {
        proxy_sol_rpc!(meta.rpc_client, GetSlotLeader, commitment)
    }

    fn minimum_ledger_slot(&self, meta: Self::Metadata) -> Result<Slot> {
        proxy_sol_rpc!(meta.rpc_client, MinimumLedgerSlot)
    }

    fn get_confirmed_block(
        &self,
        meta: Self::Metadata,
        slot: Slot,
        config: Option<RpcEncodingConfigWrapper<RpcConfirmedBlockConfig>>,
    ) -> Result<Option<UiConfirmedBlock>> {
        proxy_sol_rpc!(meta.rpc_client, GetConfirmedBlock, slot, config)
    }

    fn get_confirmed_blocks(
        &self,
        meta: Self::Metadata,
        start_slot: Slot,
        config: Option<RpcConfirmedBlocksConfigWrapper>,
        commitment: Option<CommitmentConfig>,
    ) -> Result<Vec<Slot>> {
        proxy_sol_rpc!(
            meta.rpc_client,
            GetConfirmedBlocks,
            start_slot,
            config,
            commitment
        )
    }

    fn get_block_time(&self, meta: Self::Metadata, slot: Slot) -> Result<Option<UnixTimestamp>> {
        proxy_sol_rpc!(meta.rpc_client, GetBlockTime, slot)
    }

    fn get_confirmed_transaction(
        &self,
        meta: Self::Metadata,
        signature_str: String,
        config: Option<RpcEncodingConfigWrapper<RpcConfirmedTransactionConfig>>,
    ) -> Result<Option<EncodedConfirmedTransaction>> {
        proxy_sol_rpc!(
            meta.rpc_client,
            GetConfirmedTransaction,
            signature_str,
            config
        )
    }

    fn get_confirmed_signatures_for_address(
        &self,
        meta: Self::Metadata,
        pubkey_str: String,
        start_slot: Slot,
        end_slot: Slot,
    ) -> Result<Vec<String>> {
        proxy_sol_rpc!(
            meta.rpc_client,
            GetConfirmedSignaturesForAddress,
            pubkey_str,
            start_slot,
            end_slot
        )
    }

    fn get_confirmed_signatures_for_address2(
        &self,
        meta: Self::Metadata,
        address: String,
        config: Option<RpcGetConfirmedSignaturesForAddress2Config>,
    ) -> Result<Vec<RpcConfirmedTransactionStatusWithSignature>> {
        proxy_sol_rpc!(
            meta.rpc_client,
            GetConfirmedSignaturesForAddress2,
            address,
            config
        )
    }

    fn get_first_available_block(&self, meta: Self::Metadata) -> Result<Slot> {
        proxy_sol_rpc!(meta.rpc_client, GetFirstAvailableBlock)
    }

    fn get_stake_activation(
        &self,
        meta: Self::Metadata,
        pubkey_str: String,
        config: Option<RpcEpochConfig>,
    ) -> Result<RpcStakeActivation> {
        proxy_sol_rpc!(meta.rpc_client, GetStakeActivation, pubkey_str, config)
    }

    fn get_block_production(
        &self,
        meta: Self::Metadata,
        config: Option<RpcBlockProductionConfig>,
    ) -> Result<Response<RpcBlockProduction>> {
        proxy_sol_rpc!(meta.rpc_client, GetBlockProduction, config)
    }

    fn get_token_account_balance(
        &self,
        meta: Self::Metadata,
        pubkey_str: String,
        commitment: Option<CommitmentConfig>,
    ) -> Result<Response<UiTokenAmount>> {
        proxy_sol_rpc!(
            meta.rpc_client,
            GetTokenAccountBalance,
            pubkey_str,
            commitment
        )
    }

    fn get_token_supply(
        &self,
        meta: Self::Metadata,
        mint_str: String,
        commitment: Option<CommitmentConfig>,
    ) -> Result<Response<UiTokenAmount>> {
        proxy_sol_rpc!(meta.rpc_client, GetTokenSupply, mint_str, commitment)
    }

    fn get_token_largest_accounts(
        &self,
        meta: Self::Metadata,
        mint_str: String,
        commitment: Option<CommitmentConfig>,
    ) -> Result<Response<Vec<RpcTokenAccountBalance>>> {
        proxy_sol_rpc!(
            meta.rpc_client,
            GetTokenLargestAccounts,
            mint_str,
            commitment
        )
    }

    fn get_token_accounts_by_owner(
        &self,
        meta: Self::Metadata,
        owner_str: String,
        token_account_filter: RpcTokenAccountsFilter,
        config: Option<RpcAccountInfoConfig>,
    ) -> Result<Response<Vec<RpcKeyedAccount>>> {
        proxy_sol_rpc!(
            meta.rpc_client,
            GetTokenAccountsByOwner,
            owner_str,
            token_account_filter,
            config
        )
    }

    fn get_token_accounts_by_delegate(
        &self,
        meta: Self::Metadata,
        delegate_str: String,
        token_account_filter: RpcTokenAccountsFilter,
        config: Option<RpcAccountInfoConfig>,
    ) -> Result<Response<Vec<RpcKeyedAccount>>> {
        proxy_sol_rpc!(
            meta.rpc_client,
            GetTokenAccountsByDelegate,
            delegate_str,
            token_account_filter,
            config
        )
    }

    fn get_velas_accounts_by_operational_key(
        &self,
        meta: Self::Metadata,
        pubkey_str: String,
    ) -> Result<Response<Vec<String>>> {
        proxy_sol_rpc!(
            meta.rpc_client,
            GetVelasAccountsByOperationalKey,
            pubkey_str
        )
    }

    fn get_velas_accounts_by_owner_key(
        &self,
        meta: Self::Metadata,
        pubkey_str: String,
    ) -> Result<Response<Vec<String>>> {
        proxy_sol_rpc!(meta.rpc_client, GetVelasAccountsByOwnerKey, pubkey_str)
    }

    fn get_velas_relying_parties_by_owner_key(
        &self,
        meta: Self::Metadata,
        pubkey_str: String,
    ) -> Result<Response<Vec<String>>> {
        proxy_sol_rpc!(
            meta.rpc_client,
            GetVelasRelyingPartiesByOwnerKey,
            pubkey_str
        )
    }

    fn get_recent_performance_samples(
        &self,
        meta: Self::Metadata,
        limit: Option<usize>,
    ) -> Result<Vec<RpcPerfSample>> {
        proxy_sol_rpc!(meta.rpc_client, GetRecentPerfomanceSamples, limit)
    }

    fn get_confirmed_blocks_with_limit(
        &self,
        meta: Self::Metadata,
        start_slot: Slot,
        limit: usize,
        commitment: Option<CommitmentConfig>,
    ) -> Result<Vec<Slot>> {
        proxy_sol_rpc!(
            meta.rpc_client,
            GetConfirmedBlocksWithLimit,
            start_slot,
            limit,
            commitment
        )
    }

    fn get_slot_leaders(
        &self,
        meta: Self::Metadata,
        start_slot: Slot,
        end_slot: Slot,
    ) -> Result<Vec<String>> {
        proxy_sol_rpc!(meta.rpc_client, GetSlotLeaders, start_slot, end_slot)
    }

    fn get_max_retransmit_slot(&self, meta: Self::Metadata) -> Result<Slot> {
        proxy_sol_rpc!(meta.rpc_client, GetMaxRetransmitSlot)
    }

    fn get_max_shred_insert_slot(&self, meta: Self::Metadata) -> Result<Slot> {
        proxy_sol_rpc!(meta.rpc_client, GetMaxShredInsertSlot)
    }
}
