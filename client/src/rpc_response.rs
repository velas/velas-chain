use crate::client_error;
use solana_account_decoder::{parse_token::UiTokenAmount, UiAccount};
use solana_sdk::{
    clock::{Epoch, Slot, UnixTimestamp},
    fee_calculator::{FeeCalculator, FeeRateGovernor},
    inflation::Inflation,
    transaction::{Result, TransactionError},
};
use solana_transaction_status::ConfirmedTransactionStatusWithSignature;
use std::{collections::HashMap, fmt, net::SocketAddr};

pub type RpcResult<T> = client_error::Result<Response<T>>;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RpcResponseContext {
    pub slot: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Response<T> {
    pub context: RpcResponseContext,
    pub value: T,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RpcBlockCommitment<T> {
    pub commitment: Option<T>,
    pub total_stake: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct RpcBlockhashFeeCalculator {
    pub blockhash: String,
    pub fee_calculator: FeeCalculator,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct RpcFees {
    pub blockhash: String,
    pub fee_calculator: FeeCalculator,
    pub last_valid_slot: Slot,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct RpcFeeCalculator {
    pub fee_calculator: FeeCalculator,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct RpcFeeRateGovernor {
    pub fee_rate_governor: FeeRateGovernor,
}

#[derive(Serialize, Deserialize, PartialEq, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct RpcInflationGovernor {
    pub initial: f64,
    pub terminal: f64,
    pub taper: f64,
    pub foundation: f64,
    pub foundation_term: f64,
}

impl From<Inflation> for RpcInflationGovernor {
    fn from(inflation: Inflation) -> Self {
        Self {
            initial: inflation.initial,
            terminal: inflation.terminal,
            taper: inflation.taper,
            foundation: inflation.foundation,
            foundation_term: inflation.foundation_term,
        }
    }
}

#[derive(Serialize, Deserialize, PartialEq, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct RpcInflationRate {
    pub total: f64,
    pub validator: f64,
    pub foundation: f64,
    pub epoch: Epoch,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct RpcKeyedAccount {
    pub pubkey: String,
    pub account: UiAccount,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq)]
pub struct SlotInfo {
    pub slot: Slot,
    pub parent: Slot,
    pub root: Slot,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase", tag = "type")]
pub enum SlotUpdate {
    OptimisticConfirmation { slot: Slot, timestamp: u64 },
    FirstShredReceived { slot: Slot, timestamp: u64 },
    Frozen { slot: Slot, timestamp: u64 },
    Root { slot: Slot, timestamp: u64 },
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase", untagged)]
pub enum RpcSignatureResult {
    ProcessedSignature(ProcessedSignatureResult),
    ReceivedSignature(ReceivedSignatureResult),
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct RpcLogsResponse {
    pub signature: String, // Signature as base58 string
    pub err: Option<TransactionError>,
    pub logs: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ProcessedSignatureResult {
    pub err: Option<TransactionError>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub enum ReceivedSignatureResult {
    ReceivedSignature,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct RpcContactInfo {
    /// Pubkey of the node as a base-58 string
    pub pubkey: String,
    /// Gossip port
    pub gossip: Option<SocketAddr>,
    /// Tpu port
    pub tpu: Option<SocketAddr>,
    /// JSON RPC port
    pub rpc: Option<SocketAddr>,
    /// Software version
    pub version: Option<String>,
    /// First 4 bytes of the FeatureSet identifier
    pub feature_set: Option<u32>,
}

/// Map of leader base58 identity pubkeys to the slot indices relative to the first epoch slot
pub type RpcLeaderSchedule = HashMap<String, Vec<usize>>;

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct RpcVersionInfo {
    /// The current version of solana-core
    pub solana_core: String,
    /// first 4 bytes of the FeatureSet identifier
    pub feature_set: Option<u32>,
}

impl fmt::Debug for RpcVersionInfo {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.solana_core)
    }
}

impl fmt::Display for RpcVersionInfo {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if let Some(version) = self.solana_core.split_whitespace().next() {
            // Display just the semver if possible
            write!(f, "{}", version)
        } else {
            write!(f, "{}", self.solana_core)
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "kebab-case")]
pub struct RpcIdentity {
    /// The current node identity pubkey
    pub identity: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct RpcVoteAccountStatus {
    pub current: Vec<RpcVoteAccountInfo>,
    pub delinquent: Vec<RpcVoteAccountInfo>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct RpcVoteAccountInfo {
    /// Vote account pubkey as base-58 encoded string
    pub vote_pubkey: String,

    /// The pubkey of the node that votes using this account
    pub node_pubkey: String,

    /// The current stake, in lamports, delegated to this vote account
    pub activated_stake: u64,
    pub activated_stake_str: UiLamports,

    /// An 8-bit integer used as a fraction (commission/MAX_U8) for rewards payout
    pub commission: u8,

    /// Whether this account is staked for the current epoch
    pub epoch_vote_account: bool,

    /// History of how many credits earned by the end of each epoch
    ///   each tuple is (Epoch, credits, prev_credits)
    pub epoch_credits: Vec<(Epoch, u64, u64)>,

    /// Most recent slot voted on by this vote account (0 if no votes exist)
    pub last_vote: u64,

    /// Current root slot for this vote account (0 if not root slot exists)
    pub root_slot: Slot,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct RpcSignatureConfirmation {
    pub confirmations: usize,
    pub status: Result<()>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct RpcSimulateTransactionResult {
    pub err: Option<TransactionError>,
    pub logs: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct RpcStorageTurn {
    pub blockhash: String,
    pub slot: Slot,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RpcAccountBalance {
    pub address: String,
    pub lamports: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct RpcSupply {
    pub total: u64,
    pub circulating: u64,
    pub non_circulating: u64,
    pub non_circulating_accounts: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub enum StakeActivationState {
    Activating,
    Active,
    Deactivating,
    Inactive,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct RpcStakeActivation {
    pub state: StakeActivationState,
    pub active: u64,
    pub inactive: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RpcTokenAccountBalance {
    pub address: String,
    #[serde(flatten)]
    pub amount: UiTokenAmount,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RpcConfirmedTransactionStatusWithSignature {
    pub signature: String,
    pub slot: Slot,
    pub err: Option<TransactionError>,
    pub memo: Option<String>,
    pub block_time: Option<UnixTimestamp>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RpcPerfSample {
    pub slot: Slot,
    pub num_transactions: u64,
    pub num_slots: u64,
    pub sample_period_secs: u16,
}

impl From<ConfirmedTransactionStatusWithSignature> for RpcConfirmedTransactionStatusWithSignature {
    fn from(value: ConfirmedTransactionStatusWithSignature) -> Self {
        let ConfirmedTransactionStatusWithSignature {
            signature,
            slot,
            err,
            memo,
            block_time,
        } = value;
        Self {
            signature: signature.to_string(),
            slot,
            err,
            memo,
            block_time,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum UiLamports {
    Plain(u64),
    String(String),
}
