use lazy_static::lazy_static;
use solana_sdk::{
    clock::Slot,
    hash::{Hash, Hasher},
    pubkey::Pubkey,
};
use std::collections::{HashMap, HashSet};

pub mod instructions_sysvar_enabled {
    solana_sdk::declare_id!("EnvhHCLvg55P7PDtbvR1NwuTuAeodqpusV3MR5QEK8gs");
}

pub mod secp256k1_program_enabled {
    solana_sdk::declare_id!("E3PHP7w8kB7np3CTQ1qQ2tW3KCtjRSXBQgW9vM2mWv2Y");
}

pub mod consistent_recent_blockhashes_sysvar {
    solana_sdk::declare_id!("3h1BQWPDS5veRsq6mDBWruEpgPxRJkfwGexg5iiQ9mYg");
}

pub mod deprecate_rewards_sysvar {
    solana_sdk::declare_id!("GaBtBJvmS4Arjj5W1NmFcyvPjsHN38UGYDq2MDwbs9Qu");
}

pub mod pico_inflation {
    solana_sdk::declare_id!("4RWNif6C2WCNiKVW7otP4G7dkmkHGyKQWRpuZ1pxKU5m");
}

pub mod full_inflation {
    pub mod devnet_and_testnet_velas_mainnet {
        solana_sdk::declare_id!("DT4n6ABDqs6w4bnfwrXT9rsprcPf6cdDga1egctaPkLC");
    }

    pub mod mainnet {
        pub mod certusone {
            pub mod vote {
                solana_sdk::declare_id!("BzBBveUDymEYoYzcMWNQCx3cd4jQs7puaVFHLtsbB6fm");
            }
            pub mod enable {
                solana_sdk::declare_id!("7XRJcS5Ud5vxGB54JbK9N2vBZVwnwdBNeJW1ibRgD9gx");
            }
        }
    }
}

pub mod spl_token_v2_multisig_fix {
    solana_sdk::declare_id!("E5JiFDQCwyC6QfT9REFyMpfK2mHcmv1GUDySU1Ue7TYv");
}

pub mod bpf_loader2_program {
    solana_sdk::declare_id!("DFBnrgThdzH4W6wZ12uGPoWcMnvfZj11EHnxHcVxLPhD");
}

pub mod bpf_compute_budget_balancing {
    solana_sdk::declare_id!("HxvjqDSiF5sYdSYuCXsUnS8UeAoWsMT9iGoFP8pgV1mB");
}

pub mod sha256_syscall_enabled {
    solana_sdk::declare_id!("D7KfP7bZxpkYtD4Pc38t9htgs1k5k47Yhxe4rp6WDVi8");
}

pub mod no_overflow_rent_distribution {
    solana_sdk::declare_id!("4kpdyrcj5jS47CZb2oJGfVxjYbsMm2Kx97gFyZrxxwXz");
}

pub mod ristretto_mul_syscall_enabled {
    solana_sdk::declare_id!("HRe7A6aoxgjKzdjbBv6HTy7tJ4YWqE6tVmYCGho6S9Aq");
}

pub mod max_invoke_depth_4 {
    solana_sdk::declare_id!("EdM9xggY5y7AhNMskRG8NgGMnaP4JFNsWi8ZZtyT1af5");
}

pub mod max_program_call_depth_64 {
    solana_sdk::declare_id!("YCKSgA6XmjtkQrHBQjpyNrX6EMhJPcYcLWMVgWn36iv");
}

pub mod sol_log_compute_units_syscall {
    solana_sdk::declare_id!("BHuZqHAj7JdZc68wVgZZcy51jZykvgrx4zptR44RyChe");
}

pub mod pubkey_log_syscall_enabled {
    solana_sdk::declare_id!("MoqiU1vryuCGQSxFKA1SZ316JdLEFFhoAu6cKUNk7dN");
}

pub mod pull_request_ping_pong_check {
    solana_sdk::declare_id!("5RzEHTnf6D7JPZCvwEzjM19kzBsyjSU3HoMfXaQmVgnZ");
}

pub mod stake_program_v2 {
    solana_sdk::declare_id!("Gvd9gGJZDHGMNf1b3jkxrfBQSR5etrfTQSBNKCvLSFJN");
}

pub mod rewrite_stake {
    solana_sdk::declare_id!("6ap2eGy7wx5JmsWUmQ5sHwEWrFSDUxSti2k5Hbfv5BZG");
}

pub mod filter_stake_delegation_accounts {
    solana_sdk::declare_id!("GE7fRxmW46K6EmCD9AMZSbnaJ2e3LfqCZzdHi9hmYAgi");
}

pub mod simple_capitalization {
    solana_sdk::declare_id!("9r69RnnxABmpcPFfj1yhg4n9YFR2MNaLdKJCC6v3Speb");
}

pub mod bpf_loader_upgradeable_program {
    solana_sdk::declare_id!("FbhK8HN9qvNHvJcoFVHAEUCNkagHvu7DTWzdnLuVQ5u4");
}

pub mod try_find_program_address_syscall_enabled {
    solana_sdk::declare_id!("EMsMNadQNhCYDyGpYH5Tx6dGHxiUqKHk782PU5XaWfmi");
}

pub mod stake_program_v3 {
    solana_sdk::declare_id!("Ego6nTu7WsBcZBvVqJQKp6Yku2N3mrfG8oYCfaLZkAeK");
}

pub mod max_cpi_instruction_size_ipv6_mtu {
    solana_sdk::declare_id!("5WLtuUJA5VVA1Cc28qULPfGs8anhoBev8uNqaaXeasnf");
}

pub mod limit_cpi_loader_invoke {
    solana_sdk::declare_id!("xGbcW7EEC7zMRJ6LaJCob65EJxKryWjwM4rv8f57SRM");
}

pub mod use_loaded_program_accounts {
    solana_sdk::declare_id!("FLjgLeg1PJkZimQCVa5sVFtaq6VmSDPw3NvH8iQ3nyHn");
}

pub mod abort_on_all_cpi_failures {
    solana_sdk::declare_id!("ED5D5a2hQaECHaMmKpnU48GdsfafdCjkb3pgAw5RKbb2");
}

pub mod use_loaded_executables {
    solana_sdk::declare_id!("3Jq7mE2chDpf6oeEDsuGK7orTYEgyQjCPvaRppTNdVGK");
}

pub mod turbine_retransmit_peers_patch {
    solana_sdk::declare_id!("5Lu3JnWSFwRYpXzwDMkanWSk6XqSuF2i5fpnVhzB5CTc");
}

pub mod prevent_upgrade_and_invoke {
    solana_sdk::declare_id!("BiNjYd8jCYDgAwMqP91uwZs6skWpuHtKrZbckuKESs8N");
}

pub mod track_writable_deescalation {
    solana_sdk::declare_id!("HVPSxqskEtRLRT2ZeEMmkmt9FWqoFX4vrN6f5VaadLED");
}

pub mod require_custodian_for_locked_stake_authorize {
    solana_sdk::declare_id!("D4jsDcXaqdW8tDAWn8H4R25Cdns2YwLneujSL1zvjW6R");
}

pub mod spl_token_v2_self_transfer_fix {
    solana_sdk::declare_id!("BL99GYhdjjcv6ys22C9wPgn2aTVERDbPHHo4NbS3hgp7");
}

pub mod matching_buffer_upgrade_authorities {
    solana_sdk::declare_id!("B5PSjDEJvKJEUQSL7q94N7XCEoWJCYum8XfUg7yuugUU");
}

pub mod warp_timestamp_again {
    solana_sdk::declare_id!("GvDsGDkH5gyzwpDhxNixx8vtx1kwYHH13RiNAPw27zXb");
}

pub mod per_byte_logging_cost {
    solana_sdk::declare_id!("59dM4SV6dPEKXPfkrkhFkRdn4K6xwKxdNAPMyXG7J1wT");
}

pub mod check_init_vote_data {
    solana_sdk::declare_id!("3ccR6QpxGYsAbWyfevEtBNGfWV4xBffxRj2tD6A9i39F");
}

pub mod check_program_owner {
    solana_sdk::declare_id!("5XnbR5Es9YXEARRuP6mdvoxiW3hx5atNNeBmwVd8P3QD");
}

pub mod test_features {
    solana_sdk::declare_id!("11111111111111111111111111111111");
}

pub mod velas_hardfork_pack {
    // 1. difficulty not a hash but a number.
    // 2. transactionRoot, receiptRoot - should calculate, and empty hashes should be setted too
    // 3. nonce is 64bit hash not a number.
    // 4. sha3uncle hash from zero block, not zeros.
    solana_sdk::declare_id!("91nakVjUc5UmNzLioE6K7HhASmb2m1E7hRuLZS4LzUPV");
}

lazy_static! {

    pub static ref FEATURE_NAMES_BEFORE_MAINNET: HashMap<Pubkey, &'static str> = [
        (instructions_sysvar_enabled::id(), "instructions sysvar"),
        (secp256k1_program_enabled::id(), "secp256k1 program"),
        (consistent_recent_blockhashes_sysvar::id(), "consistent recentblockhashes sysvar"),
        (deprecate_rewards_sysvar::id(), "deprecate unused rewards sysvar"),
        (pico_inflation::id(), "pico inflation"),
        (full_inflation::devnet_and_testnet_velas_mainnet::id(), "full inflation on devnet and testnet"),
        (spl_token_v2_multisig_fix::id(), "spl-token multisig fix"),
        (bpf_loader2_program::id(), "bpf_loader2 program"),
        (bpf_compute_budget_balancing::id(), "compute budget balancing"),
        (sha256_syscall_enabled::id(), "sha256 syscall"),
        (no_overflow_rent_distribution::id(), "no overflow rent distribution"),
        (ristretto_mul_syscall_enabled::id(), "ristretto multiply syscall"),
        (max_invoke_depth_4::id(), "max invoke call depth 4"),
        (max_program_call_depth_64::id(), "max program call depth 64"),
        (sol_log_compute_units_syscall::id(), "sol_log_compute_units syscall (#13243)"),
        (pubkey_log_syscall_enabled::id(), "pubkey log syscall"),
        (pull_request_ping_pong_check::id(), "ping-pong packet check #12794"),
        (stake_program_v2::id(), "solana_stake_program v2"),
        (rewrite_stake::id(), "rewrite stake"),
        (filter_stake_delegation_accounts::id(), "filter stake_delegation_accounts #14062"),
        (simple_capitalization::id(), "simple capitalization"),
        (bpf_loader_upgradeable_program::id(), "upgradeable bpf loader"),
        (try_find_program_address_syscall_enabled::id(), "add try_find_program_address syscall"),
        (stake_program_v3::id(), "solana_stake_program v3"),
        (max_cpi_instruction_size_ipv6_mtu::id(), "max cross-program invocation size 1280"),
        (limit_cpi_loader_invoke::id(), "loader not authorized via CPI"),
        (use_loaded_program_accounts::id(), "use loaded program accounts"),
        (abort_on_all_cpi_failures::id(), "abort on all CPI failures"),
        (use_loaded_executables::id(), "use loaded executable accounts"),
        (turbine_retransmit_peers_patch::id(), "turbine retransmit peers patch #14631"),
        (prevent_upgrade_and_invoke::id(), "prevent upgrade and invoke in same tx batch"),
        (track_writable_deescalation::id(), "track account writable deescalation"),
        (require_custodian_for_locked_stake_authorize::id(), "require custodian to authorize withdrawer change for locked stake"),
        (spl_token_v2_self_transfer_fix::id(), "spl-token self-transfer fix"),
        (matching_buffer_upgrade_authorities::id(), "Upgradeable buffer and program authorities must match"),
        (warp_timestamp_again::id(), "warp timestamp again, adjust bounding to 25% fast 80% slow #15204"),
        (per_byte_logging_cost::id(), "charge the compute budget per byte for logging"),
        (check_init_vote_data::id(), "check initialized Vote data"),
        (check_program_owner::id(), "limit programs to operating on accounts owned by itself")
        /*************** ADD NEW FEATURES HERE ***************/
    ]
    .iter()
    .cloned()
    .collect();

    /// Map of feature identifiers to user-visible description
    pub static ref FEATURE_NAMES: HashMap<Pubkey, &'static str> = FEATURE_NAMES_BEFORE_MAINNET.iter().map(|(k,v)| (*k, *v))
    .chain(
        [
            (test_features::id(), "Test feature used as example how to implement features."),
            (velas_hardfork_pack::id(), "EVMblockhashes sysvar history, roothashes calculation. Apply old (reconfigure_native_token, unlock_switch_vote).")
            /*************** ADD NEW FEATURES HERE ***************/
        ]
        .iter()
        .cloned())
    .collect();



    /// Unique identifier of the current software's feature set
    pub static ref ID: Hash = {
        let mut hasher = Hasher::default();
        let mut feature_ids = FEATURE_NAMES.keys().collect::<Vec<_>>();
        feature_ids.sort();
        for feature in feature_ids {
            hasher.hash(feature.as_ref());
        }
        hasher.result()
    };
}

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct FullInflationFeaturePair {
    pub vote_id: Pubkey, // Feature that grants the candidate the ability to enable full inflation
    pub enable_id: Pubkey, // Feature to enable full inflation by the candidate
}

lazy_static! {
    /// Set of feature pairs that once enabled will trigger full inflation
    pub static ref FULL_INFLATION_FEATURE_PAIRS: HashSet<FullInflationFeaturePair> = [
        FullInflationFeaturePair {
            vote_id: full_inflation::mainnet::certusone::vote::id(),
            enable_id: full_inflation::mainnet::certusone::enable::id(),
        },
    ]
    .iter()
    .cloned()
    .collect();
}

/// `FeatureSet` holds the set of currently active/inactive runtime features
#[derive(AbiExample, Debug, Clone)]
pub struct FeatureSet {
    pub active: HashMap<Pubkey, Slot>,
    pub inactive: HashSet<Pubkey>,
}
impl Default for FeatureSet {
    fn default() -> Self {
        // All features disabled
        Self {
            active: HashMap::new(),
            inactive: FEATURE_NAMES.keys().cloned().collect(),
        }
    }
}
impl FeatureSet {
    pub fn is_active(&self, feature_id: &Pubkey) -> bool {
        self.active.contains_key(feature_id)
    }

    pub fn activated_slot(&self, feature_id: &Pubkey) -> Option<Slot> {
        self.active.get(feature_id).copied()
    }

    /// List of enabled features that trigger full inflation
    pub fn full_inflation_features_enabled(&self) -> HashSet<Pubkey> {
        let mut hash_set = FULL_INFLATION_FEATURE_PAIRS
            .iter()
            .filter_map(|pair| {
                if self.is_active(&pair.vote_id) && self.is_active(&pair.enable_id) {
                    Some(pair.enable_id)
                } else {
                    None
                }
            })
            .collect::<HashSet<_>>();

        if self.is_active(&full_inflation::devnet_and_testnet_velas_mainnet::id()) {
            hash_set.insert(full_inflation::devnet_and_testnet_velas_mainnet::id());
        }
        hash_set
    }

    /// All features enabled, useful for testing
    pub fn all_enabled() -> Self {
        Self {
            active: FEATURE_NAMES.keys().cloned().map(|key| (key, 0)).collect(),
            inactive: HashSet::new(),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_full_inflation_features_enabled_devnet_and_testnet_velas_mainnet() {
        let mut feature_set = FeatureSet::default();
        assert!(feature_set.full_inflation_features_enabled().is_empty());
        feature_set
            .active
            .insert(full_inflation::devnet_and_testnet_velas_mainnet::id(), 42);
        assert_eq!(
            feature_set.full_inflation_features_enabled(),
            [full_inflation::devnet_and_testnet_velas_mainnet::id()]
                .iter()
                .cloned()
                .collect()
        );
    }

    #[test]
    fn test_full_inflation_features_enabled() {
        // Normal sequence: vote_id then enable_id
        let mut feature_set = FeatureSet::default();
        assert!(feature_set.full_inflation_features_enabled().is_empty());
        feature_set
            .active
            .insert(full_inflation::mainnet::certusone::vote::id(), 42);
        assert!(feature_set.full_inflation_features_enabled().is_empty());
        feature_set
            .active
            .insert(full_inflation::mainnet::certusone::enable::id(), 42);
        assert_eq!(
            feature_set.full_inflation_features_enabled(),
            [full_inflation::mainnet::certusone::enable::id()]
                .iter()
                .cloned()
                .collect()
        );

        // Backwards sequence: enable_id and then vote_id
        let mut feature_set = FeatureSet::default();
        assert!(feature_set.full_inflation_features_enabled().is_empty());
        feature_set
            .active
            .insert(full_inflation::mainnet::certusone::enable::id(), 42);
        assert!(feature_set.full_inflation_features_enabled().is_empty());
        feature_set
            .active
            .insert(full_inflation::mainnet::certusone::vote::id(), 42);
        assert_eq!(
            feature_set.full_inflation_features_enabled(),
            [full_inflation::mainnet::certusone::enable::id()]
                .iter()
                .cloned()
                .collect()
        );
    }
}
