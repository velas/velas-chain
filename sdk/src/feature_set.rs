//! Collection of all runtime features.
//!
//! Steps to add a new feature are outlined below. Note that these steps only cover
//! the process of getting a feature into the core Solana code.
//! - For features that are unambiguously good (ie bug fixes), these steps are sufficient.
//! - For features that should go up for community vote (ie fee structure changes), more
//!   information on the additional steps to follow can be found at:
//!   <https://spl.solana.com/feature-proposal#feature-proposal-life-cycle>
//!
//! 1. Generate a new keypair with `velas-keygen new --outfile feature.json --no-passphrase`
//!    - Keypairs should be held by core contributors only. If you're a non-core contirbutor going
//!      through these steps, the PR process will facilitate a keypair holder being picked. That
//!      person will generate the keypair, provide pubkey for PR, and ultimately enable the feature.
//! 2. Add a public module for the feature, specifying keypair pubkey as the id with
//!    `solana_sdk::declare_id!()` within the module.
//!    Additionally, add an entry to `FEATURE_NAMES` map.
//! 3. Add desired logic to check for and switch on feature availability.
//!
//! For more information on how features are picked up, see comments for `Feature`.

use {
    lazy_static::lazy_static,
    solana_sdk::{
        clock::Slot,
        hash::{Hash, Hasher},
        pubkey::Pubkey,
    },
    std::collections::{HashMap, HashSet},
};

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

pub mod secp256k1_program_enabled {
    solana_sdk::declare_id!("E3PHP7w8kB7np3CTQ1qQ2tW3KCtjRSXBQgW9vM2mWv2Y");
}

pub mod spl_token_v2_multisig_fix {
    solana_sdk::declare_id!("E5JiFDQCwyC6QfT9REFyMpfK2mHcmv1GUDySU1Ue7TYv");
}

pub mod no_overflow_rent_distribution {
    solana_sdk::declare_id!("4kpdyrcj5jS47CZb2oJGfVxjYbsMm2Kx97gFyZrxxwXz");
}

pub mod filter_stake_delegation_accounts {
    solana_sdk::declare_id!("GE7fRxmW46K6EmCD9AMZSbnaJ2e3LfqCZzdHi9hmYAgi");
}

pub mod require_custodian_for_locked_stake_authorize {
    solana_sdk::declare_id!("D4jsDcXaqdW8tDAWn8H4R25Cdns2YwLneujSL1zvjW6R");
}

pub mod spl_token_v2_self_transfer_fix {
    solana_sdk::declare_id!("BL99GYhdjjcv6ys22C9wPgn2aTVERDbPHHo4NbS3hgp7");
}

pub mod warp_timestamp_again {
    solana_sdk::declare_id!("GvDsGDkH5gyzwpDhxNixx8vtx1kwYHH13RiNAPw27zXb");
}

pub mod check_init_vote_data {
    solana_sdk::declare_id!("3ccR6QpxGYsAbWyfevEtBNGfWV4xBffxRj2tD6A9i39F");
}

pub mod secp256k1_recover_syscall_enabled {
    solana_sdk::declare_id!("AT9Uetzbg1tMtFVF5MyM7GKXPnxYYp2mF4w3quT44TTq");
}

pub mod require_stake_for_gossip {
    solana_sdk::declare_id!("EV8cfTBZfhjNH23qg7xz4TL95f4vKLGoNuG5gJJG85WY");
}

pub mod blake3_syscall_enabled {
    solana_sdk::declare_id!("EPghBhwDZ22GxtS8VGGUvjt782HR9ZG4aFWoBNMxEyxj");
}

pub mod dedupe_config_program_signers {
    solana_sdk::declare_id!("9GPUKsfby7DhKBJYeA4wLKMiPetfYj2himhibLMMDN5c");
}

pub mod deterministic_shred_seed_enabled {
    solana_sdk::declare_id!("44mj7xcpxMWfbdKkmg4nx6uVwJxaLUZG68H7KLgYKUWx");
}

pub mod verify_tx_signatures_len {
    solana_sdk::declare_id!("BBgMBfyF2S8wDdmtJxLAq7JZqAkjm5PbD1FBsZJ5BVha");
}

pub mod vote_stake_checked_instructions {
    solana_sdk::declare_id!("JCbownRcSZnQGT7wH37Coa7mVQ4jrAeXr8m5AvkKPhh5");
}

pub mod neon_evm_compute_budget {
    solana_sdk::declare_id!("ET2UpXAFfZ5AaTda2aNZUsnDbsU2dJJ13iHMx2h6saGM");
}

pub mod rent_for_sysvars {
    solana_sdk::declare_id!("3WrEtnnBhftU7T5gLHP9wQGsydvMJatGsjFSSjbUk6fP");
}

pub mod tx_wide_compute_cap {
    solana_sdk::declare_id!("HPapMaoQExkaFhdMMFuYpfdqPMtMY2ad11WCC256RKwp");
}

pub mod spl_token_v2_set_authority_fix {
    solana_sdk::declare_id!("D242FbFnEvVTxY1bbk5o1Zdk5QBQ82rGQxNurYjKEfL9");
}

pub mod merge_nonce_error_into_system_error {
    solana_sdk::declare_id!("9FgehSu5tsq75Y8gEfnzJjLuxyg8BS4CsWAwPuXAogMi");
}

pub mod disable_fees_sysvar {
    solana_sdk::declare_id!("FTcBZeNTPk4HZnmqVKQET27mDGhyXyn7wbMGAxZJmKmq");
}

pub mod stake_merge_with_unmatched_credits_observed {
    solana_sdk::declare_id!("J5rEzrCKQVa23bG8KQyVCfWhu4py9q7VKw9X6MZ2WKK3");
}

pub mod gate_large_block {
    solana_sdk::declare_id!("4UPG1aJdScuxDkEqD9brENqLk9b9Qpzy69WfXgpZxLPz");
}

pub mod zk_token_sdk_enabled {
    solana_sdk::declare_id!("GeRe1G19482JagxzZ8ug7U6g74shoTLsT4t3Sk7hSJfi");
}

pub mod curve25519_syscall_enabled {
    solana_sdk::declare_id!("8tUrW8mkouRCwgnWvu1bPbQKVQSWBEaPdYZyDE7XVbXD");
}

pub mod versioned_tx_message_enabled {
    solana_sdk::declare_id!("3Xa7Gzhge3vNGr4wEP3NSnafFQPGTySo3bn8SRUr4DeK");
}

pub mod libsecp256k1_fail_on_bad_count {
    solana_sdk::declare_id!("BbZwXnae6nJzbr36LCMduTChw8eTAdDQUHU8gcSzauLW");
}

pub mod instructions_sysvar_owned_by_sysvar {
    solana_sdk::declare_id!("EfbG3kFQFaNuWdrfmK6sZisGWEWhLFmwUdmE4jtxm31d");
}

pub mod stake_program_advance_activating_credits_observed {
    solana_sdk::declare_id!("49x9JGnqdbGfRKRCsJuwZ1e9h3XjuNq5Hk357M1reh22");
}

pub mod demote_program_write_locks {
    solana_sdk::declare_id!("HrjSPBE9Ud4ox7QyM7ZUVu3w6kjpZc6ofQoApT8W5mmL");
}

pub mod ed25519_program_enabled {
    solana_sdk::declare_id!("8cEaqMxTqSxxNEFQ2Wqx8gaZX59RFtFStHkMyEEj1bDY");
}

pub mod return_data_syscall_enabled {
    solana_sdk::declare_id!("Be63DQhVeGApFxP6b6dXjJoiD9ot6RoSnaTTNwiRGgVE");
}

pub mod reduce_required_deploy_balance {
    solana_sdk::declare_id!("5MpaxB8P2qcQ2XUVop3nkEzTXK3usY9NkjvWzDezJP2t");
}

pub mod sol_log_data_syscall_enabled {
    solana_sdk::declare_id!("7ZJWhQSS55aX3McX2KVenrBpG88cxuTrPhH41sjZhPT3");
}

pub mod stakes_remove_delegation_if_inactive {
    solana_sdk::declare_id!("9CcMBCcQJVNL2d9Eg9zcCjin8cP7mf1994f3XQ1jcxTX");
}

pub mod do_support_realloc {
    solana_sdk::declare_id!("FSQCa8sKNTNMM8CFbP83wnmTKx88JNYXLfW23uJ4HLbR");
}

// Note: when this feature is cleaned up, also remove the secp256k1 program from
// the list of builtins and remove its files from /programs
pub mod prevent_calling_precompiles_as_programs {
    solana_sdk::declare_id!("Gi7CTx8yyS67ehMDcqtPC2vy1FdLR7pSKvfUSfUtbNSt");
}

pub mod optimize_epoch_boundary_updates {
    solana_sdk::declare_id!("FWB3jKvsUcd9ECXSeteR8QuPciXeFG8NnsHf3eJhAXWW");
}

pub mod remove_native_loader {
    solana_sdk::declare_id!("GEhtX9GzKX7xTj4ovY1117NGn2Z5gj1nLorvpA3oLMND");
}

pub mod send_to_tpu_vote_port {
    solana_sdk::declare_id!("5BTa7JwJGuxLHqiuympG8XHXnftvriZbAnMNJMyHKZa2");
}

pub mod turbine_peers_shuffle {
    solana_sdk::declare_id!("A2zx9SGayLnSiDLasV2enDRMk8U7CByYxk7RX3SDZoRZ");
}

pub mod requestable_heap_size {
    solana_sdk::declare_id!("9xCNKScHp2wRYhVtVE4S2j6qtANrQzvHheZ68LP6ptu1");
}

pub mod disable_fee_calculator {
    solana_sdk::declare_id!("FWvU5UkjD3HvpK1N9YG1zRu4ZkLzduySUrCiezcKeBL7");
}

pub mod add_compute_budget_program {
    solana_sdk::declare_id!("62xudn7B3zNEMUZ57Tdk2HdDBeYpgPBF8YuCGkPkukxG");
}

pub mod nonce_must_be_writable {
    solana_sdk::declare_id!("6Gx36JjLJnx5dZacxXwJCUGgvyxXiZgntjrsFqdSeCEv");
}

pub mod spl_token_v3_3_0_release {
    solana_sdk::declare_id!("4DmZWdTk1Qxff4LjVDLRdpec3ir6JXGCi3K8LuBD1T3z");
}

pub mod leave_nonce_on_success {
    solana_sdk::declare_id!("DnkEdU3PuZ3QmcMfd38YfGPXv7PZgZjFiDp4eiURexRK");
}

pub mod reject_empty_instruction_without_program {
    solana_sdk::declare_id!("EdVMAajAR6DjxfBr22ZsVqh2N8x6WNThJ8DVkyqwXQKQ");
}

pub mod reject_non_rent_exempt_vote_withdraws {
    solana_sdk::declare_id!("8cZEsHN41GrFnAp98ivJzUU33caKKnsyjWXPCT7R1VMx");
}

pub mod evict_invalid_stakes_cache_entries {
    solana_sdk::declare_id!("HMFbRJdZaMsMyVAtCwmDyZuYxfE9rYfomwfK3GHs4V6b");
}

pub mod cap_accounts_data_len {
    solana_sdk::declare_id!("3GnCXHAKJfVQjB8KwHP1xuv8HWYKFTPCvWShye5Ufsqa");
}

pub mod max_tx_account_locks {
    solana_sdk::declare_id!("BTSCj81SqxphCDsMSrxa5a71ZLw9bTvAvMY2PTYsTSP3");
}

pub mod require_rent_exempt_accounts {
    solana_sdk::declare_id!("84ADcpnDQGVJfDkPRNYPtuX7gZgDr9ZZ8RS4h4RQ9Fnp");
}

pub mod vote_withdraw_authority_may_change_authorized_voter {
    solana_sdk::declare_id!("5EW4kCw6LMLcmkC7fqqd7pky6732Mf3kSM7u9EZeVtdd");
}

pub mod spl_associated_token_account_v1_0_4 {
    solana_sdk::declare_id!("G8M9wV8KjHUJfeAfHXejV6uiMVnwJygtJWwWMBje7yDx");
}

pub mod update_syscall_base_costs {
    solana_sdk::declare_id!("Eb5dHhEtkVggr98SffmPJ8C6Y9gvGqngM39aKg8rrFDp");
}

pub mod reject_vote_account_close_unless_zero_credit_epoch {
    solana_sdk::declare_id!("FzCCojixUktU4qbkWVEEjrDimqNajd1YyW1Wto4FMoB3");
}

pub mod bank_tranaction_count_fix {
    solana_sdk::declare_id!("7DeeVjqtgV4FYMrwcwoMRPCTKv8As4Y97yvRzDeuMk4u");
}

pub mod disable_bpf_deprecated_load_instructions {
    solana_sdk::declare_id!("vA5qCgRAjvcTgFoC53CrDNaZguZz7LCgJrwAfUZSBnb");
}

pub mod disable_bpf_unresolved_symbols_at_runtime {
    solana_sdk::declare_id!("87s91NBpVNcTCihzKAr44Mjgu7rNx1dEi9EVGuY4MZnN");
}

pub mod add_get_processed_sibling_instruction_syscall {
    solana_sdk::declare_id!("BQXp78AatCdBGWSByQMELkPptQHtS8dcDJTqrzYcTji3");
}

pub mod fixed_memcpy_nonoverlapping_check {
    solana_sdk::declare_id!("D5YEM15Fgox3JFqCGFRgnwqAcJ2QtB6MiJMAm7B38sQ3");
}

pub mod drop_redundant_turbine_path {
    solana_sdk::declare_id!("9e9RFVCfsBA19iJ6w7v7w5gvoEP8C2SVMxCgRZNKEVaX");
}

pub mod default_units_per_instruction {
    solana_sdk::declare_id!("HLtQsLVVBaCL3YYwt6UsH9gWoPHB285hTiYMa4rFpBbp");
}

pub mod add_shred_type_to_shred_seed {
    solana_sdk::declare_id!("D63CT5jtNMSTnNmKvVdd22NTbGiW9DgZEowaAPFsDvD3");
}

pub mod warp_timestamp_with_a_vengeance {
    solana_sdk::declare_id!("76k5t7davqtAHxLc4f84W7KVnwgUEBgeg6JxxrixE5jF");
}

pub mod separate_nonce_from_blockhash {
    solana_sdk::declare_id!("HRXtnwaMAwH9b2P8jT4CpvChk3Tj5wbuQaLLKcuKz3vb");
}

pub mod enable_durable_nonce {
    solana_sdk::declare_id!("m1HeqS9BpDqJ6NUu8oUgFxes1DZWQB1pbchbwmWTbyo");
}

pub mod nonce_must_be_authorized {
    solana_sdk::declare_id!("2xLqXg2nj3UpdNonMxkwc6DBxmjPiyNYAWLh2NuHzNuk");
}

pub mod nonce_must_be_advanceable {
    solana_sdk::declare_id!("4ViDUMd1axFfJxWViMkZ2nwdbYGxHer1MhoT3igGasPj");
}

pub mod cpi_data_cost {
    solana_sdk::declare_id!("CuYeffE36Bed4qExko1XwUDHB2b6TJ9pwphXw52Nm9UB");
}

pub mod upgradeable_close_instruction {
    solana_sdk::declare_id!("8CiKcDAct4LY4FZgzTv2tcAi1PkNW2P1JFzaS28tpFzB");
}

pub mod demote_sysvar_write_locks {
    solana_sdk::declare_id!("6LDeGYz9iqbscuLrMYpZxeifFZWDzXL7n7zS6syaCDJ8");
}

pub mod sysvar_via_syscall {
    solana_sdk::declare_id!("2bfZ6cxMn5yJ5cf3T8J3zSoraYPe9V9iMSab1gNiRERr");
}

pub mod check_duplicates_by_hash {
    solana_sdk::declare_id!("AjSWo5fdpbo2Xy2G8Xbjhythe42MQci3CV8FuJ9cpi9d");
}

pub mod enforce_aligned_host_addrs {
    solana_sdk::declare_id!("5GDsuYGNKRRKE2tTpid7aGRixfryAVBz2MPHzSJexwyp");
}
pub mod set_upgrade_authority_via_cpi_enabled {
    solana_sdk::declare_id!("3n34oY4kEma7jNGGsu4btRteisnqqHGmSEZNJpz3A8cU");
}

pub mod update_data_on_realloc {
    solana_sdk::declare_id!("23wrJ1vCGMbugM14C5vgXxP1trJbKSzK52MnMzWBtQQ4");
}

pub mod keccak256_syscall_enabled {
    solana_sdk::declare_id!("DtDVADxBHPQpPUuXunL4tRik4fx9YiSQTHa5H1hXHksc");
}

pub mod stake_program_v4 {
    solana_sdk::declare_id!("cug7ESsYA4ma7iE1y4qgi5zsdKyo6KJ1NyS5K4CVEE3");
}

pub mod system_transfer_zero_check {
    solana_sdk::declare_id!("EqohBJpJsJym3qAJ3N7AH35c4u2rfS5yYvS693ThYTbG");
}

pub mod velas {
    pub mod hardfork_pack {
        // 1. difficulty not a hash but a number.
        // 2. transactionRoot, receiptRoot - should calculate, and empty hashes should be setted too
        // 3. nonce is 64bit hash not a number.
        // 4. sha3uncle hash from zero block, not zeros.
        solana_sdk::declare_id!("91nakVjUc5UmNzLioE6K7HhASmb2m1E7hRuLZS4LzUPV");
    }

    pub mod evm_cross_execution {
        solana_sdk::declare_id!("3rkhJCKKR8Szj5v237NzRF3FS2nnyRvaeGF8xAvnVkwf");
    }

    pub mod native_swap_in_evm_history {
        solana_sdk::declare_id!("8h8BTnexqgpfiA8E6Bx8JT97asTPDGBPwhBR98x1Z5cW");
    }
    pub mod evm_new_error_handling {
        solana_sdk::declare_id!("9HscytNCkVfhQYuVbKGdicUzk6zGjRVtwXXbo1b6spRG");
    }

    pub mod unsigned_tx_fix {
        solana_sdk::declare_id!("HfCMpyxjAmu7sPtRdnqdrTf3zDpkErKugzYPnKs4vhat");
    }

    pub mod ignore_reset_on_cleared {
        solana_sdk::declare_id!("HC6ZH7Dx92Q5dwVLYAaK3SPNCDc1L7Wq41Zuc7FU1mR1");
    }

    pub mod free_ownership_require_signer {
        solana_sdk::declare_id!("3zdr7CPgRJegSXMQrSVvAMXvGFPyRKmuLdajCXnbrXNL");
    }

    pub mod burn_fee {
        solana_sdk::declare_id!("CjdrowBMM3drcSSciwPVpAWz4hBqWAKSLj9Ea9PD1vip");
    }

    pub mod clear_logs_on_error {
        solana_sdk::declare_id!("9rZZ68tcDSZYkDMuFn59iRzoUxki2r16RWUucZQywFzS");
    }

    pub mod disable_durable_nonce {
        solana_sdk::declare_id!("AKAGpT85PfoGDxCBPsxGHy8iZdaJoeAiVXq5oRxFS5TL");
    }

    pub mod evm_instruction_borsh_serialization {
        solana_sdk::declare_id!("9NUVkN3PYJXz6z8cUgtGHYWd1CmcYF7ci3a552rASPQw");
    }

    pub mod evm_new_precompiles {
        solana_sdk::declare_id!("4NLsdp3QnxQaERdfVqSMDczFQLeLokqGXBWpp1EJVLme");
    }

    pub mod accept_zero_gas_price_with_native_fee {
        solana_sdk::declare_id!("H4xTVSJMFSzWSoi6JuunAJSn8EJxHtJHWYDb3yDpuvU3");
    }

    pub mod clear_logs_on_native_error {
        solana_sdk::declare_id!("BVF8r9JP1is4YworaZsiEk6fCSTiDxvD59Eo9kFyc85F");
    }
}

pub mod allow_votes_to_directly_update_vote_state {
    solana_sdk::declare_id!("59ERyBwB4c87P6pL2YNk5TWZywoAfzJ4WJUZ38v62puF");
}

pub mod filter_votes_outside_slot_hashes {
    solana_sdk::declare_id!("2p7vj6Na47DnnsnugbWaecmncuQbowCv6jenCAFkapvJ");
}

pub mod record_instruction_in_transaction_context_push {
    solana_sdk::declare_id!("2Kr6HBCte7zNtdy5YyqJHuEEy9uATzda854Wn5TCTH3e");
}

pub mod syscall_saturated_math {
    solana_sdk::declare_id!("BmrsJ15d3B8fe4qkCtkRYaBFBURCJJaoPekdfTjWhXJ7");
}

pub mod check_physical_overlapping {
    solana_sdk::declare_id!("5uJVX3r8R5nRhtDqTEe8DW2pW9mf2ANxHrTq1JrAtxP4");
}

pub mod limit_secp256k1_recovery_id {
    solana_sdk::declare_id!("3KgbRjKx7FN37RVBdsoKzhx54p5orCCR7bcLTNZDTSBV");
}

pub mod disable_deprecated_loader {
    solana_sdk::declare_id!("94JS29AXMyKkexM4YEb4sqg4jCGE63Bx97cMTU3vJTcL");
}

pub mod spl_token_v3_4_0 {
    solana_sdk::declare_id!("Fd3rWCAN3NXtVh5UEbqVc3fsvG88rToPuuojaUqRm7yj");
}

pub mod spl_associated_token_account_v1_1_0 {
    solana_sdk::declare_id!("7DphuBjvTCyhhnsmVEe6FoV7HUDBoQL9UsTFv2PC4gBs");
}

pub mod stake_allow_zero_undelegated_amount {
    solana_sdk::declare_id!("HBwktH2TaM1GgfvN83wZKzsouPSaVvVKj6Sc3qCtfedH");
}

pub mod require_static_program_ids_in_transaction {
    solana_sdk::declare_id!("59UWyKDb8pqs6h79kXCwvkBuHBSmk2MHDJQDc6Th6H4L");
}

pub mod add_set_compute_unit_price_ix {
    solana_sdk::declare_id!("F7qkNWKiDG5iBV1ivneq7uB5G94dWiWuDbEk3fimo7iy");
}

pub mod include_account_index_in_rent_error {
    solana_sdk::declare_id!("HPYA1bUYArG5tS4CgALXMHBmhvUmHfky6LHid6wxujFr");
}

pub mod executables_incur_cpi_data_cost {
    solana_sdk::declare_id!("AdLPpPEFvKCJwXBzvqYLRQkAqCM21tV5rap9G6CwZuUn");
}

pub mod quick_bail_on_panic {
    solana_sdk::declare_id!("HCmiJRZamjFewgrXfY39GHa9MACtsSDyNQ2zyhfU3t6X");
}

pub mod vote_authorize_with_seed {
    solana_sdk::declare_id!("7GAy3vA2H7R1nHQfXtVBX7QqmanAycJpJhs4sZe4Rg7r");
}

pub mod cap_accounts_data_size_per_block {
    solana_sdk::declare_id!("F6a2Qe7ak47XLfkjfkWmDYZPathZ3YCNfz6LS1rNiC23");
}

pub mod preserve_rent_epoch_for_rent_exempt_accounts {
    solana_sdk::declare_id!("6fX6HE3HvuEh5mX9StqDas1X523WCMa1b9qM37ZJPPRL");
}

pub mod prevent_crediting_accounts_that_end_rent_paying {
    solana_sdk::declare_id!("96NdMoPxigEwEeGZCCDWTMqXUyZyUuvVTFaVsdenkwmD");
}

pub mod sign_repair_requests {
    solana_sdk::declare_id!("GVEj117ucvHxL7LfqaCTbZF9JscAMXYcECsa9Pu1f7e3");
}

pub mod return_none_for_zero_lamport_accounts {
    solana_sdk::declare_id!("BFez6hGLRwm8dNx1uVCX5Xjq2e7XiGje1vrRD8UtfrYU");
}

pub mod increase_tx_account_lock_limit {
    solana_sdk::declare_id!("4pfVvtTJWz5FE8aZYJYjjipavxkoRuuoJnQEUZvKHvs9");
}

lazy_static! {
    /// Map of feature identifiers to user-visible description
    pub static ref FEATURE_NAMES_BEFORE_MAINNET: HashMap<Pubkey, &'static str> = [
        // (instructions_sysvar_enabled::id(), "instructions sysvar"),
        // (check_program_owner::id(), "limit programs to operating on accounts owned by itself"),
        (secp256k1_program_enabled::id(), "secp256k1 program"),
        (deprecate_rewards_sysvar::id(), "deprecate unused rewards sysvar"),
        (pico_inflation::id(), "pico inflation"),
        (full_inflation::devnet_and_testnet_velas_mainnet::id(), "full inflation on devnet and testnet"),
        (spl_token_v2_multisig_fix::id(), "spl-token multisig fix"),
        (no_overflow_rent_distribution::id(), "no overflow rent distribution"),
        (filter_stake_delegation_accounts::id(), "filter stake_delegation_accounts #14062"),
        (require_custodian_for_locked_stake_authorize::id(), "require custodian to authorize withdrawer change for locked stake"),
        (spl_token_v2_self_transfer_fix::id(), "spl-token self-transfer fix"),
        (warp_timestamp_again::id(), "warp timestamp again, adjust bounding to 25% fast 80% slow #15204"),
        (check_init_vote_data::id(), "check initialized Vote data"),
        /*************** ADD NEW FEATURES HERE ***************/
    ]
        .iter()
        .copied()
        .collect();

    pub static ref FEATURE_NAMES: HashMap<Pubkey, &'static str> = FEATURE_NAMES_BEFORE_MAINNET.iter().map(|(k, v)| (*k, *v)).chain(
        [
            // Solana new features
            (require_stake_for_gossip::id(), "require stakes for propagating crds values through gossip #15561"),
            (cpi_data_cost::id(), "charge the compute budget for data passed via CPI"),
            (upgradeable_close_instruction::id(), "close upgradeable buffer accounts"),
            (demote_sysvar_write_locks::id(), "demote builtins and sysvar write locks to readonly #15497"),
            (sysvar_via_syscall::id(), "provide sysvars via syscalls"),
            (check_duplicates_by_hash::id(), "use transaction message hash for duplicate check"),
            (enforce_aligned_host_addrs::id(), "enforce aligned host addresses"),
            (update_data_on_realloc::id(), "Retain updated data values modified after realloc via CPI"),
            (set_upgrade_authority_via_cpi_enabled::id(), "set upgrade authority instruction via cpi calls for upgradable programs"),
            (keccak256_syscall_enabled::id(), "keccak256 syscall"),
            (system_transfer_zero_check::id(), "perform all checks for transfers of 0 lamports"),
            (full_inflation::mainnet::certusone::enable::id(), "full inflation enabled by Certus One"),
            (secp256k1_recover_syscall_enabled::id(), "secp256k1_recover syscall"),
            (blake3_syscall_enabled::id(), "blake3 syscall"),
            (dedupe_config_program_signers::id(), "dedupe config program signers"),
            (verify_tx_signatures_len::id(), "prohibit extra transaction signatures"),
            (vote_stake_checked_instructions::id(), "vote/state program checked instructions #18345"),
            (neon_evm_compute_budget::id(), "bump neon_evm's compute budget"),
            (rent_for_sysvars::id(), "collect rent from accounts owned by sysvars"),
            (tx_wide_compute_cap::id(), "transaction wide compute cap"),
            (spl_token_v2_set_authority_fix::id(), "spl-token set_authority fix"),
            (merge_nonce_error_into_system_error::id(), "merge NonceError into SystemError"),
            (disable_fees_sysvar::id(), "disable fees sysvar"),
            (stake_merge_with_unmatched_credits_observed::id(), "allow merging active stakes with unmatched credits_observed #18985"),
            (gate_large_block::id(), "validator checks block cost against max limit in realtime, reject if exceeds."),
            (zk_token_sdk_enabled::id(), "enable Zk Token proof program and syscalls"),
            (curve25519_syscall_enabled::id(), "enable curve25519 syscalls"),
            (versioned_tx_message_enabled::id(), "enable versioned transaction message processing"),
            (libsecp256k1_fail_on_bad_count::id(), "fail libsec256k1_verify if count appears wrong"),
            (instructions_sysvar_owned_by_sysvar::id(), "fix owner for instructions sysvar"),
            (stake_program_advance_activating_credits_observed::id(), "Enable advancing credits observed for activation epoch #19309"),
            (demote_program_write_locks::id(), "demote program write locks to readonly, except when upgradeable loader present #19593 #20265"),
            (ed25519_program_enabled::id(), "enable builtin ed25519 signature verify program"),
            (return_data_syscall_enabled::id(), "enable sol_{set,get}_return_data syscall"),
            (reduce_required_deploy_balance::id(), "reduce required payer balance for program deploys"),
            (sol_log_data_syscall_enabled::id(), "enable sol_log_data syscall"),
            (stakes_remove_delegation_if_inactive::id(), "remove delegations from stakes cache when inactive"),
            (do_support_realloc::id(), "support account data reallocation"),
            (prevent_calling_precompiles_as_programs::id(), "prevent calling precompiles as programs"),
            (optimize_epoch_boundary_updates::id(), "optimize epoch boundary updates"),
            (remove_native_loader::id(), "remove support for the native loader"),
            (send_to_tpu_vote_port::id(), "send votes to the tpu vote port"),
            (requestable_heap_size::id(), "Requestable heap frame size"),
            (disable_fee_calculator::id(), "deprecate fee calculator"),
            (add_compute_budget_program::id(), "Add compute_budget_program"),
            (nonce_must_be_writable::id(), "nonce must be writable"),
            (spl_token_v3_3_0_release::id(), "spl-token v3.3.0 release"),
            (leave_nonce_on_success::id(), "leave nonce as is on success"),
            (reject_empty_instruction_without_program::id(), "fail instructions which have native_loader as program_id directly"),
            (fixed_memcpy_nonoverlapping_check::id(), "use correct check for nonoverlapping regions in memcpy syscall"),
            (reject_non_rent_exempt_vote_withdraws::id(), "fail vote withdraw instructions which leave the account non-rent-exempt"),
            (evict_invalid_stakes_cache_entries::id(), "evict invalid stakes cache entries on epoch boundaries"),
            (allow_votes_to_directly_update_vote_state::id(), "enable direct vote state update"),
            (cap_accounts_data_len::id(), "cap the accounts data len"),
            (max_tx_account_locks::id(), "enforce max number of locked accounts per transaction"),
            (require_rent_exempt_accounts::id(), "require all new transaction accounts with data to be rent-exempt"),
            (filter_votes_outside_slot_hashes::id(), "filter vote slots older than the slot hashes history"),
            (update_syscall_base_costs::id(), "update syscall base costs"),
            (vote_withdraw_authority_may_change_authorized_voter::id(), "vote account withdraw authority may change the authorized voter #22521"),
            (spl_associated_token_account_v1_0_4::id(), "SPL Associated Token Account Program release version 1.0.4, tied to token 3.3.0 #22648"),
            (update_syscall_base_costs::id(), "Update syscall base costs"),
            (reject_vote_account_close_unless_zero_credit_epoch::id(), "fail vote account withdraw to 0 unless account earned 0 credits in last completed epoch"),
            (add_get_processed_sibling_instruction_syscall::id(), "add add_get_processed_sibling_instruction_syscall"),
            (bank_tranaction_count_fix::id(), "Fixes Bank::transaction_count to include all committed transactions, not just successful ones"),
            (disable_bpf_deprecated_load_instructions::id(), "Disable ldabs* and ldind* BPF instructions"),
            (disable_bpf_unresolved_symbols_at_runtime::id(), "Disable reporting of unresolved BPF symbols at runtime"),
            (add_get_processed_sibling_instruction_syscall::id(), "add add_get_processed_sibling_instruction_syscall"),
            (record_instruction_in_transaction_context_push::id(), "move the CPI stack overflow check to the end of push"),
            (fixed_memcpy_nonoverlapping_check::id(), "use correct check for nonoverlapping regions in memcpy syscall"),
            (syscall_saturated_math::id(), "syscalls use saturated math"),
            (check_physical_overlapping::id(), "check physical overlapping regions"),
            (limit_secp256k1_recovery_id::id(), "limit secp256k1 recovery id"),
            (disable_deprecated_loader::id(), "disable the deprecated BPF loader"),
            (drop_redundant_turbine_path::id(), "drop redundant turbine path"),
            (spl_token_v3_4_0::id(), "SPL Token Program version 3.4.0 release #24740"),
            (spl_associated_token_account_v1_1_0::id(), "SPL Associated Token Account Program version 1.1.0 release #24741"),
            (default_units_per_instruction::id(), "Default max tx-wide compute units calculated per instruction"),
            (stake_allow_zero_undelegated_amount::id(), "Allow zero-lamport undelegated amount for initialized stakes #24670"),
            (require_static_program_ids_in_transaction::id(), "require static program ids in versioned transactions"),
            (add_set_compute_unit_price_ix::id(), "add compute budget ix for setting a compute unit price"),
            (include_account_index_in_rent_error::id(), "include account index in rent tx error #25190"),
            (add_shred_type_to_shred_seed::id(), "add shred-type to shred seed #25556"),
            (warp_timestamp_with_a_vengeance::id(), "warp timestamp again, adjust bounding to 150% slow #25666"),
            (separate_nonce_from_blockhash::id(), "separate durable nonce and blockhash domains #25744"),
            (enable_durable_nonce::id(), "enable durable nonce #25744"),
            (executables_incur_cpi_data_cost::id(), "Executables incure CPI data costs"),
            (quick_bail_on_panic::id(), "quick bail on panic"),
            (nonce_must_be_authorized::id(), "nonce must be authorized"),
            (nonce_must_be_advanceable::id(), "durable nonces must be advanceable"),
            (vote_authorize_with_seed::id(), "An instruction you can use to change a vote accounts authority when the current authority is a derived key #25860"),
            (cap_accounts_data_size_per_block::id(), "cap the accounts data size per block #25517"),
            (preserve_rent_epoch_for_rent_exempt_accounts::id(), "preserve rent epoch for rent exempt accounts #26479"),
            (prevent_crediting_accounts_that_end_rent_paying::id(), "prevent crediting rent paying accounts #26606"),
            (sign_repair_requests::id(), "sign repair requests #26834"),
            (return_none_for_zero_lamport_accounts::id(), "return none for zero lamport accounts #27800"),
            (increase_tx_account_lock_limit::id(), "increase tx account lock limit to 128 #27241"),

            // Velas features
            (velas::hardfork_pack::id(), "EVMblockhashes sysvar history, roothashes calculation. Apply old (reconfigure_native_token, unlock_switch_vote)."),
            (velas::evm_cross_execution::id(), "EVM cross execution."),
            (velas::native_swap_in_evm_history::id(), "Native swap in evm history."),
            (velas::evm_new_error_handling::id(), "EVM new error handling."),
            (velas::unsigned_tx_fix::id(), "Authorized transaction hash fixed."),
            (velas::ignore_reset_on_cleared::id(), "Don't reset evm_swap address balance, when it already swapped, to avoid empty blocks."),
            (velas::free_ownership_require_signer::id(), "Free ownership require signer."),
            (velas::burn_fee::id(), "Burn fee during transaction execution."),
            (velas::clear_logs_on_error::id(), "Clear logs from receipt if transaction is failed or reverted."),
            (velas::disable_durable_nonce::id(), "Disable durable nonce."),
            (velas::evm_new_precompiles::id(), "Evm new precomplies pack."),
            (velas::evm_instruction_borsh_serialization::id(), "Support for Borsh serialization for EVM instructions."),
            (velas::accept_zero_gas_price_with_native_fee::id(), "Accept evm transactions with native fee and zero gas price."),
            (velas::clear_logs_on_native_error::id(), "Clear evm logs from receipt if native transaction is failed."),
            /*************** ADD NEW FEATURES HERE ***************/
        ]
    ).collect();


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

    /// Activate a feature
    pub fn activate(&mut self, feature_id: &Pubkey, slot: u64) {
        self.inactive.remove(feature_id);
        self.active.insert(*feature_id, slot);
    }

    /// Deactivate a feature
    pub fn deactivate(&mut self, feature_id: &Pubkey) {
        self.active.remove(feature_id);
        self.inactive.insert(*feature_id);
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_full_inflation_features_enabled_devnet_and_testnet() {
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

    #[test]
    fn test_feature_set_activate_deactivate() {
        let mut feature_set = FeatureSet::default();

        let feature = Pubkey::new_unique();
        assert!(!feature_set.is_active(&feature));
        feature_set.activate(&feature, 0);
        assert!(feature_set.is_active(&feature));
        feature_set.deactivate(&feature);
        assert!(!feature_set.is_active(&feature));
    }
}
