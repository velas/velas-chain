use crate::{
    cluster_info::ClusterInfo, contact_info::ContactInfo, epoch_slots::EpochSlots,
    serve_repair::RepairType,
};
use solana_runtime::{bank_forks::BankForks, epoch_stakes::NodeIdToVoteAccounts};
use solana_sdk::{clock::Slot, pubkey::Pubkey};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    sync::{Arc, RwLock},
};

// Limit the size of cluster-slots map in case
// of receiving bogus epoch slots values.
const CLUSTER_SLOTS_TRIM_SIZE: usize = 524_288; // 512K

pub type SlotPubkeys = HashMap<Pubkey, u64>;

#[derive(Default)]
pub struct ClusterSlots {
    cluster_slots: RwLock<BTreeMap<Slot, Arc<RwLock<SlotPubkeys>>>>,
    since: RwLock<Option<u64>>,
    validator_stakes: RwLock<Arc<NodeIdToVoteAccounts>>,
    epoch: RwLock<Option<u64>>,
    self_id: RwLock<Pubkey>,
}

impl ClusterSlots {
    pub fn lookup(&self, slot: Slot) -> Option<Arc<RwLock<SlotPubkeys>>> {
        self.cluster_slots.read().unwrap().get(&slot).cloned()
    }
    pub fn update(&self, root: Slot, cluster_info: &ClusterInfo, bank_forks: &RwLock<BankForks>) {
        self.update_peers(cluster_info, bank_forks);
        let since = *self.since.read().unwrap();
        let (epoch_slots, since) = cluster_info.get_epoch_slots_since(since);
        self.update_internal(root, epoch_slots, since);
    }
    fn update_internal(&self, root: Slot, epoch_slots_list: Vec<EpochSlots>, since: Option<u64>) {
        for epoch_slots in epoch_slots_list {
            let slots = epoch_slots.to_slots(root);
            for slot in &slots {
                if *slot <= root {
                    continue;
                }
                self.insert_node_id(*slot, epoch_slots.from);
            }
        }
        {
            let mut cluster_slots = self.cluster_slots.write().unwrap();
            *cluster_slots = cluster_slots.split_off(&(root + 1));
            // Trimming is done at 2x size so that amortized it has a constant
            // cost. The slots furthest away from the root are discarded.
            if cluster_slots.len() > 2 * CLUSTER_SLOTS_TRIM_SIZE {
                let key = *cluster_slots.keys().nth(CLUSTER_SLOTS_TRIM_SIZE).unwrap();
                cluster_slots.split_off(&key);
            }
        }
        *self.since.write().unwrap() = since;
    }

    pub fn collect(&self, id: &Pubkey) -> HashSet<Slot> {
        self.cluster_slots
            .read()
            .unwrap()
            .iter()
            .filter(|(_, keys)| keys.read().unwrap().contains_key(id))
            .map(|(slot, _)| *slot)
            .collect()
    }

    pub fn insert_node_id(&self, slot: Slot, node_id: Pubkey) {
        let balance = self
            .validator_stakes
            .read()
            .unwrap()
            .get(&node_id)
            .map(|v| v.total_stake)
            .unwrap_or(0);
        let slot_pubkeys = self
            .cluster_slots
            .write()
            .unwrap()
            .entry(slot)
            .or_default()
            .clone();
        slot_pubkeys.write().unwrap().insert(node_id, balance);
    }

    fn update_peers(&self, cluster_info: &ClusterInfo, bank_forks: &RwLock<BankForks>) {
        let root_bank = bank_forks.read().unwrap().root_bank();
        let root_epoch = root_bank.epoch();
        let my_epoch = *self.epoch.read().unwrap();

        if Some(root_epoch) != my_epoch {
            let validator_stakes = root_bank
                .epoch_stakes(root_epoch)
                .expect(
                    "Bank must have epoch stakes
                for its own epoch",
                )
                .node_id_to_vote_accounts()
                .clone();

            *self.validator_stakes.write().unwrap() = validator_stakes;
            let id = cluster_info.id();
            *self.self_id.write().unwrap() = id;
            *self.epoch.write().unwrap() = Some(root_epoch);
        }
    }

    pub fn compute_weights(&self, slot: Slot, repair_peers: &[ContactInfo]) -> Vec<u64> {
        let stakes = {
            let validator_stakes = self.validator_stakes.read().unwrap();
            repair_peers
                .iter()
                .map(|peer| {
                    validator_stakes
                        .get(&peer.id)
                        .map(|node| node.total_stake)
                        .unwrap_or(0)
                        + 1
                })
                .collect()
        };
        let slot_peers = match self.lookup(slot) {
            None => return stakes,
            Some(slot_peers) => slot_peers,
        };
        let slot_peers = slot_peers.read().unwrap();
        repair_peers
            .iter()
            .map(|peer| slot_peers.get(&peer.id).cloned().unwrap_or(0))
            .zip(stakes)
            .map(|(a, b)| a + b)
            .collect()
    }

    pub fn compute_weights_exclude_noncomplete(
        &self,
        slot: Slot,
        repair_peers: &[ContactInfo],
    ) -> Vec<(u64, usize)> {
        let slot_peers = self.lookup(slot);
        repair_peers
            .iter()
            .enumerate()
            .filter_map(|(i, x)| {
                slot_peers
                    .as_ref()
                    .and_then(|v| v.read().unwrap().get(&x.id).map(|stake| (*stake + 1, i)))
            })
            .collect()
    }

    pub fn generate_repairs_for_missing_slots(
        &self,
        self_id: &Pubkey,
        root: Slot,
    ) -> Vec<RepairType> {
        let my_slots = self.collect(self_id);
        self.cluster_slots
            .read()
            .unwrap()
            .keys()
            .filter(|x| **x > root)
            .filter(|x| !my_slots.contains(*x))
            .map(|x| RepairType::HighestShred(*x, 0))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use solana_runtime::epoch_stakes::NodeVoteAccounts;

    #[test]
    fn test_default() {
        let cs = ClusterSlots::default();
        assert!(cs.cluster_slots.read().unwrap().is_empty());
        assert!(cs.since.read().unwrap().is_none());
    }

    #[test]
    fn test_update_noop() {
        let cs = ClusterSlots::default();
        cs.update_internal(0, vec![], None);
        assert!(cs.cluster_slots.read().unwrap().is_empty());
        assert!(cs.since.read().unwrap().is_none());
    }

    #[test]
    fn test_update_empty() {
        let cs = ClusterSlots::default();
        let epoch_slot = EpochSlots::default();
        cs.update_internal(0, vec![epoch_slot], Some(0));
        assert_eq!(*cs.since.read().unwrap(), Some(0));
        assert!(cs.lookup(0).is_none());
    }

    #[test]
    fn test_update_rooted() {
        //root is 0, so it should clear out the slot
        let cs = ClusterSlots::default();
        let mut epoch_slot = EpochSlots::default();
        epoch_slot.fill(&[0], 0);
        cs.update_internal(0, vec![epoch_slot], Some(0));
        assert_eq!(*cs.since.read().unwrap(), Some(0));
        assert!(cs.lookup(0).is_none());
    }

    #[test]
    fn test_update_new_slot() {
        let cs = ClusterSlots::default();
        let mut epoch_slot = EpochSlots::default();
        epoch_slot.fill(&[1], 0);
        cs.update_internal(0, vec![epoch_slot], Some(0));
        assert_eq!(*cs.since.read().unwrap(), Some(0));
        assert!(cs.lookup(0).is_none());
        assert!(cs.lookup(1).is_some());
        assert_eq!(
            cs.lookup(1)
                .unwrap()
                .read()
                .unwrap()
                .get(&Pubkey::default()),
            Some(&0)
        );
    }

    #[test]
    fn test_compute_weights() {
        let cs = ClusterSlots::default();
        let ci = ContactInfo::default();
        assert_eq!(cs.compute_weights(0, &[ci]), vec![1]);
    }

    #[test]
    fn test_best_peer_2() {
        let cs = ClusterSlots::default();
        let mut c1 = ContactInfo::default();
        let mut c2 = ContactInfo::default();
        let mut map = HashMap::new();
        let k1 = solana_sdk::pubkey::new_rand();
        let k2 = solana_sdk::pubkey::new_rand();
        map.insert(k1, std::u64::MAX / 2);
        map.insert(k2, 0);
        cs.cluster_slots
            .write()
            .unwrap()
            .insert(0, Arc::new(RwLock::new(map)));
        c1.id = k1;
        c2.id = k2;
        assert_eq!(
            cs.compute_weights(0, &[c1, c2]),
            vec![std::u64::MAX / 2 + 1, 1]
        );
    }

    #[test]
    fn test_best_peer_3() {
        let cs = ClusterSlots::default();
        let mut c1 = ContactInfo::default();
        let mut c2 = ContactInfo::default();
        let mut map = HashMap::new();
        let k1 = solana_sdk::pubkey::new_rand();
        let k2 = solana_sdk::pubkey::new_rand();
        map.insert(k2, 0);
        cs.cluster_slots
            .write()
            .unwrap()
            .insert(0, Arc::new(RwLock::new(map)));
        //make sure default weights are used as well
        let validator_stakes: HashMap<_, _> = vec![(
            k1,
            NodeVoteAccounts {
                total_stake: std::u64::MAX / 2,
                vote_accounts: vec![Pubkey::default()],
            },
        )]
        .into_iter()
        .collect();
        *cs.validator_stakes.write().unwrap() = Arc::new(validator_stakes);
        c1.id = k1;
        c2.id = k2;
        assert_eq!(
            cs.compute_weights(0, &[c1, c2]),
            vec![std::u64::MAX / 2 + 1, 1]
        );
    }

    #[test]
    fn test_best_completed_slot_peer() {
        let cs = ClusterSlots::default();
        let mut contact_infos = vec![ContactInfo::default(); 2];
        for ci in contact_infos.iter_mut() {
            ci.id = solana_sdk::pubkey::new_rand();
        }
        let slot = 9;

        // None of these validators have completed slot 9, so should
        // return nothing
        assert!(cs
            .compute_weights_exclude_noncomplete(slot, &contact_infos)
            .is_empty());

        // Give second validator max stake
        let validator_stakes: HashMap<_, _> = vec![(
            *Arc::new(contact_infos[1].id),
            NodeVoteAccounts {
                total_stake: std::u64::MAX / 2,
                vote_accounts: vec![Pubkey::default()],
            },
        )]
        .into_iter()
        .collect();
        *cs.validator_stakes.write().unwrap() = Arc::new(validator_stakes);

        // Mark the first validator as completed slot 9, should pick that validator,
        // even though it only has default stake, while the other validator has
        // max stake
        cs.insert_node_id(slot, contact_infos[0].id);
        assert_eq!(
            cs.compute_weights_exclude_noncomplete(slot, &contact_infos),
            vec![(1, 0)]
        );
    }

    #[test]
    fn test_update_new_staked_slot() {
        let cs = ClusterSlots::default();
        let mut epoch_slot = EpochSlots::default();
        epoch_slot.fill(&[1], 0);

        let map = Arc::new(
            vec![(
                Pubkey::default(),
                NodeVoteAccounts {
                    total_stake: 1,
                    vote_accounts: vec![Pubkey::default()],
                },
            )]
            .into_iter()
            .collect(),
        );

        *cs.validator_stakes.write().unwrap() = map;
        cs.update_internal(0, vec![epoch_slot], None);
        assert!(cs.lookup(1).is_some());
        assert_eq!(
            cs.lookup(1)
                .unwrap()
                .read()
                .unwrap()
                .get(&Pubkey::default()),
            Some(&1)
        );
    }

    #[test]
    fn test_generate_repairs() {
        let cs = ClusterSlots::default();
        let mut epoch_slot = EpochSlots::default();
        epoch_slot.fill(&[1], 0);
        cs.update_internal(0, vec![epoch_slot], None);
        let self_id = solana_sdk::pubkey::new_rand();
        assert_eq!(
            cs.generate_repairs_for_missing_slots(&self_id, 0),
            vec![RepairType::HighestShred(1, 0)]
        )
    }

    #[test]
    fn test_collect_my_slots() {
        let cs = ClusterSlots::default();
        let mut epoch_slot = EpochSlots::default();
        epoch_slot.fill(&[1], 0);
        let self_id = epoch_slot.from;
        cs.update_internal(0, vec![epoch_slot], None);
        let slots: Vec<Slot> = cs.collect(&self_id).into_iter().collect();
        assert_eq!(slots, vec![1]);
    }

    #[test]
    fn test_generate_repairs_existing() {
        let cs = ClusterSlots::default();
        let mut epoch_slot = EpochSlots::default();
        epoch_slot.fill(&[1], 0);
        let self_id = epoch_slot.from;
        cs.update_internal(0, vec![epoch_slot], None);
        assert!(cs
            .generate_repairs_for_missing_slots(&self_id, 0)
            .is_empty());
    }
}
