//! Frozen development campaign rules, shared by the native Solana program and tools.
//! No ledger in this crate can confer an entitlement: account ownership is checked on chain.
use borsh::{BorshDeserialize, BorshSerialize};
use flypow_receipt_v1::{GlobalSummary, SubmissionV1, TopNeuron};
use flypow_task_catalog::{Campaign, TaskDescriptor};
use sha2::{Digest, Sha256};

pub type Key = [u8; 32];
pub const DRAFT: u8 = 0;
pub const RUNNING: u8 = 1;
pub const SUCCESS: u8 = 2;
pub const FAILED: u8 = 3;
pub const QUEUE_SIZE: usize = 8;

#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
pub struct Rules {
    pub catalog: Campaign,
    pub manifest_root: Key,
    pub readout_root: Key,
    pub genesis: Key,
    pub verifiers: [Key; 3],
    pub developer: Key,
    pub community: Key,
    pub mint: Key,
    pub roi_count: u8,
    pub readout_schema_id: u32,
    pub verifier_policy_id: u32,
    pub simulation_config_id: u32,
    pub observe_start: u32,
    pub submit_deadline: i64,
    pub reveal_ttl: i64,
    pub verify_ttl: i64,
    pub archive_ttl: i64,
    pub min_reveal_slots: u64,
    pub advance: u64,
    pub queue_fee: u64,
    pub verify_fee: u64,
    pub rejection_slash: u64,
    pub archive_retention_seconds: i64,
    pub miner_pool_whole: u64,
    pub validator_pool_whole: u64,
    pub community_pool_whole: u64,
    /// 0 localnet; 1 devnet. This implementation deliberately has no mainnet mode.
    pub network: u8,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    Config,
    State,
    Deadline,
    Membership,
    Identity,
    Commitment,
    Summary,
    DuplicateVote,
    Priority,
    QueueFull,
    Funds,
    Overflow,
}
pub type Result<T> = std::result::Result<T, Error>;

pub fn digest(parts: &[&[u8]]) -> Key {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

pub fn whole_allocation(k: u64, count: u64, pool: u64) -> Result<u64> {
    if count == 0 || k >= count {
        return Err(Error::Membership);
    }
    let p = u128::from(pool);
    u64::try_from(
        ((u128::from(k) + 1) * p / u128::from(count)) - u128::from(k) * p / u128::from(count),
    )
    .map_err(|_| Error::Overflow)
}

impl Rules {
    pub fn count(&self) -> Result<u64> {
        self.catalog.validate().map_err(|_| Error::Config)
    }
    pub fn final_deadline(&self) -> Result<i64> {
        self.submit_deadline
            .checked_add(self.reveal_ttl)
            .and_then(|v| v.checked_add(self.verify_ttl))
            .and_then(|v| v.checked_add(self.archive_ttl))
            .ok_or(Error::Overflow)
    }
    pub fn validate(&self) -> Result<()> {
        let count = self.count()?;
        // Pilot implementation bounds account sizes, proof depth and the aggregate queue.
        if self.network > 1
            || count > 4096
            || self.catalog.targets.len() > 16
            || self.catalog.stimuli.len() > 64
            || self.roi_count > 16
            || self.observe_start >= self.catalog.simulation_steps
            || self.reveal_ttl <= 0
            || self.verify_ttl <= 0
            || self.archive_ttl <= 0
            || self.min_reveal_slots < 2
            || self.archive_retention_seconds < self.archive_ttl
            || self.submit_deadline <= 0
            || self.advance
                < self
                    .verify_fee
                    .checked_add(self.rejection_slash)
                    .ok_or(Error::Overflow)?
            || self.manifest_root == [0; 32]
            || self.readout_root == [0; 32]
            || self.genesis == [0; 32]
            || self.developer == [0; 32]
            || self.community == [0; 32]
            || self.mint == [0; 32]
            || self.verifiers.contains(&[0; 32])
            || self.verifiers[0] == self.verifiers[1]
            || self.verifiers[0] == self.verifiers[2]
            || self.verifiers[1] == self.verifiers[2]
            || self.miner_pool_whole < count
            || self.validator_pool_whole == 0
            || self.community_pool_whole == 0
        {
            return Err(Error::Config);
        }
        let observe = self.catalog.simulation_steps - self.observe_start;
        if observe > i32::MAX as u32
            || u64::from(self.catalog.model_neuron_count) * u64::from(observe.div_ceil(32))
                > i32::MAX as u64
        {
            return Err(Error::Overflow);
        }
        self.total_whole()?
            .checked_mul(flypow_receipt_v1::ATOMS_PER_FLY)
            .ok_or(Error::Overflow)?;
        self.final_deadline()?;
        Ok(())
    }
    pub fn total_whole(&self) -> Result<u64> {
        self.miner_pool_whole
            .checked_add(self.validator_pool_whole)
            .and_then(|n| n.checked_add(self.community_pool_whole))
            .ok_or(Error::Overflow)
    }
    pub fn check_task(&self, t: &TaskDescriptor, proof: &[Key]) -> Result<()> {
        if !flypow_task_catalog::verify_membership(&self.catalog, t, proof, self.manifest_root) {
            return Err(Error::Membership);
        }
        Ok(())
    }
    pub fn check_receipt(&self, s: &SubmissionV1) -> Result<()> {
        s.validate_shape().map_err(|_| Error::Summary)?;
        let t = self
            .catalog
            .task(s.task.global_task_index)
            .map_err(|_| Error::Membership)?;
        if s.task.body_id != t.body_id
            || s.task.target_index != t.target_index
            || s.task.stimulus_index != t.stimulus_index
            || s.task.repeat_index != t.repeat_index
            || s.hashes.task_id != t.task_id
            || s.task.model_neuron_count != self.catalog.model_neuron_count
            || s.task.simulation_steps != self.catalog.simulation_steps
            || s.task.time_step_us != self.catalog.time_step_us
            || s.task.simulation_config_id != self.simulation_config_id
            || s.header.roi_count != self.roi_count
            || s.header.readout_schema_id != self.readout_schema_id
            || s.header.verifier_policy_id != self.verifier_policy_id
        {
            return Err(Error::Membership);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, BorshSerialize, BorshDeserialize)]
pub struct CampaignAccount {
    pub authority: Key,
    pub state: u8,
    pub sealed_epochs: u32,
    pub initialized_epochs: u32,
    pub tge: bool,
    pub community_claimed_atoms: u64,
    pub rules_bytes: Vec<u8>,
}
impl CampaignAccount {
    pub fn rules(&self) -> Result<Rules> {
        Rules::try_from_slice(&self.rules_bytes).map_err(|_| Error::Config)
    }
}

#[derive(Clone, Debug, Default, BorshSerialize, BorshDeserialize)]
pub struct EpochAccount {
    pub campaign: Key,
    pub body_id: u64,
    pub target_index: u32,
    pub first_k: u64,
    pub task_count: u32,
    pub initialized_tasks: u32,
    pub completed: u32,
    pub archived: u32,
    pub sealed: bool,
    pub bits: Vec<u8>,
}

#[derive(Clone, Debug, Default, Copy, BorshSerialize, BorshDeserialize)]
pub struct QueueEntry {
    pub submission: Key,
    pub seq: u32,
    pub status: u8,
    pub reveal_deadline: i64,
    pub verify_deadline: i64,
}
impl QueueEntry {
    pub fn blocks(&self, now: i64) -> bool {
        self.submission != [0; 32]
            && ((self.status == 0 && now <= self.reveal_deadline)
                || (self.status == 1 && now <= self.verify_deadline)
                || self.status == 2)
    }
}

#[derive(Clone, Debug, Default, BorshSerialize, BorshDeserialize)]
pub struct ResultPage {
    pub campaign: Key,
    pub task_id: Key,
    pub global_index: u64,
    pub next_seq: u32,
    pub complete: bool,
    pub archived: bool,
    pub winner: Key,
    pub result_root: Key,
    pub preview_root: Key,
    pub archive_root: Key,
    pub summary_hash: Key,
    pub queue: [QueueEntry; QUEUE_SIZE],
}
impl ResultPage {
    pub fn slot(&self, now: i64) -> Result<usize> {
        if self.complete {
            return Err(Error::State);
        }
        self.queue
            .iter()
            .position(|x| !x.blocks(now))
            .ok_or(Error::QueueFull)
    }
    pub fn priority(&self, seq: u32, now: i64) -> Result<()> {
        if self.complete || self.queue.iter().any(|x| x.seq < seq && x.blocks(now)) {
            return Err(Error::Priority);
        }
        Ok(())
    }
    pub fn entry_mut(&mut self, key: Key) -> Result<&mut QueueEntry> {
        self.queue
            .iter_mut()
            .find(|x| x.submission == key)
            .ok_or(Error::Identity)
    }
}

/// Created by the independent operating pool, never from refundable user principal.
/// Persists after the temporary 1024-byte Submission is closed.
#[derive(Clone, Debug, Default, BorshSerialize, BorshDeserialize)]
pub struct Entitlement {
    pub campaign: Key,
    pub submission: Key,
    pub miner: Key,
    pub payer: Key,
    pub task_id: Key,
    pub global_index: u64,
    pub beneficiary: Key,
    pub refund_recipient: Key,
    pub body_id: u64,
    pub closed: bool,
    pub accepted: bool,
    pub refund_paid: bool,
    pub principal_released: bool,
    pub principal: u64,
    pub advance: u64,
    pub miner_whole: u64,
    pub validator_whole: [u64; 3],
    pub miner_claimed: u64,
    pub validator_claimed: [u64; 3],
}

#[derive(Clone, Debug, Default, BorshSerialize, BorshDeserialize)]
pub struct Vault {
    pub campaign: Key,
    pub body_id: u64,
    /// Only closed Submissions contribute to this liability. Active principal remains in its PDA.
    pub liability: u64,
}

#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
pub struct Reveal {
    pub result_root: Key,
    pub preview_root: Key,
    pub archive_root: Key,
    pub salt: Key,
    pub global: GlobalSummary,
    pub roi: [i64; 16],
    pub time: [i32; 32],
    pub top: [TopNeuron; 8],
    pub top_count: u8,
}

// Keep the ordered protocol identity explicit at this hashing boundary.
#[allow(clippy::too_many_arguments)]
pub fn commitment(
    program: Key,
    r: &Rules,
    campaign: Key,
    task: Key,
    miner: Key,
    beneficiary: Key,
    result: Key,
    salt: Key,
) -> Key {
    digest(&[
        b"FlyPoW/commit/v1\0",
        &r.genesis,
        &program,
        &campaign,
        &task,
        &miner,
        &beneficiary,
        &result,
        &salt,
    ])
}

pub fn apply_reveal(
    s: &mut SubmissionV1,
    r: &Rules,
    program: Key,
    campaign: Key,
    reveal: &Reveal,
    slot: u64,
    now: i64,
) -> Result<()> {
    r.check_receipt(s)?;
    if s.header.status != 0 {
        return Err(Error::State);
    }
    if now > s.lifecycle.reveal_deadline_ts
        || slot
            < s.lifecycle
                .commit_slot
                .checked_add(r.min_reveal_slots)
                .ok_or(Error::Overflow)?
    {
        return Err(Error::Deadline);
    }
    if [reveal.result_root, reveal.preview_root, reveal.archive_root].contains(&[0; 32])
        || s.hashes.commitment
            != commitment(
                program,
                r,
                campaign,
                s.hashes.task_id,
                s.identity.miner,
                s.identity.reward_beneficiary,
                reveal.result_root,
                reveal.salt,
            )
    {
        return Err(Error::Commitment);
    }
    s.global = reveal.global.clone();
    s.roi_delta_spikes = reveal.roi;
    s.population_delta_by_bin = reveal.time;
    s.top = reveal.top;
    s.header.top_count = reveal.top_count;
    s.hashes.result_root = reveal.result_root;
    s.hashes.preview_root = reveal.preview_root;
    s.hashes.archive_manifest_hash = reveal.archive_root;
    s.hashes.summary_hash = s.compute_summary_hash(&r.readout_root);
    validate_scientific_bounds(s, r)?;
    s.header.status = 1;
    s.lifecycle.revealed_slot = slot;
    Ok(())
}

pub fn validate_scientific_bounds(s: &SubmissionV1, r: &Rules) -> Result<()> {
    s.validate_summary(&r.readout_root)
        .map_err(|_| Error::Summary)?;
    let n = u64::from(r.catalog.model_neuron_count);
    let steps = u64::from(r.catalog.simulation_steps - r.observe_start);
    let g = &s.global;
    if g.spikes_a > n * steps
        || g.spikes_b > n * steps
        || g.active_a > n
        || g.active_b > n
        || g.target_spikes_a > steps
        || g.target_spikes_b > steps
        || g.vnc_spikes_a > g.spikes_a
        || g.vnc_spikes_b > g.spikes_b
        || g.active_a > g.spikes_a
        || g.active_b > g.spikes_b
        || s.population_delta_by_bin
            .iter()
            .map(|v| i64::from(*v))
            .sum::<i64>()
            != (i128::from(g.spikes_b) - i128::from(g.spikes_a)) as i64
        || s.roi_delta_spikes
            .iter()
            .any(|v| i128::from(*v).abs() > i128::from(n * steps))
        || s.top[..s.header.top_count as usize].iter().any(|t| {
            i64::from(t.delta_spikes).abs() > steps as i64
                || t.first_divergence_step < r.observe_start
        })
    {
        return Err(Error::Summary);
    }
    for (i, delta) in s.population_delta_by_bin.iter().enumerate() {
        let width = ((i as u64 + 1) * steps / 32) - (i as u64 * steps / 32);
        if i64::from(*delta).abs() > (n * width) as i64 {
            return Err(Error::Summary);
        }
    }
    Ok(())
}

/// Every vote has the same expiry from the chain Clock. No per-vote deadline can revive a late quorum.
pub fn verification_message(
    program: Key,
    campaign: Key,
    submission: Key,
    r: &Rules,
    s: &SubmissionV1,
    accept: bool,
) -> Vec<u8> {
    let mut v = b"FlyPoW/verify-archive/v1\0".to_vec();
    for k in [
        r.genesis,
        program,
        campaign,
        submission,
        s.hashes.task_id,
        s.identity.miner,
        s.identity.reward_beneficiary,
        r.catalog.source_root,
        r.catalog.registry_root,
        r.catalog.graph_root,
        r.catalog.model_root,
        r.catalog.experiment_root,
        r.manifest_root,
        r.readout_root,
        s.hashes.result_root,
        s.hashes.preview_root,
        s.hashes.archive_manifest_hash,
        s.hashes.summary_hash,
    ] {
        v.extend_from_slice(&k);
    }
    v.push(u8::from(accept));
    v.extend_from_slice(&r.verifier_policy_id.to_le_bytes());
    v.extend_from_slice(&s.lifecycle.verify_deadline_ts.to_le_bytes());
    v.extend_from_slice(&r.archive_retention_seconds.to_le_bytes());
    v
}

pub fn apply_vote(
    s: &mut SubmissionV1,
    r: &Rules,
    verifier: usize,
    accept: bool,
    slot: u64,
    now: i64,
) -> Result<bool> {
    r.check_receipt(s)?;
    validate_scientific_bounds(s, r)?;
    if s.header.status != 1 || verifier >= 3 {
        return Err(Error::State);
    }
    if now > s.lifecycle.verify_deadline_ts {
        return Err(Error::Deadline);
    }
    let bit = 1u16 << verifier;
    if (s.header.accept_mask | s.header.reject_mask) & bit != 0 {
        return Err(Error::DuplicateVote);
    }
    if accept {
        s.header.accept_mask |= bit;
    } else {
        s.header.reject_mask |= bit;
    }
    if s.header.accept_mask.count_ones() >= 2 {
        s.header.status = 2;
        s.lifecycle.verified_slot = slot;
    } else if s.header.reject_mask.count_ones() >= 2 {
        s.header.status = 3;
        s.lifecycle.verified_slot = slot;
    }
    Ok(s.header.status == 2)
}

pub fn validator_shares(pool: u64, mask: u16) -> Result<[u64; 3]> {
    let count = mask.count_ones() as u64;
    if count < 2 || mask & !7 != 0 {
        return Err(Error::Config);
    }
    let mut result = [0; 3];
    let mut rank = 0;
    for (i, v) in result.iter_mut().enumerate() {
        if mask & (1 << i) != 0 {
            *v = whole_allocation(rank, count, pool)?;
            rank += 1;
        }
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn queue_blocks_matches_shared_browser_vectors() {
        let vectors: serde_json::Value =
            serde_json::from_str(include_str!("../../../tests/fixtures/queue-blocks.json"))
                .unwrap();
        for row in vectors.as_array().unwrap() {
            let entry = QueueEntry {
                submission: [if row["nonempty"].as_bool().unwrap() {
                    1
                } else {
                    0
                }; 32],
                status: row["status"].as_u64().unwrap() as u8,
                reveal_deadline: row["revealDeadline"].as_i64().unwrap(),
                verify_deadline: row["verifyDeadline"].as_i64().unwrap(),
                ..QueueEntry::default()
            };
            assert_eq!(
                entry.blocks(row["now"].as_i64().unwrap()),
                row["blocks"].as_bool().unwrap(),
                "{row}"
            );
        }
    }
    #[test]
    fn whole_rewards_cannot_change_by_splitting_wallets() {
        for (m, p) in [(1024, 224_519_936), (4096, 56_129_984), (3, 5)] {
            assert_eq!(
                (0..m)
                    .map(|k| whole_allocation(k, m, p).unwrap())
                    .sum::<u64>(),
                p
            );
        }
        assert!(whole_allocation(1, 1, 5).is_err());
        assert_eq!(validator_shares(5, 5).unwrap(), [2, 0, 3]);
    }
    #[test]
    fn queue_is_bounded_and_expiration_does_not_block_later_candidate() {
        let mut p = ResultPage::default();
        for (i, e) in p.queue.iter_mut().enumerate() {
            *e = QueueEntry {
                submission: [i as u8 + 1; 32],
                seq: i as u32,
                status: 0,
                reveal_deadline: 10,
                verify_deadline: 20,
            };
        }
        assert_eq!(p.slot(10), Err(Error::QueueFull));
        assert_eq!(p.slot(11), Ok(0));
        assert_eq!(p.priority(1, 10), Err(Error::Priority));
        assert!(p.priority(1, 11).is_ok());
        p.queue[0].status = 2;
        assert_eq!(p.priority(1, 100), Err(Error::Priority));
        p.complete = true;
        assert_eq!(p.slot(100), Err(Error::State));
    }
    #[test]
    fn signatures_bind_identity_program_genesis_summary_and_fixed_expiry() {
        let s = SubmissionV1::decode_account(include_bytes!(
            "../../../tests/fixtures/submission-v1.bin"
        ))
        .unwrap();
        let c = Campaign {
            campaign_id: [1; 32],
            source_root: [2; 32],
            registry_root: [3; 32],
            graph_root: [4; 32],
            model_root: [5; 32],
            experiment_root: [6; 32],
            public_seed: [7; 32],
            model_neuron_count: 10,
            simulation_steps: 32,
            time_step_us: 1000,
            targets: vec![flypow_task_catalog::Target {
                body_id: 42,
                model_index: 0,
            }],
            stimuli: vec![flypow_task_catalog::Stimulus {
                start_step: 1,
                end_step: 2,
                current: 1,
            }],
            repeats: 1,
        };
        let r = Rules {
            catalog: c,
            manifest_root: [2; 32],
            readout_root: [3; 32],
            genesis: [4; 32],
            verifiers: [[5; 32], [6; 32], [7; 32]],
            developer: [8; 32],
            community: [9; 32],
            mint: [10; 32],
            roi_count: 1,
            readout_schema_id: 7,
            verifier_policy_id: 9,
            simulation_config_id: 4,
            observe_start: 0,
            submit_deadline: 100,
            reveal_ttl: 300,
            verify_ttl: 600,
            archive_ttl: 600,
            min_reveal_slots: 2,
            advance: 500,
            queue_fee: 0,
            verify_fee: 100,
            rejection_slash: 0,
            archive_retention_seconds: 3600,
            miner_pool_whole: 5,
            validator_pool_whole: 2,
            community_pool_whole: 1,
            network: 0,
        };
        r.validate().unwrap();
        let a = verification_message([1; 32], [2; 32], [3; 32], &r, &s, true);
        assert_ne!(
            a,
            verification_message([2; 32], [2; 32], [3; 32], &r, &s, true)
        );
        assert_ne!(
            a,
            verification_message([1; 32], [2; 32], [3; 32], &r, &s, false)
        );
        let mut t = s.clone();
        t.hashes.summary_hash[0] ^= 1;
        assert_ne!(
            a,
            verification_message([1; 32], [2; 32], [3; 32], &r, &t, true)
        );
    }
}
