//! Finite, deterministic task directory for an uncalibrated research campaign.
//! This is pure catalog logic; it does not confer payment or chain membership.
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;

const TASK_DOMAIN: &[u8] = b"FlyPoW/task-id/v1\0";
const SEED_DOMAIN: &[u8] = b"FlyPoW/task-seed/v1\0";
const LEAF_DOMAIN: &[u8] = b"FlyPoW/task-leaf/v1\0";
const NODE_DOMAIN: &[u8] = b"FlyPoW/task-node/v1\0";
const ROOT_DOMAIN: &[u8] = b"FlyPoW/task-root/v1\0";

#[derive(
    Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub struct Target {
    pub body_id: u64,
    pub model_index: u32,
}

/// Rectangular stimulus only. New waveform semantics require a new experiment root.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
)]
pub struct Stimulus {
    pub start_step: u32,
    pub end_step: u32,
    pub current: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct Campaign {
    pub campaign_id: [u8; 32],
    pub source_root: [u8; 32],
    pub registry_root: [u8; 32],
    pub graph_root: [u8; 32],
    pub model_root: [u8; 32],
    pub experiment_root: [u8; 32],
    pub public_seed: [u8; 32],
    pub model_neuron_count: u32,
    pub simulation_steps: u32,
    pub time_step_us: u32,
    /// Strictly increasing official body IDs; each model index is distinct.
    pub targets: Vec<Target>,
    /// Strictly increasing canonical (start, end, current) triples.
    pub stimuli: Vec<Stimulus>,
    pub repeats: u32,
}

#[derive(
    Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub struct TaskDescriptor {
    pub global_index: u64,
    pub body_id: u64,
    pub target_index: u32,
    pub stimulus_index: u32,
    pub repeat_index: u32,
    pub stimulus: Stimulus,
    pub task_id: [u8; 32],
    pub simulation_seed: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CatalogFile {
    pub state: String,
    pub campaign: Campaign,
    pub graph_data_sha256: [u8; 32],
    pub model_data_sha256: [u8; 32],
    pub task_manifest_root: [u8; 32],
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile_definition: Option<serde_json::Value>,
}

pub fn duration_stimuli(steps: u32) -> Result<Vec<Stimulus>, CatalogError> {
    if ![128, 256, 512].contains(&steps) {
        return Err(CatalogError::InvalidConfig);
    }
    let mut stimuli = Vec::new();
    for start_step in [0, steps / 8, steps / 2, steps - 1] {
        for duration in [1, steps / 32, steps / 8, steps / 4] {
            if start_step + duration <= steps {
                for current in [50, 100, 150, 200] {
                    stimuli.push(Stimulus {
                        start_step,
                        end_step: start_step + duration,
                        current,
                    });
                }
            }
        }
    }
    stimuli.sort_unstable();
    Ok(stimuli)
}
pub fn duration_definition(c: &Campaign) -> serde_json::Value {
    serde_json::json!({"schema":"flypow-duration-profile-v1","profile_id":format!("duration{}-v1-dev",c.simulation_steps),
        "question":"Sensitivity to rectangular stimulus timing, strength, duration and public seed; late response and persistent cascades in a longer observation window",
        "parameter_version":"lif-point-v0-dev","observe_start":0,"steps":c.simulation_steps,"time_step_us":1000,
        "source_root":hex(&c.source_root),"registry_root":hex(&c.registry_root),"graph_root":hex(&c.graph_root),"model_root":hex(&c.model_root),"neuron_count":c.model_neuron_count,
        "parameters":{"leak_divisor":8,"threshold":100,"reset":0,"membrane_limit":1000000,"refractory_steps":2,"synaptic_unit":1,"synaptic_delay_steps":1,"background_probability_u16":256,"background_current":10},
        "targets":c.targets,"stimuli":c.stimuli,"repeats":4,
        "resources":{"max_archive_bytes":134217728,"max_trace_bytes":16777216,"max_trace_cells":64,"max_trace_edges":256},"payment":false,"rewards":false})
}
pub fn duration_roots(
    c: &Campaign,
    definition: &serde_json::Value,
) -> ([u8; 32], [u8; 32], [u8; 32]) {
    let data = serde_json::to_vec(definition).expect("definition JSON");
    (
        hash(&[b"FlyPoW/duration-campaign/v1\0", &data]),
        hash(&[b"FlyPoW/duration-experiment/v1\0", &data]),
        hash(&[
            b"FlyPoW/duration-public-seed/v1\0",
            &c.simulation_steps.to_le_bytes(),
        ]),
    )
}
pub fn validate_development_science(file: &CatalogFile) -> Result<(), CatalogError> {
    let c = &file.campaign;
    if c.time_step_us != 1000 {
        return Err(CatalogError::InvalidConfig);
    }
    if let Some(definition) = &file.profile_definition {
        if c.stimuli != duration_stimuli(c.simulation_steps)?
            || c.repeats != 4
            || definition != &duration_definition(c)
        {
            return Err(CatalogError::InvalidConfig);
        }
        let (campaign, experiment, seed) = duration_roots(c, definition);
        if c.campaign_id != campaign || c.experiment_root != experiment || c.public_seed != seed {
            return Err(CatalogError::InvalidConfig);
        }
    } else {
        let mut stimuli = Vec::new();
        for start_step in [0, 4, 8, 12] {
            for duration in [1, 2, 4, 8] {
                for current in [50, 100, 150, 200] {
                    stimuli.push(Stimulus {
                        start_step,
                        end_step: start_step + duration,
                        current,
                    });
                }
            }
        }
        stimuli.sort_unstable();
        let mut definition = Vec::new();
        definition.extend_from_slice(b"FlyPoW/experiment/lif-rectangular-v0-dev\0");
        definition.extend_from_slice(&c.model_root);
        for value in [32_u32, 1000, 0] {
            definition.extend_from_slice(&value.to_le_bytes());
        }
        for s in &stimuli {
            definition.extend_from_slice(&s.start_step.to_le_bytes());
            definition.extend_from_slice(&s.end_step.to_le_bytes());
            definition.extend_from_slice(&s.current.to_le_bytes());
        }
        if c.simulation_steps != 32
            || c.repeats != 4
            || c.stimuli != stimuli
            || c.campaign_id != hash(&[b"FlyPoW/aipg10/local-catalog-v0/NO-PAYMENT"])
            || c.public_seed != hash(&[b"FlyPoW/LOCAL-DEVELOPMENT-SEED-ONLY/v0"])
            || c.experiment_root != hash(&[&definition])
        {
            return Err(CatalogError::InvalidConfig);
        }
    }
    Ok(())
}

pub fn hex(bytes: &[u8]) -> String {
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write;
        write!(result, "{byte:02x}").expect("writing to String");
    }
    result
}

pub fn parse_hex32(value: &str) -> Result<[u8; 32], CatalogError> {
    if value.len() != 64 {
        return Err(CatalogError::InvalidConfig);
    }
    let mut output = [0; 32];
    for (index, byte) in output.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| CatalogError::InvalidConfig)?;
    }
    Ok(output)
}

#[derive(Debug, PartialEq, Eq)]
pub enum CatalogError {
    InvalidConfig,
    TooManyTasks,
    OutOfRange,
}

fn hash(parts: &[&[u8]]) -> [u8; 32] {
    let mut digest = Sha256::new();
    for part in parts {
        digest.update(part);
    }
    digest.finalize().into()
}

impl Campaign {
    pub fn validate(&self) -> Result<u64, CatalogError> {
        if [
            self.campaign_id,
            self.source_root,
            self.registry_root,
            self.graph_root,
            self.model_root,
            self.experiment_root,
            self.public_seed,
        ]
        .contains(&[0; 32])
            || self.model_neuron_count == 0
            || self.simulation_steps < 32
            || self.time_step_us == 0
            || self.repeats == 0
            || self.targets.is_empty()
            || self.stimuli.is_empty()
            || self
                .targets
                .windows(2)
                .any(|pair| pair[0].body_id >= pair[1].body_id)
            || self
                .targets
                .iter()
                .any(|target| target.body_id == 0 || target.model_index >= self.model_neuron_count)
            || self
                .targets
                .iter()
                .map(|target| target.model_index)
                .collect::<HashSet<_>>()
                .len()
                != self.targets.len()
            || self.stimuli.len() > u32::MAX as usize
            || self.stimuli.windows(2).any(|pair| pair[0] >= pair[1])
            || self.stimuli.iter().any(|stimulus| {
                stimulus.start_step >= stimulus.end_step
                    || stimulus.end_step > self.simulation_steps
                    || stimulus.current <= 0
            })
        {
            return Err(CatalogError::InvalidConfig);
        }
        (self.targets.len() as u64)
            .checked_mul(self.stimuli.len() as u64)
            .and_then(|count| count.checked_mul(u64::from(self.repeats)))
            .ok_or(CatalogError::TooManyTasks)
    }

    /// Global order: body ID, canonical stimulus, then repeat index.
    pub fn task(&self, k: u64) -> Result<TaskDescriptor, CatalogError> {
        let total = self.validate()?;
        if k >= total {
            return Err(CatalogError::OutOfRange);
        }
        Ok(self.task_unchecked(k))
    }

    fn task_unchecked(&self, k: u64) -> TaskDescriptor {
        let per_target = (self.stimuli.len() as u64) * u64::from(self.repeats);
        let target = self.targets[(k / per_target) as usize];
        let stimulus_index = ((k % per_target) / u64::from(self.repeats)) as usize;
        let repeat_index = (k % u64::from(self.repeats)) as u32;
        let stimulus = self.stimuli[stimulus_index];
        let task_id = hash(&[
            TASK_DOMAIN,
            &self.campaign_id,
            &self.source_root,
            &self.registry_root,
            &self.graph_root,
            &self.model_root,
            &self.experiment_root,
            &self.public_seed,
            &self.model_neuron_count.to_le_bytes(),
            &self.simulation_steps.to_le_bytes(),
            &self.time_step_us.to_le_bytes(),
            &k.to_le_bytes(),
            &target.body_id.to_le_bytes(),
            &target.model_index.to_le_bytes(),
            &(stimulus_index as u32).to_le_bytes(),
            &stimulus.start_step.to_le_bytes(),
            &stimulus.end_step.to_le_bytes(),
            &stimulus.current.to_le_bytes(),
            &repeat_index.to_le_bytes(),
        ]);
        let seed = hash(&[SEED_DOMAIN, &self.public_seed, &task_id]);
        TaskDescriptor {
            global_index: k,
            body_id: target.body_id,
            target_index: target.model_index,
            stimulus_index: stimulus_index as u32,
            repeat_index,
            stimulus,
            task_id,
            simulation_seed: u64::from_le_bytes(seed[..8].try_into().expect("SHA-256 size")),
        }
    }
}

fn leaf(task: &TaskDescriptor) -> [u8; 32] {
    hash(&[
        LEAF_DOMAIN,
        &task.global_index.to_le_bytes(),
        &task.task_id,
        &task.body_id.to_le_bytes(),
        &task.target_index.to_le_bytes(),
        &task.stimulus_index.to_le_bytes(),
        &task.repeat_index.to_le_bytes(),
        &task.stimulus.start_step.to_le_bytes(),
        &task.stimulus.end_step.to_le_bytes(),
        &task.stimulus.current.to_le_bytes(),
        &task.simulation_seed.to_le_bytes(),
    ])
}

fn parent(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    hash(&[NODE_DOMAIN, &left, &right])
}

fn root(count: u64, top: [u8; 32]) -> [u8; 32] {
    hash(&[ROOT_DOMAIN, &count.to_le_bytes(), &top])
}

/// Dense development tree. Large main campaigns will need a paged builder.
pub struct MerkleTree {
    levels: Vec<Vec<[u8; 32]>>,
    count: u64,
}

impl MerkleTree {
    pub fn build(campaign: &Campaign) -> Result<Self, CatalogError> {
        let count = campaign.validate()?;
        if count > 1_000_000 {
            return Err(CatalogError::TooManyTasks);
        }
        let capacity = usize::try_from(count).map_err(|_| CatalogError::TooManyTasks)?;
        let mut leaves = Vec::with_capacity(capacity);
        for k in 0..count {
            leaves.push(leaf(&campaign.task_unchecked(k)));
        }
        let mut levels = vec![leaves];
        while levels.last().expect("nonempty").len() > 1 {
            let previous = levels.last().expect("nonempty");
            let next = previous
                .chunks(2)
                .map(|pair| parent(pair[0], *pair.get(1).unwrap_or(&pair[0])))
                .collect();
            levels.push(next);
        }
        Ok(Self { levels, count })
    }

    pub fn root(&self) -> [u8; 32] {
        root(self.count, self.levels.last().expect("nonempty")[0])
    }

    pub fn proof(&self, index: u64) -> Result<Vec<[u8; 32]>, CatalogError> {
        if index >= self.count {
            return Err(CatalogError::OutOfRange);
        }
        let mut position = index as usize;
        let mut proof = Vec::with_capacity(self.levels.len() - 1);
        for level in self.levels.iter().take(self.levels.len() - 1) {
            proof.push(level.get(position ^ 1).copied().unwrap_or(level[position]));
            position /= 2;
        }
        Ok(proof)
    }
}

/// Also checks all claimed task fields against the frozen deterministic order.
pub fn verify_membership(
    campaign: &Campaign,
    claimed: &TaskDescriptor,
    proof: &[[u8; 32]],
    expected_root: [u8; 32],
) -> bool {
    let Ok(count) = campaign.validate() else {
        return false;
    };
    if campaign.task(claimed.global_index).ok().as_ref() != Some(claimed) {
        return false;
    }
    let mut width = count;
    let mut position = claimed.global_index;
    let mut node = leaf(claimed);
    let mut level = 0;
    while width > 1 {
        let Some(sibling) = proof.get(level).copied() else {
            return false;
        };
        if position & 1 == 0 {
            if position + 1 == width && sibling != node {
                return false;
            }
            node = parent(node, sibling);
        } else {
            node = parent(sibling, node);
        }
        position /= 2;
        width = width.div_ceil(2);
        level += 1;
    }
    level == proof.len() && root(count, node) == expected_root
}

#[cfg(test)]
mod tests {
    use super::*;

    fn campaign() -> Campaign {
        Campaign {
            campaign_id: [1; 32],
            source_root: [2; 32],
            registry_root: [3; 32],
            graph_root: [4; 32],
            model_root: [5; 32],
            experiment_root: [6; 32],
            public_seed: [7; 32],
            model_neuron_count: 3,
            simulation_steps: 32,
            time_step_us: 1000,
            targets: vec![
                Target {
                    body_id: 10,
                    model_index: 1,
                },
                Target {
                    body_id: 20,
                    model_index: 2,
                },
            ],
            stimuli: vec![
                Stimulus {
                    start_step: 0,
                    end_step: 1,
                    current: 100,
                },
                Stimulus {
                    start_step: 4,
                    end_step: 12,
                    current: 200,
                },
            ],
            repeats: 2,
        }
    }

    #[test]
    fn finite_order_and_membership_reject_mutations() {
        let campaign = campaign();
        let tree = MerkleTree::build(&campaign).unwrap();
        assert_eq!(campaign.validate().unwrap(), 8);
        for k in 0..8 {
            let task = campaign.task(k).unwrap();
            let proof = tree.proof(k).unwrap();
            assert!(verify_membership(&campaign, &task, &proof, tree.root()));
            let mut wrong = task;
            wrong.body_id += 1;
            assert!(!verify_membership(&campaign, &wrong, &proof, tree.root()));
            wrong = task;
            wrong.simulation_seed += 1;
            assert!(!verify_membership(&campaign, &wrong, &proof, tree.root()));
            wrong = task;
            wrong.global_index = (k + 1) % 8;
            assert!(!verify_membership(&campaign, &wrong, &proof, tree.root()));
            let mut bad_proof = proof.clone();
            bad_proof[0][0] ^= 1;
            assert!(!verify_membership(
                &campaign,
                &task,
                &bad_proof,
                tree.root()
            ));
        }
        assert_eq!(campaign.task(8), Err(CatalogError::OutOfRange));
    }

    #[test]
    fn wallet_and_salt_cannot_change_scientific_task() {
        let campaign = campaign();
        let first = campaign.task(0).unwrap();
        assert_eq!(campaign.task(0).unwrap(), first);
        assert_ne!(campaign.task(1).unwrap().task_id, first.task_id);
        let mut bad = campaign.clone();
        bad.stimuli.push(bad.stimuli[1]);
        assert_eq!(bad.validate(), Err(CatalogError::InvalidConfig));
        let mut oversized = campaign.clone();
        oversized.repeats = 1_000_000;
        assert!(matches!(
            MerkleTree::build(&oversized),
            Err(CatalogError::TooManyTasks)
        ));
    }
}
