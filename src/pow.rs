use core::fmt;

use crate::{
    block::{BlockTemplate, MinedHeader},
    dataset::CanonicalDataset,
    flyhash::{CONNECTOME_REFERENCE, FlyHashEngine, FlyHashError, FlyHashOutput, FlyHashProfile},
    hash::{Hash256, hash_parts},
    useful::{FingerprintLookup, derive_sketch_seed},
};

const CHALLENGE_DOMAIN: &[u8] = b"FlyPoW/challenge/v1";
const WORK_DOMAIN: &[u8] = b"FlyPoW/work/v1";
const DATASET_CHALLENGE_DOMAIN: &[u8] = b"FlyPoW/dataset-challenge/v1";
const DATASET_ACCESS_INIT_DOMAIN: &[u8] = b"FlyPoW/dataset-access-init/v1";
const DATASET_ACCESS_DOMAIN: &[u8] = b"FlyPoW/dataset-access/v1";
const DATASET_WORK_DOMAIN: &[u8] = b"FlyPoW/dataset-work/v1";

/// Serial random reads per nonce. The next record depends on the previous
/// record, so a single nonce trace cannot be prefetched or parallelized.
pub const DATASET_ACCESS_ROUNDS: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PowError {
    DifficultyOutOfRange(u16),
    FlyHash(FlyHashError),
    DatasetIndexRootMismatch,
    SketchSeedMismatch,
    MissingFingerprint(u64),
}

impl fmt::Display for PowError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DifficultyOutOfRange(bits) => {
                write!(f, "difficulty_bits must be in 0..=256, got {bits}")
            }
            Self::FlyHash(error) => write!(f, "invalid FlyHash configuration: {error}"),
            Self::DatasetIndexRootMismatch => {
                f.write_str("useful index was built for a different canonical dataset")
            }
            Self::SketchSeedMismatch => {
                f.write_str("useful index seed does not match epoch seed and miner key")
            }
            Self::MissingFingerprint(body_id) => {
                write!(f, "useful index has no fingerprint for body ID {body_id}")
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DatasetNonceWork {
    pub nonce: u64,
    pub hash: Hash256,
    pub access_trace: Hash256,
    pub flyhash: FlyHashOutput,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DatasetMiningOutcome {
    pub attempts: u64,
    pub solution: Option<DatasetNonceWork>,
}

impl std::error::Error for PowError {}

impl From<FlyHashError> for PowError {
    fn from(value: FlyHashError) -> Self {
        Self::FlyHash(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NonceWork {
    pub nonce: u64,
    pub hash: Hash256,
    pub flyhash: FlyHashOutput,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MiningOutcome {
    pub attempts: u64,
    pub solution: Option<NonceWork>,
}

/// Challenge-specific PoW context. Build once, hash many nonces.
#[derive(Debug, Clone)]
pub struct FlyPowContext {
    template: BlockTemplate,
    profile: FlyHashProfile,
    challenge: Hash256,
    flyhash: FlyHashEngine,
}

impl FlyPowContext {
    pub fn new(template: BlockTemplate, profile: FlyHashProfile) -> Result<Self, PowError> {
        if template.difficulty_bits > 256 {
            return Err(PowError::DifficultyOutOfRange(template.difficulty_bits));
        }

        let params = profile.params();
        let params_bytes = params.consensus_bytes();
        let template_bytes = template.consensus_bytes();
        let reference_tag = hash_parts(b"FlyPoW/connectome-reference/v1", &[CONNECTOME_REFERENCE]);
        let challenge = hash_parts(
            CHALLENGE_DOMAIN,
            &[&template_bytes, &params_bytes, &reference_tag],
        );
        let flyhash = FlyHashEngine::new(params, challenge)?;

        Ok(Self {
            template,
            profile,
            challenge,
            flyhash,
        })
    }

    pub fn template(&self) -> &BlockTemplate {
        &self.template
    }

    pub fn profile(&self) -> FlyHashProfile {
        self.profile
    }

    pub fn challenge(&self) -> Hash256 {
        self.challenge
    }

    pub fn hash_nonce(&self, nonce: u64) -> NonceWork {
        let flyhash = self.flyhash.hash_nonce(nonce);
        let nonce_bytes = nonce.to_le_bytes();
        let hash = hash_parts(
            WORK_DOMAIN,
            &[&self.challenge, &nonce_bytes, &flyhash.code_digest],
        );
        NonceWork {
            nonce,
            hash,
            flyhash,
        }
    }

    pub fn verify_nonce(&self, nonce: u64) -> bool {
        meets_difficulty(&self.hash_nonce(nonce).hash, self.template.difficulty_bits)
    }

    pub fn verify_claim(&self, nonce: u64, claimed_hash: &Hash256) -> bool {
        let work = self.hash_nonce(nonce);
        work.hash == *claimed_hash && meets_difficulty(&work.hash, self.template.difficulty_bits)
    }

    pub fn mine(&self, start_nonce: u64, max_attempts: u64) -> MiningOutcome {
        let mut nonce = start_nonce;
        for attempt_index in 0..max_attempts {
            let work = self.hash_nonce(nonce);
            if meets_difficulty(&work.hash, self.template.difficulty_bits) {
                return MiningOutcome {
                    attempts: attempt_index + 1,
                    solution: Some(work),
                };
            }
            nonce = nonce.wrapping_add(1);
        }
        MiningOutcome {
            attempts: max_attempts,
            solution: None,
        }
    }

    pub fn mined_header(&self, work: NonceWork) -> Option<MinedHeader> {
        if self.verify_claim(work.nonce, &work.hash) {
            Some(MinedHeader {
                template: self.template.clone(),
                nonce: work.nonce,
                work_hash: work.hash,
            })
        } else {
            None
        }
    }
}

/// Dataset-bound PoW used by the proposed mining path.
///
/// The constructor binds a verified canonical dataset, a useful neuron index,
/// an epoch seed, and a miner key into the block challenge. Each nonce follows
/// a sequential, data-dependent random walk through synapse records and mixes
/// the corresponding FlyHash neuron fingerprints before the final WTA hash.
pub struct DatasetFlyPowContext<'a> {
    template: BlockTemplate,
    dataset: &'a CanonicalDataset,
    index: &'a dyn FingerprintLookup,
    challenge: Hash256,
    flyhash: FlyHashEngine,
}

impl fmt::Debug for DatasetFlyPowContext<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DatasetFlyPowContext")
            .field("template", &self.template)
            .field("dataset_root", &self.dataset.merkle_root())
            .field("artifact_root", &self.index.artifact_root())
            .field("challenge", &self.challenge)
            .finish()
    }
}

impl<'a> DatasetFlyPowContext<'a> {
    pub fn new(
        template: BlockTemplate,
        dataset: &'a CanonicalDataset,
        index: &'a dyn FingerprintLookup,
        epoch_seed: Hash256,
        miner_key: Hash256,
    ) -> Result<Self, PowError> {
        if template.difficulty_bits > 256 {
            return Err(PowError::DifficultyOutOfRange(template.difficulty_bits));
        }
        if dataset.merkle_root() != index.dataset_root() {
            return Err(PowError::DatasetIndexRootMismatch);
        }
        let expected_seed = derive_sketch_seed(dataset.merkle_root(), epoch_seed, miner_key);
        if index.sketch_seed() != expected_seed {
            return Err(PowError::SketchSeedMismatch);
        }

        let template_bytes = template.consensus_bytes();
        let challenge = hash_parts(
            DATASET_CHALLENGE_DOMAIN,
            &[
                &template_bytes,
                &dataset.merkle_root(),
                &index.artifact_root(),
                &epoch_seed,
                &miner_key,
            ],
        );
        let flyhash = FlyHashEngine::new(FlyHashProfile::Reference.params(), challenge)?;
        Ok(Self {
            template,
            dataset,
            index,
            challenge,
            flyhash,
        })
    }

    pub fn challenge(&self) -> Hash256 {
        self.challenge
    }

    pub fn hash_nonce(&self, nonce: u64) -> Result<DatasetNonceWork, PowError> {
        let nonce_bytes = nonce.to_le_bytes();
        let mut state = hash_parts(DATASET_ACCESS_INIT_DOMAIN, &[&self.challenge, &nonce_bytes]);
        let mut features = [0_u32; 50];

        for round in 0..DATASET_ACCESS_ROUNDS {
            let selector = u64::from_le_bytes(state[..8].try_into().unwrap());
            let record_index = selector % self.dataset.record_count();
            let record_bytes = self
                .dataset
                .raw_record(record_index)
                .expect("record index is reduced modulo record_count");
            let record = crate::dataset::CanonicalSynapse::from_consensus_bytes(record_bytes);
            let pre = self
                .index
                .fingerprint(record.body_pre)
                .ok_or(PowError::MissingFingerprint(record.body_pre))?;
            let post = self
                .index
                .fingerprint(record.body_post)
                .ok_or(PowError::MissingFingerprint(record.body_post))?;
            let chunk_hash = self
                .dataset
                .chunk_hash(self.dataset.chunk_index_for_record(record_index))
                .expect("record-derived chunk index is in range");
            let round_bytes = (round as u32).to_le_bytes();
            let record_index_bytes = record_index.to_le_bytes();

            state = hash_parts(
                DATASET_ACCESS_DOMAIN,
                &[
                    &state,
                    &round_bytes,
                    &record_index_bytes,
                    record_bytes,
                    &chunk_hash,
                    &pre.leaf_hash,
                    &post.leaf_hash,
                ],
            );

            // Fold both the cryptographic trace and sparse neuron codes into
            // a 50-dimensional odor-like input for the final FlyHash circuit.
            for (offset, &byte) in state.iter().enumerate() {
                let bucket = (offset + round + byte as usize) % features.len();
                features[bucket] = features[bucket].wrapping_add(byte as u32 + 1);
            }
            for (offset, &winner) in pre.winners.iter().step_by(10).enumerate() {
                let bucket = (winner as usize + offset + round) % features.len();
                features[bucket] = features[bucket].wrapping_add(winner + 1);
            }
            for (offset, &winner) in post.winners.iter().skip(5).step_by(10).enumerate() {
                let bucket = (winner as usize + offset + round + 25) % features.len();
                features[bucket] = features[bucket].wrapping_add(winner + 1);
            }
        }

        let input = features.map(fold_u32_to_u8);
        let flyhash = self.flyhash.hash_input(nonce, &input)?;
        let hash = hash_parts(
            DATASET_WORK_DOMAIN,
            &[&self.challenge, &nonce_bytes, &state, &flyhash.code_digest],
        );
        Ok(DatasetNonceWork {
            nonce,
            hash,
            access_trace: state,
            flyhash,
        })
    }

    pub fn verify_claim(&self, nonce: u64, claimed_hash: &Hash256) -> Result<bool, PowError> {
        let work = self.hash_nonce(nonce)?;
        Ok(work.hash == *claimed_hash
            && meets_difficulty(&work.hash, self.template.difficulty_bits))
    }

    pub fn mine(
        &self,
        start_nonce: u64,
        max_attempts: u64,
    ) -> Result<DatasetMiningOutcome, PowError> {
        let mut nonce = start_nonce;
        for attempt_index in 0..max_attempts {
            let work = self.hash_nonce(nonce)?;
            if meets_difficulty(&work.hash, self.template.difficulty_bits) {
                return Ok(DatasetMiningOutcome {
                    attempts: attempt_index + 1,
                    solution: Some(work),
                });
            }
            nonce = nonce.wrapping_add(1);
        }
        Ok(DatasetMiningOutcome {
            attempts: max_attempts,
            solution: None,
        })
    }
}

fn fold_u32_to_u8(value: u32) -> u8 {
    let folded = value ^ (value >> 8) ^ (value >> 16) ^ (value >> 24);
    folded as u8
}

pub fn leading_zero_bits(hash: &Hash256) -> u16 {
    let mut count = 0_u16;
    for &byte in hash {
        if byte == 0 {
            count += 8;
        } else {
            count += byte.leading_zeros() as u16;
            break;
        }
    }
    count
}

pub fn meets_difficulty(hash: &Hash256, difficulty_bits: u16) -> bool {
    difficulty_bits <= 256 && leading_zero_bits(hash) >= difficulty_bits
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        dataset::{CanonicalDataset, CanonicalSynapse},
        hash::hash_parts,
        useful::UsefulIndex,
    };
    use std::{
        fs::{self, File},
        io::Write,
        time::{SystemTime, UNIX_EPOCH},
    };

    fn template(difficulty_bits: u16) -> BlockTemplate {
        BlockTemplate::new(
            [0; 32],
            hash_parts(b"test-merkle", &[b"genesis"]),
            0,
            1_789_344_000,
            difficulty_bits,
        )
    }

    #[test]
    fn counts_zero_bits() {
        let mut hash = [0xff; 32];
        assert_eq!(leading_zero_bits(&hash), 0);
        hash[0] = 0;
        hash[1] = 0b0001_1111;
        assert_eq!(leading_zero_bits(&hash), 11);
        assert!(meets_difficulty(&hash, 11));
        assert!(!meets_difficulty(&hash, 12));
        assert!(meets_difficulty(&[0; 32], 256));
    }

    #[test]
    fn mining_and_verification_agree() {
        let context = FlyPowContext::new(template(6), FlyHashProfile::Reference).unwrap();
        let outcome = context.mine(0, 2_000);
        let solution = outcome.solution.expect("low difficulty should be found");
        assert!(context.verify_nonce(solution.nonce));
        assert!(context.verify_claim(solution.nonce, &solution.hash));

        let mut wrong_hash = solution.hash;
        wrong_hash[31] ^= 1;
        assert!(!context.verify_claim(solution.nonce, &wrong_hash));
    }

    #[test]
    fn template_change_changes_challenge() {
        let first = FlyPowContext::new(template(0), FlyHashProfile::Reference).unwrap();
        let mut changed = template(0);
        changed.timestamp += 1;
        let second = FlyPowContext::new(changed, FlyHashProfile::Reference).unwrap();
        assert_ne!(first.challenge(), second.challenge());
        assert_ne!(first.hash_nonce(0).hash, second.hash_nonce(0).hash);
    }

    #[test]
    fn dataset_pow_binds_synapses_and_useful_index() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("flypow-pow-{unique}.bin"));
        let mut file = File::create(&path).unwrap();
        for i in 0..20_u32 {
            let synapse = CanonicalSynapse {
                body_pre: (i % 4 + 1) as u64,
                body_post: ((i + 1) % 4 + 1) as u64,
                x_pre: i,
                y_pre: i + 1,
                z_pre: i + 2,
                x_post: i + 3,
                y_post: i + 4,
                z_post: i + 5,
            };
            file.write_all(&synapse.consensus_bytes()).unwrap();
        }
        file.sync_all().unwrap();
        drop(file);

        let dataset = CanonicalDataset::inspect(&path).unwrap();
        let epoch_seed = [3; 32];
        let miner_key = [4; 32];
        let index = UsefulIndex::build(&dataset, epoch_seed, miner_key).unwrap();
        let context =
            DatasetFlyPowContext::new(template(4), &dataset, &index, epoch_seed, miner_key)
                .unwrap();
        let first = context.hash_nonce(7).unwrap();
        let second = context.hash_nonce(7).unwrap();
        assert_eq!(
            dataset.merkle_root(),
            crate::hash::decode_hash(
                "0477d42c55e90725c24218bb4a7e607ab50c00bae3fc7c82a1e4dd26a81beb7a"
            )
            .unwrap()
        );
        assert_eq!(
            index.artifact_root(),
            crate::hash::decode_hash(
                "f7212e810f6300f40a0aaf63ccadbbeb5278d2cb90d61be1b4a5c66186e35648"
            )
            .unwrap()
        );
        assert_eq!(
            context.challenge(),
            crate::hash::decode_hash(
                "b960980e6e9c4cc247fa819c47c0109490f4ff65dc40cb386f39228271c81860"
            )
            .unwrap()
        );
        assert_eq!(
            first.hash,
            crate::hash::decode_hash(
                "51d7feb89027a4e2392adc932253d37465e78b7c9e68dc3781e8bd6f40d79366"
            )
            .unwrap()
        );
        assert_eq!(
            first.access_trace,
            crate::hash::decode_hash(
                "7fe8d4dd6f34a8a8748b7734b45df3db4305b0efa7580cd7ce32e34fb95f5072"
            )
            .unwrap()
        );
        assert_eq!(first, second);
        assert_ne!(first.hash, context.hash_nonce(8).unwrap().hash);

        let outcome = context.mine(0, 1_000).unwrap();
        let solution = outcome.solution.expect("low difficulty should be found");
        assert!(
            context
                .verify_claim(solution.nonce, &solution.hash)
                .unwrap()
        );

        drop(context);
        drop(index);
        drop(dataset);
        fs::remove_file(path).unwrap();
    }
}
