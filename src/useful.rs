use core::fmt;
use std::{
    collections::HashMap,
    fs::{self, OpenOptions},
    io::{self, Write},
    path::Path,
};

use crate::{
    dataset::{CanonicalDataset, CanonicalSynapse},
    flyhash::{FlyHashEngine, FlyHashError, FlyHashProfile},
    hash::{Hash256, encode_hex, hash_parts},
};

pub const SKETCH_DIMENSIONS: usize = 50;
pub const DIRECTION_BUCKETS: usize = SKETCH_DIMENSIONS / 2;
pub const FINGERPRINT_WINNERS: usize = 100;

const INDEX_MAGIC: &[u8; 8] = b"FLYIDX1\0";
const INDEX_VERSION: u16 = 1;
const INDEX_HEADER_BYTES: usize = 8 + 2 + 2 + 8 + 32 + 32 + 32;
const INDEX_RECORD_BYTES: usize = 8 + FINGERPRINT_WINNERS * 4;
const SKETCH_SEED_DOMAIN: &[u8] = b"FlyPoW/useful-sketch-seed/v1";
const FINGERPRINT_LEAF_DOMAIN: &[u8] = b"FlyPoW/fingerprint-leaf/v1";
pub(crate) const FINGERPRINT_NODE_DOMAIN: &[u8] = b"FlyPoW/fingerprint-node/v1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NeuronFingerprint {
    pub body_id: u64,
    pub winners: Vec<u32>,
    pub leaf_hash: Hash256,
}

pub trait FingerprintLookup: Send + Sync {
    fn dataset_root(&self) -> Hash256;
    fn sketch_seed(&self) -> Hash256;
    fn artifact_root(&self) -> Hash256;
    fn fingerprint(&self, body_id: u64) -> Option<NeuronFingerprint>;
}

impl FingerprintLookup for UsefulIndex {
    fn dataset_root(&self) -> Hash256 {
        self.dataset_root
    }
    fn sketch_seed(&self) -> Hash256 {
        self.sketch_seed
    }
    fn artifact_root(&self) -> Hash256 {
        self.artifact_root
    }
    fn fingerprint(&self, body_id: u64) -> Option<NeuronFingerprint> {
        UsefulIndex::fingerprint(self, body_id).cloned()
    }
}

#[derive(Debug)]
pub enum UsefulIndexError {
    Io(io::Error),
    FlyHash(FlyHashError),
    InvalidFormat(String),
    DatasetRootMismatch { expected: Hash256, actual: Hash256 },
    SketchSeedMismatch { expected: Hash256, actual: Hash256 },
    ArtifactRootMismatch { expected: Hash256, actual: Hash256 },
}

impl fmt::Display for UsefulIndexError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "useful-index I/O error: {error}"),
            Self::FlyHash(error) => write!(f, "FlyHash error while building index: {error}"),
            Self::InvalidFormat(message) => write!(f, "invalid useful-index format: {message}"),
            Self::DatasetRootMismatch { expected, actual } => write!(
                f,
                "index dataset root mismatch: expected {}, got {}",
                encode_hex(expected),
                encode_hex(actual)
            ),
            Self::SketchSeedMismatch { expected, actual } => write!(
                f,
                "index sketch seed mismatch: expected {}, got {}",
                encode_hex(expected),
                encode_hex(actual)
            ),
            Self::ArtifactRootMismatch { expected, actual } => write!(
                f,
                "index artifact root mismatch: expected {}, got {}",
                encode_hex(expected),
                encode_hex(actual)
            ),
        }
    }
}

impl std::error::Error for UsefulIndexError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::FlyHash(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for UsefulIndexError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<FlyHashError> for UsefulIndexError {
    fn from(value: FlyHashError) -> Self {
        Self::FlyHash(value)
    }
}

/// A deterministic, content-addressed ANN table over connectome neurons.
///
/// For each body ID, all incoming and outgoing synapses are accumulated into a
/// 50-dimensional direction-aware count sketch. The reference FlyHash sparse
/// projection then expands it to 2,000 dimensions and retains 100 winners.
/// Hamming overlap between these fingerprints is useful as a first-stage
/// candidate search for neurons with similar connection patterns.
#[derive(Debug, Clone)]
pub struct UsefulIndex {
    dataset_root: Hash256,
    sketch_seed: Hash256,
    artifact_root: Hash256,
    fingerprints: Vec<NeuronFingerprint>,
}

#[derive(Debug, Clone, Copy)]
pub struct IndexBuildProgress {
    pub phase: &'static str,
    pub completed: u64,
    pub total: u64,
    pub bodies: usize,
}

impl UsefulIndex {
    pub fn build(
        dataset: &CanonicalDataset,
        epoch_seed: Hash256,
        miner_key: Hash256,
    ) -> Result<Self, UsefulIndexError> {
        Self::build_with_progress(dataset, epoch_seed, miner_key, |_| {})
    }

    pub fn build_with_progress(
        dataset: &CanonicalDataset,
        epoch_seed: Hash256,
        miner_key: Hash256,
        mut progress: impl FnMut(IndexBuildProgress),
    ) -> Result<Self, UsefulIndexError> {
        let dataset_root = dataset.merkle_root();
        let sketch_seed = derive_sketch_seed(dataset_root, epoch_seed, miner_key);
        let seed_word = u64::from_le_bytes(sketch_seed[..8].try_into().unwrap());

        let mut sketches: HashMap<u64, [u32; SKETCH_DIMENSIONS]> = HashMap::new();
        progress(IndexBuildProgress {
            phase: "sketching",
            completed: 0,
            total: dataset.record_count(),
            bodies: 0,
        });
        for index in 0..dataset.record_count() {
            let synapse = dataset
                .record(index)
                .expect("the record index is bounded by dataset.record_count()");
            accumulate_synapse(&mut sketches, synapse, seed_word);
            if (index + 1) % 1_000_000 == 0 || index + 1 == dataset.record_count() {
                progress(IndexBuildProgress {
                    phase: "sketching",
                    completed: index + 1,
                    total: dataset.record_count(),
                    bodies: sketches.len(),
                });
            }
        }

        let engine = FlyHashEngine::new(FlyHashProfile::Reference.params(), sketch_seed)?;
        let mut body_ids = sketches.keys().copied().collect::<Vec<_>>();
        body_ids.sort_unstable();

        let mut fingerprints = Vec::with_capacity(body_ids.len());
        let body_count = body_ids.len();
        // Quantized fragment sketches often repeat. Reusing only their winner
        // sets preserves every consensus byte: the leaf still binds body_id.
        let mut winner_cache: HashMap<[u8; SKETCH_DIMENSIONS], Vec<u32>> = HashMap::new();
        progress(IndexBuildProgress {
            phase: "indexing",
            completed: 0,
            total: body_count as u64,
            bodies: body_count,
        });
        for body_id in body_ids {
            let counts = sketches
                .remove(&body_id)
                .expect("body ID came from the accumulator map");
            let input = counts.map(quantize_count);
            let winners = if let Some(cached) = winner_cache.get(&input) {
                cached.clone()
            } else {
                let winners = engine.hash_input(body_id, &input)?.winners;
                if winner_cache.len() < 4_096 {
                    winner_cache.insert(input, winners.clone());
                }
                winners
            };
            debug_assert_eq!(winners.len(), FINGERPRINT_WINNERS);
            let leaf_hash = fingerprint_leaf(dataset_root, sketch_seed, body_id, &winners);
            fingerprints.push(NeuronFingerprint {
                body_id,
                winners,
                leaf_hash,
            });
            if fingerprints.len() % 10_000 == 0 || fingerprints.len() == body_count {
                progress(IndexBuildProgress {
                    phase: "indexing",
                    completed: fingerprints.len() as u64,
                    total: body_count as u64,
                    bodies: body_count,
                });
            }
        }
        drop(sketches);

        let artifact_root = fingerprint_merkle_root(
            &fingerprints
                .iter()
                .map(|fingerprint| fingerprint.leaf_hash)
                .collect::<Vec<_>>(),
        )?;

        Ok(Self {
            dataset_root,
            sketch_seed,
            artifact_root,
            fingerprints,
        })
    }

    pub fn load_verified(
        path: impl AsRef<Path>,
        expected_dataset_root: Hash256,
        expected_sketch_seed: Hash256,
    ) -> Result<Self, UsefulIndexError> {
        let bytes = fs::read(path)?;
        if bytes.len() < INDEX_HEADER_BYTES {
            return Err(UsefulIndexError::InvalidFormat(format!(
                "file is {} bytes; header needs {INDEX_HEADER_BYTES}",
                bytes.len()
            )));
        }
        if &bytes[..8] != INDEX_MAGIC {
            return Err(UsefulIndexError::InvalidFormat("wrong magic".into()));
        }

        let version = u16::from_le_bytes(bytes[8..10].try_into().unwrap());
        if version != INDEX_VERSION {
            return Err(UsefulIndexError::InvalidFormat(format!(
                "unsupported version {version}"
            )));
        }
        let winner_count = u16::from_le_bytes(bytes[10..12].try_into().unwrap()) as usize;
        if winner_count != FINGERPRINT_WINNERS {
            return Err(UsefulIndexError::InvalidFormat(format!(
                "expected {FINGERPRINT_WINNERS} winners, got {winner_count}"
            )));
        }
        let fingerprint_count = u64::from_le_bytes(bytes[12..20].try_into().unwrap());
        let expected_len = INDEX_HEADER_BYTES
            .checked_add(
                usize::try_from(fingerprint_count)
                    .map_err(|_| UsefulIndexError::InvalidFormat("too many fingerprints".into()))?
                    .checked_mul(INDEX_RECORD_BYTES)
                    .ok_or_else(|| {
                        UsefulIndexError::InvalidFormat("index length overflow".into())
                    })?,
            )
            .ok_or_else(|| UsefulIndexError::InvalidFormat("index length overflow".into()))?;
        if bytes.len() != expected_len {
            return Err(UsefulIndexError::InvalidFormat(format!(
                "expected {expected_len} bytes, got {}",
                bytes.len()
            )));
        }

        let dataset_root: Hash256 = bytes[20..52].try_into().unwrap();
        let sketch_seed: Hash256 = bytes[52..84].try_into().unwrap();
        let claimed_artifact_root: Hash256 = bytes[84..116].try_into().unwrap();
        if dataset_root != expected_dataset_root {
            return Err(UsefulIndexError::DatasetRootMismatch {
                expected: expected_dataset_root,
                actual: dataset_root,
            });
        }
        if sketch_seed != expected_sketch_seed {
            return Err(UsefulIndexError::SketchSeedMismatch {
                expected: expected_sketch_seed,
                actual: sketch_seed,
            });
        }

        let mut fingerprints = Vec::with_capacity(fingerprint_count as usize);
        let mut previous_body_id = None;
        for raw in bytes[INDEX_HEADER_BYTES..]
            .as_chunks::<INDEX_RECORD_BYTES>()
            .0
        {
            let body_id = u64::from_le_bytes(raw[..8].try_into().unwrap());
            if previous_body_id.is_some_and(|previous| previous >= body_id) {
                return Err(UsefulIndexError::InvalidFormat(
                    "body IDs are not strictly increasing".into(),
                ));
            }
            previous_body_id = Some(body_id);

            let mut winners = Vec::with_capacity(FINGERPRINT_WINNERS);
            for winner_bytes in raw[8..].as_chunks::<4>().0 {
                winners.push(u32::from_le_bytes(*winner_bytes));
            }
            if winners.windows(2).any(|pair| pair[0] >= pair[1])
                || winners.last().is_some_and(|&winner| winner >= 2_000)
            {
                return Err(UsefulIndexError::InvalidFormat(format!(
                    "invalid winner list for body {body_id}"
                )));
            }
            let leaf_hash = fingerprint_leaf(dataset_root, sketch_seed, body_id, &winners);
            fingerprints.push(NeuronFingerprint {
                body_id,
                winners,
                leaf_hash,
            });
        }

        let actual_artifact_root = fingerprint_merkle_root(
            &fingerprints
                .iter()
                .map(|fingerprint| fingerprint.leaf_hash)
                .collect::<Vec<_>>(),
        )?;
        if actual_artifact_root != claimed_artifact_root {
            return Err(UsefulIndexError::ArtifactRootMismatch {
                expected: claimed_artifact_root,
                actual: actual_artifact_root,
            });
        }

        Ok(Self {
            dataset_root,
            sketch_seed,
            artifact_root: actual_artifact_root,
            fingerprints,
        })
    }

    /// Writes a new artifact and refuses to overwrite an existing file.
    pub fn write_new(&self, path: impl AsRef<Path>) -> Result<(), UsefulIndexError> {
        let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
        file.write_all(INDEX_MAGIC)?;
        file.write_all(&INDEX_VERSION.to_le_bytes())?;
        file.write_all(&(FINGERPRINT_WINNERS as u16).to_le_bytes())?;
        file.write_all(&(self.fingerprints.len() as u64).to_le_bytes())?;
        file.write_all(&self.dataset_root)?;
        file.write_all(&self.sketch_seed)?;
        file.write_all(&self.artifact_root)?;
        for fingerprint in &self.fingerprints {
            file.write_all(&fingerprint.body_id.to_le_bytes())?;
            for &winner in &fingerprint.winners {
                file.write_all(&winner.to_le_bytes())?;
            }
        }
        file.sync_all()?;
        Ok(())
    }

    pub fn dataset_root(&self) -> Hash256 {
        self.dataset_root
    }

    pub fn sketch_seed(&self) -> Hash256 {
        self.sketch_seed
    }

    pub fn artifact_root(&self) -> Hash256 {
        self.artifact_root
    }

    pub fn fingerprints(&self) -> &[NeuronFingerprint] {
        &self.fingerprints
    }

    pub fn len(&self) -> usize {
        self.fingerprints.len()
    }

    pub fn is_empty(&self) -> bool {
        self.fingerprints.is_empty()
    }

    pub fn fingerprint(&self, body_id: u64) -> Option<&NeuronFingerprint> {
        self.fingerprints
            .binary_search_by_key(&body_id, |fingerprint| fingerprint.body_id)
            .ok()
            .map(|index| &self.fingerprints[index])
    }
}

pub fn derive_sketch_seed(
    dataset_root: Hash256,
    epoch_seed: Hash256,
    miner_key: Hash256,
) -> Hash256 {
    hash_parts(
        SKETCH_SEED_DOMAIN,
        &[&dataset_root, &epoch_seed, &miner_key],
    )
}

fn accumulate_synapse(
    sketches: &mut HashMap<u64, [u32; SKETCH_DIMENSIONS]>,
    synapse: CanonicalSynapse,
    seed: u64,
) {
    let outgoing_bucket = feature_bucket(
        seed,
        synapse.body_post,
        [synapse.x_post, synapse.y_post, synapse.z_post],
        0,
    );
    let incoming_bucket = DIRECTION_BUCKETS
        + feature_bucket(
            seed,
            synapse.body_pre,
            [synapse.x_pre, synapse.y_pre, synapse.z_pre],
            1,
        );
    let outgoing = sketches
        .entry(synapse.body_pre)
        .or_insert([0; SKETCH_DIMENSIONS]);
    outgoing[outgoing_bucket] = outgoing[outgoing_bucket].saturating_add(1);
    let incoming = sketches
        .entry(synapse.body_post)
        .or_insert([0; SKETCH_DIMENSIONS]);
    incoming[incoming_bucket] = incoming[incoming_bucket].saturating_add(1);
}

pub(crate) fn feature_bucket(
    seed: u64,
    partner: u64,
    coordinates: [u32; 3],
    direction: u64,
) -> usize {
    let mut value = seed
        ^ partner.rotate_left(17)
        ^ (coordinates[0] as u64).rotate_left(7)
        ^ (coordinates[1] as u64).rotate_left(29)
        ^ (coordinates[2] as u64).rotate_left(43)
        ^ direction.wrapping_mul(0xd6e8_feb8_6659_fd93);
    value ^= value >> 30;
    value = value.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value ^= value >> 27;
    value = value.wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^= value >> 31;
    (value % DIRECTION_BUCKETS as u64) as usize
}

pub(crate) fn quantize_count(count: u32) -> u8 {
    if count == 0 {
        0
    } else {
        ((count.ilog2() + 1) * 16).min(u8::MAX as u32) as u8
    }
}

pub(crate) fn fingerprint_leaf(
    dataset_root: Hash256,
    sketch_seed: Hash256,
    body_id: u64,
    winners: &[u32],
) -> Hash256 {
    let mut sparse_code = Vec::with_capacity(winners.len() * 4);
    for &winner in winners {
        sparse_code.extend_from_slice(&winner.to_le_bytes());
    }
    hash_parts(
        FINGERPRINT_LEAF_DOMAIN,
        &[
            &dataset_root,
            &sketch_seed,
            &body_id.to_le_bytes(),
            &sparse_code,
        ],
    )
}

fn fingerprint_merkle_root(leaves: &[Hash256]) -> Result<Hash256, UsefulIndexError> {
    if leaves.is_empty() {
        return Err(UsefulIndexError::InvalidFormat(
            "an index must contain at least one neuron".into(),
        ));
    }
    let mut level = leaves.to_vec();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            let left = &pair[0];
            let right = pair.get(1).unwrap_or(left);
            next.push(hash_parts(FINGERPRINT_NODE_DOMAIN, &[left, right]));
        }
        level = next;
    }
    Ok(level[0])
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs::{self, File},
        io::Write,
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    fn unique_path(suffix: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("flypow-{unique}-{suffix}"))
    }

    fn tiny_dataset() -> (PathBuf, CanonicalDataset) {
        let path = unique_path("synapses.bin");
        let mut file = File::create(&path).unwrap();
        for i in 0..12_u32 {
            let record = CanonicalSynapse {
                body_pre: (i % 3 + 1) as u64,
                body_post: ((i + 1) % 3 + 1) as u64,
                x_pre: i,
                y_pre: i + 1,
                z_pre: i + 2,
                x_post: i + 3,
                y_post: i + 4,
                z_post: i + 5,
            };
            file.write_all(&record.consensus_bytes()).unwrap();
        }
        file.sync_all().unwrap();
        drop(file);
        let dataset = CanonicalDataset::inspect(&path).unwrap();
        (path, dataset)
    }

    #[test]
    fn builds_deterministic_useful_index_and_round_trips() {
        let (dataset_path, dataset) = tiny_dataset();
        let epoch_seed = [9; 32];
        let miner_key = [7; 32];
        let first = UsefulIndex::build(&dataset, epoch_seed, miner_key).unwrap();
        let second = UsefulIndex::build(&dataset, epoch_seed, miner_key).unwrap();
        assert_eq!(first.artifact_root(), second.artifact_root());
        assert_eq!(first.len(), 3);
        assert!(first.fingerprint(2).is_some());

        let index_path = unique_path("index.bin");
        first.write_new(&index_path).unwrap();
        let loaded = UsefulIndex::load_verified(
            &index_path,
            dataset.merkle_root(),
            derive_sketch_seed(dataset.merkle_root(), epoch_seed, miner_key),
        )
        .unwrap();
        assert_eq!(loaded.artifact_root(), first.artifact_root());
        assert_eq!(loaded.fingerprint(3), first.fingerprint(3));

        drop(dataset);
        fs::remove_file(index_path).unwrap();
        fs::remove_file(dataset_path).unwrap();
    }
}
