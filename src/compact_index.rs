//! Bounded-memory construction and dictionary-compressed storage for the full
//! official table, including its many small segmentation fragments. This
//! changes storage only; every fingerprint and the artifact root equal v1.
use std::{
    collections::HashMap,
    fs::{self, File, OpenOptions},
    io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write},
    path::Path,
};

use memmap2::{Mmap, MmapOptions};
use serde_json::json;

use crate::{
    CanonicalDataset, Hash256, encode_hex,
    flyhash::{FlyHashEngine, FlyHashProfile},
    hash::hash_parts,
    useful::{
        FINGERPRINT_NODE_DOMAIN, FingerprintLookup, IndexBuildProgress, NeuronFingerprint,
        UsefulIndexError, derive_sketch_seed, feature_bucket, fingerprint_leaf, quantize_count,
    },
};

const MAGIC: &[u8; 8] = b"FLYCMP1\0";
const HEADER: usize = 120;
const BODY_BYTES: usize = 12;
const CODE_BYTES: usize = 400;
const SHARDS: usize = 256;

#[derive(Default)]
struct MerkleAccumulator {
    levels: Vec<Option<Hash256>>,
}
impl MerkleAccumulator {
    fn add(&mut self, mut hash: Hash256) {
        let mut level = 0;
        loop {
            if level == self.levels.len() {
                self.levels.push(Some(hash));
                return;
            }
            if let Some(left) = self.levels[level].take() {
                hash = hash_parts(FINGERPRINT_NODE_DOMAIN, &[&left, &hash]);
                level += 1;
            } else {
                self.levels[level] = Some(hash);
                return;
            }
        }
    }
    fn root(&self) -> Result<Hash256, UsefulIndexError> {
        let mut right: Option<(Hash256, usize)> = None;
        for (level, node) in self.levels.iter().enumerate() {
            if let Some(left) = node {
                right = Some(match right {
                    None => (*left, level),
                    Some((mut hash, mut height)) => {
                        while height < level {
                            hash = hash_parts(FINGERPRINT_NODE_DOMAIN, &[&hash, &hash]);
                            height += 1;
                        }
                        (
                            hash_parts(FINGERPRINT_NODE_DOMAIN, &[left, &hash]),
                            level + 1,
                        )
                    }
                });
            }
        }
        right.map(|r| r.0).ok_or_else(|| invalid("empty index"))
    }
}
fn invalid(message: impl Into<String>) -> UsefulIndexError {
    UsefulIndexError::InvalidFormat(message.into())
}

pub struct CompactIndex {
    mmap: Mmap,
    dataset_root: Hash256,
    sketch_seed: Hash256,
    artifact_root: Hash256,
    bodies: usize,
    codes: usize,
}

impl CompactIndex {
    pub fn build(
        dataset: &CanonicalDataset,
        epoch_seed: Hash256,
        miner_key: Hash256,
        destination: &Path,
        mut progress: impl FnMut(IndexBuildProgress),
    ) -> Result<Self, UsefulIndexError> {
        if destination.exists() {
            return Err(invalid("refusing to overwrite completed compact index"));
        }
        let root = dataset.merkle_root();
        let seed = derive_sketch_seed(root, epoch_seed, miner_key);
        let seed_word = u64::from_le_bytes(seed[..8].try_into().unwrap());
        let work_dir = destination.with_extension("work");
        fs::create_dir_all(&work_dir)?;
        let partition_receipt = work_dir.join("partition.json");
        let expected_receipt = json!({"dataset_root":encode_hex(&root),"sketch_seed":encode_hex(&seed),"record_count":dataset.record_count(),"version":1});
        let partitions_ready = fs::read(&partition_receipt)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
            .as_ref()
            == Some(&expected_receipt);
        if !partitions_ready {
            progress(IndexBuildProgress {
                phase: "partitioning",
                completed: 0,
                total: dataset.record_count() * 2,
                bodies: 0,
            });
            let mut max_body = 0_u64;
            for i in 0..dataset.record_count() {
                let s = dataset.record(i).expect("bounded record");
                max_body = max_body.max(s.body_pre).max(s.body_post);
                if i % 5_000_000 == 0 {
                    progress(IndexBuildProgress {
                        phase: "partitioning",
                        completed: i,
                        total: dataset.record_count() * 2,
                        bodies: 0,
                    });
                }
            }
            let shift = (64 - max_body.leading_zeros()).saturating_sub(8);
            let mut writers = (0..SHARDS)
                .map(|i| {
                    File::create(work_dir.join(format!("shard-{i:03}.bin")))
                        .map(|file| BufWriter::with_capacity(256 * 1024, file))
                })
                .collect::<Result<Vec<_>, _>>()?;
            for i in 0..dataset.record_count() {
                let s = dataset.record(i).expect("bounded record");
                let outgoing =
                    feature_bucket(seed_word, s.body_post, [s.x_post, s.y_post, s.z_post], 0) as u8;
                let incoming = (25
                    + feature_bucket(seed_word, s.body_pre, [s.x_pre, s.y_pre, s.z_pre], 1))
                    as u8;
                for (body, bucket) in [(s.body_pre, outgoing), (s.body_post, incoming)] {
                    let mut bytes = [0; 9];
                    bytes[..8].copy_from_slice(&body.to_le_bytes());
                    bytes[8] = bucket;
                    writers[(body >> shift) as usize].write_all(&bytes)?;
                }
                if (i + 1) % 5_000_000 == 0 || i + 1 == dataset.record_count() {
                    progress(IndexBuildProgress {
                        phase: "partitioning",
                        completed: dataset.record_count() + i + 1,
                        total: dataset.record_count() * 2,
                        bodies: 0,
                    });
                }
            }
            for writer in &mut writers {
                writer.flush()?;
                writer.get_ref().sync_all()?;
            }
            fs::write(
                &partition_receipt,
                serde_json::to_vec(&expected_receipt).map_err(|e| invalid(e.to_string()))?,
            )?;
        }
        let partial = destination.with_extension("partial");
        let mut output = BufWriter::with_capacity(
            1024 * 1024,
            OpenOptions::new()
                .create(true)
                .truncate(true)
                .write(true)
                .open(&partial)?,
        );
        output.write_all(&[0; HEADER])?;
        let engine = FlyHashEngine::new(FlyHashProfile::Reference.params(), seed)?;
        let mut input_cache: HashMap<[u8; 50], u32> = HashMap::new();
        let mut code_ids: HashMap<Hash256, u32> = HashMap::new();
        let mut codes: Vec<[u32; 100]> = Vec::new();
        let mut merkle = MerkleAccumulator::default();
        let mut bodies = 0_usize;
        let mut contributions = 0_u64;
        for shard in 0..SHARDS {
            let file = File::open(work_dir.join(format!("shard-{shard:03}.bin")))?;
            if file.metadata()?.len() % 9 != 0 {
                return Err(invalid("truncated contribution shard"));
            }
            let entries = file.metadata()?.len() / 9;
            let mut reader = BufReader::with_capacity(1024 * 1024, file);
            let mut counts: HashMap<u64, [u32; 50]> = HashMap::new();
            for _ in 0..entries {
                let mut bytes = [0; 9];
                reader.read_exact(&mut bytes)?;
                let body = u64::from_le_bytes(bytes[..8].try_into().unwrap());
                if bytes[8] >= 50 {
                    return Err(invalid("invalid contribution bucket"));
                }
                let count = &mut counts.entry(body).or_insert([0; 50])[bytes[8] as usize];
                *count = count.saturating_add(1);
            }
            let mut ids = counts.keys().copied().collect::<Vec<_>>();
            ids.sort_unstable();
            for body in ids {
                let input = counts
                    .remove(&body)
                    .expect("known body ID")
                    .map(quantize_count);
                let code_id = if let Some(id) = input_cache.get(&input) {
                    *id
                } else {
                    let winners: [u32; 100] = engine
                        .hash_input(body, &input)?
                        .winners
                        .try_into()
                        .map_err(|_| invalid("wrong winner count"))?;
                    let mut packed = [0; 400];
                    for (i, w) in winners.iter().enumerate() {
                        packed[i * 4..i * 4 + 4].copy_from_slice(&w.to_le_bytes());
                    }
                    let code_hash = hash_parts(b"FlyPoW/compact-code-storage/v1", &[&packed]);
                    let id = if let Some(id) = code_ids.get(&code_hash) {
                        if codes[*id as usize] != winners {
                            return Err(invalid("code dictionary hash collision"));
                        }
                        *id
                    } else {
                        let id = u32::try_from(codes.len())
                            .map_err(|_| invalid("code dictionary too large"))?;
                        codes.push(winners);
                        code_ids.insert(code_hash, id);
                        id
                    };
                    if input_cache.len() < 1_000_000 {
                        input_cache.insert(input, id);
                    }
                    id
                };
                output.write_all(&body.to_le_bytes())?;
                output.write_all(&code_id.to_le_bytes())?;
                merkle.add(fingerprint_leaf(root, seed, body, &codes[code_id as usize]));
                bodies += 1;
                if bodies.is_multiple_of(100_000) {
                    progress(IndexBuildProgress {
                        phase: "indexing",
                        completed: contributions,
                        total: dataset.record_count() * 2,
                        bodies,
                    });
                }
            }
            contributions += entries;
            progress(IndexBuildProgress {
                phase: "indexing",
                completed: contributions,
                total: dataset.record_count() * 2,
                bodies,
            });
        }
        if contributions != dataset.record_count() * 2 {
            return Err(invalid("partition contribution count mismatch"));
        }
        let artifact_root = merkle.root()?;
        for code in &codes {
            for winner in code {
                output.write_all(&winner.to_le_bytes())?;
            }
        }
        output.flush()?;
        let mut file = output
            .into_inner()
            .map_err(|e| UsefulIndexError::Io(e.into_error()))?;
        file.seek(SeekFrom::Start(0))?;
        file.write_all(MAGIC)?;
        file.write_all(&(bodies as u64).to_le_bytes())?;
        file.write_all(&(codes.len() as u64).to_le_bytes())?;
        file.write_all(&root)?;
        file.write_all(&seed)?;
        file.write_all(&artifact_root)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&partial, destination)?;
        // Keep the contribution shards to support reproducible inspection and
        // retries; they are explicitly excluded from source control.
        Self::map(destination, root, seed, artifact_root)
    }

    fn map(
        path: &Path,
        root: Hash256,
        seed: Hash256,
        expected_artifact: Hash256,
    ) -> Result<Self, UsefulIndexError> {
        let file = File::open(path)?;
        // SAFETY: read-only artifact produced by this process; it must not be
        // modified while the service holds the mapping.
        let mmap = unsafe { MmapOptions::new().map(&file)? };
        if mmap.len() < HEADER || &mmap[..8] != MAGIC {
            return Err(invalid("invalid compact index header"));
        }
        let bodies = usize::try_from(u64::from_le_bytes(mmap[8..16].try_into().unwrap()))
            .map_err(|_| invalid("body count overflow"))?;
        let codes = usize::try_from(u64::from_le_bytes(mmap[16..24].try_into().unwrap()))
            .map_err(|_| invalid("code count overflow"))?;
        let size = bodies
            .checked_mul(BODY_BYTES)
            .and_then(|b| codes.checked_mul(CODE_BYTES).and_then(|c| b.checked_add(c)))
            .and_then(|s| s.checked_add(HEADER))
            .ok_or_else(|| invalid("index size overflow"))?;
        if bodies == 0 || codes == 0 || codes > u32::MAX as usize || size != mmap.len() {
            return Err(invalid("compact index length mismatch"));
        }
        let dataset_root = mmap[24..56].try_into().unwrap();
        let sketch_seed = mmap[56..88].try_into().unwrap();
        let artifact_root = mmap[88..120].try_into().unwrap();
        if root != dataset_root {
            return Err(UsefulIndexError::DatasetRootMismatch {
                expected: root,
                actual: dataset_root,
            });
        }
        if seed != sketch_seed {
            return Err(UsefulIndexError::SketchSeedMismatch {
                expected: seed,
                actual: sketch_seed,
            });
        }
        if expected_artifact != artifact_root {
            return Err(UsefulIndexError::ArtifactRootMismatch {
                expected: expected_artifact,
                actual: artifact_root,
            });
        }
        Ok(Self {
            mmap,
            dataset_root,
            sketch_seed,
            artifact_root,
            bodies,
            codes,
        })
    }

    pub fn open_verified(
        path: &Path,
        root: Hash256,
        seed: Hash256,
        expected_artifact: Hash256,
        mut progress: impl FnMut(IndexBuildProgress),
    ) -> Result<Self, UsefulIndexError> {
        let index = Self::map(path, root, seed, expected_artifact)?;
        for i in 0..index.codes {
            let winners = index.code(i);
            if winners.windows(2).any(|p| p[0] >= p[1]) || winners[99] >= 2000 {
                return Err(invalid("invalid compact index winners"));
            }
        }
        let mut merkle = MerkleAccumulator::default();
        let mut previous = None;
        for i in 0..index.bodies {
            let (body, code) = index.entry(i);
            if previous.is_some_and(|p| p >= body) || code >= index.codes {
                return Err(invalid("invalid compact body entry"));
            }
            merkle.add(fingerprint_leaf(root, seed, body, &index.code(code)));
            previous = Some(body);
            if i % 100_000 == 0 || i + 1 == index.bodies {
                progress(IndexBuildProgress {
                    phase: "index_loading",
                    completed: (i + 1) as u64,
                    total: index.bodies as u64,
                    bodies: index.bodies,
                });
            }
        }
        let actual = merkle.root()?;
        if actual != expected_artifact {
            return Err(UsefulIndexError::ArtifactRootMismatch {
                expected: expected_artifact,
                actual,
            });
        }
        Ok(index)
    }

    fn entry(&self, index: usize) -> (u64, usize) {
        let start = HEADER + index * BODY_BYTES;
        (
            u64::from_le_bytes(self.mmap[start..start + 8].try_into().unwrap()),
            u32::from_le_bytes(self.mmap[start + 8..start + 12].try_into().unwrap()) as usize,
        )
    }
    fn code(&self, id: usize) -> [u32; 100] {
        let start = HEADER + self.bodies * BODY_BYTES + id * CODE_BYTES;
        let mut code = [0; 100];
        for (i, value) in code.iter_mut().enumerate() {
            *value = u32::from_le_bytes(
                self.mmap[start + i * 4..start + i * 4 + 4]
                    .try_into()
                    .unwrap(),
            );
        }
        code
    }
    pub fn len(&self) -> usize {
        self.bodies
    }
    pub fn is_empty(&self) -> bool {
        self.bodies == 0
    }
    pub fn byte_len(&self) -> usize {
        self.mmap.len()
    }
    pub fn unique_codes(&self) -> usize {
        self.codes
    }
    pub fn first_body_id(&self) -> u64 {
        self.entry(0).0
    }
}

impl FingerprintLookup for CompactIndex {
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
        let mut low = 0;
        let mut high = self.bodies;
        while low < high {
            let mid = low + (high - low) / 2;
            if self.entry(mid).0 < body_id {
                low = mid + 1;
            } else {
                high = mid;
            }
        }
        if low == self.bodies {
            return None;
        }
        let (body, code) = self.entry(low);
        if body != body_id {
            return None;
        }
        let winners = self.code(code).to_vec();
        let leaf_hash = fingerprint_leaf(self.dataset_root, self.sketch_seed, body, &winners);
        Some(NeuronFingerprint {
            body_id,
            winners,
            leaf_hash,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compact_storage_preserves_all_v1_fingerprints_and_rejects_corruption() {
        use crate::{CanonicalSynapse, UsefulIndex};
        let dir = tempfile::tempdir().unwrap();
        let data_path = dir.path().join("data.bin");
        let mut file = File::create(&data_path).unwrap();
        for i in 0..75_u32 {
            let s = CanonicalSynapse {
                body_pre: (i % 7 + 1) as u64,
                body_post: ((i % 11 + 1) as u64) << 56,
                x_pre: i,
                y_pre: i + 1,
                z_pre: i + 2,
                x_post: i + 3,
                y_post: i + 4,
                z_post: i + 5,
            };
            file.write_all(&s.consensus_bytes()).unwrap();
        }
        drop(file);
        let dataset = CanonicalDataset::inspect(data_path).unwrap();
        let epoch = [3; 32];
        let key = [4; 32];
        let reference = UsefulIndex::build(&dataset, epoch, key).unwrap();
        let index_path = dir.path().join("compact.bin");
        let compact = CompactIndex::build(&dataset, epoch, key, &index_path, |_| {}).unwrap();
        assert_eq!(compact.artifact_root(), reference.artifact_root());
        assert_eq!(compact.len(), reference.len());
        for fingerprint in reference.fingerprints() {
            assert_eq!(
                compact.fingerprint(fingerprint.body_id).as_ref(),
                Some(fingerprint)
            );
        }
        let reopened = CompactIndex::open_verified(
            &index_path,
            dataset.merkle_root(),
            reference.sketch_seed(),
            reference.artifact_root(),
            |_| {},
        )
        .unwrap();
        assert_eq!(reopened.artifact_root(), reference.artifact_root());
        assert!(reopened.fingerprint(u64::MAX).is_none());
        drop(compact);
        drop(reopened);
        let mut changed = OpenOptions::new().write(true).open(&index_path).unwrap();
        changed.seek(SeekFrom::Start((HEADER + 8) as u64)).unwrap();
        changed.write_all(&u32::MAX.to_le_bytes()).unwrap();
        drop(changed);
        assert!(
            CompactIndex::open_verified(
                &index_path,
                dataset.merkle_root(),
                reference.sketch_seed(),
                reference.artifact_root(),
                |_| {}
            )
            .is_err()
        );
    }
    #[test]
    fn streaming_merkle_matches_duplicate_last_tree() {
        for count in 1..130 {
            let mut leaves = Vec::new();
            let mut stream = MerkleAccumulator::default();
            for i in 0_u64..count {
                let leaf = hash_parts(b"test", &[&i.to_le_bytes()]);
                leaves.push(leaf);
                stream.add(leaf);
            }
            while leaves.len() > 1 {
                leaves = leaves
                    .chunks(2)
                    .map(|p| {
                        hash_parts(FINGERPRINT_NODE_DOMAIN, &[&p[0], p.get(1).unwrap_or(&p[0])])
                    })
                    .collect();
            }
            assert_eq!(stream.root().unwrap(), leaves[0], "{count} leaves");
        }
    }
}
