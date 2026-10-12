use core::fmt;
use std::{
    fs::File,
    io,
    path::{Path, PathBuf},
};

use memmap2::{Mmap, MmapOptions};

use crate::hash::{Hash256, encode_hex, hash_parts};

pub const OFFICIAL_DATASET_NAME: &str = "MaleCNS v1.0";
pub const OFFICIAL_DATASET_PAGE: &str = "https://male-cns.janelia.org/download/";
pub const OFFICIAL_SOURCE_URL: &str = "https://storage.googleapis.com/flyem-male-cns/v1.0/connectome-data/flat-connectome/syn-partners-male-cns-v1.0-minconf-0.5.feather";
pub const OFFICIAL_SOURCE_OBJECT: &str = "gs://flyem-male-cns/v1.0/connectome-data/flat-connectome/syn-partners-male-cns-v1.0-minconf-0.5.feather";
pub const OFFICIAL_SOURCE_SIZE: u64 = 6_777_179_098;
pub const OFFICIAL_SOURCE_MD5_HEX: &str = "58efcf712f8c4d4de5f2ad51e97def76";
pub const OFFICIAL_SOURCE_CRC32C_HEX: &str = "8d394d20";
pub const OFFICIAL_SOURCE_GENERATION: u64 = 1_780_494_942_562_468;
pub const OFFICIAL_LICENSE: &str = "CC-BY-4.0";
pub const REPORTED_SYNAPSE_COUNT: u64 = 125_000_000;

/// Canonical record layout produced by `tools/prepare_dataset.py`.
///
/// Every row of the official `syn-partners` Feather table becomes one 40-byte
/// little-endian record, in the exact official row order. Confidence and ROI
/// labels are intentionally excluded from consensus v1 to avoid floating-point
/// and dictionary-encoding ambiguity. Body IDs plus both endpoint coordinates
/// preserve the identity of every synaptic partner row.
pub const CANONICAL_RECORD_BYTES: usize = 40;
pub const DATASET_CHUNK_RECORDS: usize = 4_096;
pub const DATASET_CHUNK_BYTES: usize = CANONICAL_RECORD_BYTES * DATASET_CHUNK_RECORDS;

const DATASET_LEAF_DOMAIN: &[u8] = b"FlyPoW/dataset-leaf/v1";
const DATASET_NODE_DOMAIN: &[u8] = b"FlyPoW/dataset-node/v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CanonicalSynapse {
    pub body_pre: u64,
    pub body_post: u64,
    pub x_pre: u32,
    pub y_pre: u32,
    pub z_pre: u32,
    pub x_post: u32,
    pub y_post: u32,
    pub z_post: u32,
}

impl CanonicalSynapse {
    pub fn consensus_bytes(self) -> [u8; CANONICAL_RECORD_BYTES] {
        let mut output = [0_u8; CANONICAL_RECORD_BYTES];
        output[0..8].copy_from_slice(&self.body_pre.to_le_bytes());
        output[8..16].copy_from_slice(&self.body_post.to_le_bytes());
        output[16..20].copy_from_slice(&self.x_pre.to_le_bytes());
        output[20..24].copy_from_slice(&self.y_pre.to_le_bytes());
        output[24..28].copy_from_slice(&self.z_pre.to_le_bytes());
        output[28..32].copy_from_slice(&self.x_post.to_le_bytes());
        output[32..36].copy_from_slice(&self.y_post.to_le_bytes());
        output[36..40].copy_from_slice(&self.z_post.to_le_bytes());
        output
    }

    pub fn from_consensus_bytes(bytes: &[u8; CANONICAL_RECORD_BYTES]) -> Self {
        Self {
            body_pre: u64::from_le_bytes(bytes[0..8].try_into().unwrap()),
            body_post: u64::from_le_bytes(bytes[8..16].try_into().unwrap()),
            x_pre: u32::from_le_bytes(bytes[16..20].try_into().unwrap()),
            y_pre: u32::from_le_bytes(bytes[20..24].try_into().unwrap()),
            z_pre: u32::from_le_bytes(bytes[24..28].try_into().unwrap()),
            x_post: u32::from_le_bytes(bytes[28..32].try_into().unwrap()),
            y_post: u32::from_le_bytes(bytes[32..36].try_into().unwrap()),
            z_post: u32::from_le_bytes(bytes[36..40].try_into().unwrap()),
        }
    }
}

#[derive(Debug)]
pub enum DatasetError {
    Io(io::Error),
    Empty,
    MisalignedLength { bytes: u64, record_bytes: usize },
    RootMismatch { expected: Hash256, actual: Hash256 },
    RecordOutOfBounds { index: u64, records: u64 },
}

impl fmt::Display for DatasetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "dataset I/O error: {error}"),
            Self::Empty => f.write_str("canonical dataset is empty"),
            Self::MisalignedLength {
                bytes,
                record_bytes,
            } => write!(
                f,
                "canonical dataset has {bytes} bytes, not a multiple of {record_bytes}"
            ),
            Self::RootMismatch { expected, actual } => write!(
                f,
                "dataset Merkle root mismatch: expected {}, got {}",
                encode_hex(expected),
                encode_hex(actual)
            ),
            Self::RecordOutOfBounds { index, records } => {
                write!(f, "synapse index {index} is outside 0..{records}")
            }
        }
    }
}

impl std::error::Error for DatasetError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for DatasetError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

/// Memory-mapped canonical synapse data plus its fully verified Merkle tree.
///
/// Opening the dataset hashes every byte before returning. This is the local
/// full-scan gate before mining. It proves file identity, but no software can
/// prove that an operating system keeps every page resident in physical RAM.
pub struct CanonicalDataset {
    path: PathBuf,
    mmap: Mmap,
    record_count: u64,
    leaf_hashes: Vec<Hash256>,
    merkle_root: Hash256,
}

impl fmt::Debug for CanonicalDataset {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CanonicalDataset")
            .field("path", &self.path)
            .field("bytes", &self.mmap.len())
            .field("record_count", &self.record_count)
            .field("chunks", &self.leaf_hashes.len())
            .field("merkle_root", &encode_hex(&self.merkle_root))
            .finish()
    }
}

impl CanonicalDataset {
    /// Inspects and hashes a canonical file without enforcing a network root.
    /// Use this only to reproduce a candidate root independently.
    pub fn inspect(path: impl AsRef<Path>) -> Result<Self, DatasetError> {
        Self::open_inner(path.as_ref(), None)
    }

    /// Opens a canonical file and refuses it unless its full Merkle root is the
    /// network-approved value.
    pub fn open_verified(
        path: impl AsRef<Path>,
        expected_root: Hash256,
    ) -> Result<Self, DatasetError> {
        Self::open_inner(path.as_ref(), Some(expected_root))
    }

    fn open_inner(path: &Path, expected_root: Option<Hash256>) -> Result<Self, DatasetError> {
        let file = File::open(path)?;
        let bytes = file.metadata()?.len();
        if bytes == 0 {
            return Err(DatasetError::Empty);
        }
        if bytes % CANONICAL_RECORD_BYTES as u64 != 0 {
            return Err(DatasetError::MisalignedLength {
                bytes,
                record_bytes: CANONICAL_RECORD_BYTES,
            });
        }

        // SAFETY: The mapping is read-only and retained by this object. Users
        // must not modify the canonical file while a miner is running.
        let mmap = unsafe { MmapOptions::new().map(&file)? };
        let leaf_hashes = hash_dataset_chunks(&mmap);
        let merkle_root = merkle_root_from_leaves(&leaf_hashes);

        if let Some(expected) = expected_root
            && expected != merkle_root
        {
            return Err(DatasetError::RootMismatch {
                expected,
                actual: merkle_root,
            });
        }

        Ok(Self {
            path: path.to_path_buf(),
            mmap,
            record_count: bytes / CANONICAL_RECORD_BYTES as u64,
            leaf_hashes,
            merkle_root,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn byte_len(&self) -> u64 {
        self.mmap.len() as u64
    }

    pub fn record_count(&self) -> u64 {
        self.record_count
    }

    pub fn chunk_count(&self) -> usize {
        self.leaf_hashes.len()
    }

    pub fn merkle_root(&self) -> Hash256 {
        self.merkle_root
    }

    pub fn chunk_hash(&self, chunk_index: usize) -> Option<Hash256> {
        self.leaf_hashes.get(chunk_index).copied()
    }

    pub fn raw_record(&self, index: u64) -> Result<&[u8; CANONICAL_RECORD_BYTES], DatasetError> {
        if index >= self.record_count {
            return Err(DatasetError::RecordOutOfBounds {
                index,
                records: self.record_count,
            });
        }
        let start = index as usize * CANONICAL_RECORD_BYTES;
        Ok(self.mmap[start..start + CANONICAL_RECORD_BYTES]
            .try_into()
            .expect("record boundaries were validated when the dataset opened"))
    }

    pub fn record(&self, index: u64) -> Result<CanonicalSynapse, DatasetError> {
        self.raw_record(index)
            .map(CanonicalSynapse::from_consensus_bytes)
    }

    pub fn chunk_index_for_record(&self, record_index: u64) -> usize {
        record_index as usize / DATASET_CHUNK_RECORDS
    }
}

fn hash_dataset_chunks(bytes: &[u8]) -> Vec<Hash256> {
    bytes
        .chunks(DATASET_CHUNK_BYTES)
        .enumerate()
        .map(|(index, chunk)| {
            let index_bytes = (index as u64).to_le_bytes();
            hash_parts(DATASET_LEAF_DOMAIN, &[&index_bytes, chunk])
        })
        .collect()
}

pub(crate) fn merkle_root_from_leaves(leaves: &[Hash256]) -> Hash256 {
    assert!(!leaves.is_empty(), "Merkle trees require at least one leaf");
    let mut level = leaves.to_vec();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            let left = &pair[0];
            let right = pair.get(1).unwrap_or(left);
            next.push(hash_parts(DATASET_NODE_DOMAIN, &[left, right]));
        }
        level = next;
    }
    level[0]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        io::Write,
        time::{SystemTime, UNIX_EPOCH},
    };

    fn temporary_dataset(records: &[CanonicalSynapse]) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("flypow-dataset-{unique}.bin"));
        let mut file = File::create(&path).unwrap();
        for record in records {
            file.write_all(&record.consensus_bytes()).unwrap();
        }
        file.sync_all().unwrap();
        path
    }

    #[test]
    fn opens_and_reads_canonical_records() {
        let records = [
            CanonicalSynapse {
                body_pre: 10,
                body_post: 20,
                x_pre: 1,
                y_pre: 2,
                z_pre: 3,
                x_post: 4,
                y_post: 5,
                z_post: 6,
            },
            CanonicalSynapse {
                body_pre: 20,
                body_post: 30,
                x_pre: 7,
                y_pre: 8,
                z_pre: 9,
                x_post: 10,
                y_post: 11,
                z_post: 12,
            },
        ];
        let path = temporary_dataset(&records);
        let dataset = CanonicalDataset::inspect(&path).unwrap();
        assert_eq!(dataset.record_count(), 2);
        assert_eq!(dataset.record(0).unwrap(), records[0]);
        assert_eq!(dataset.record(1).unwrap(), records[1]);
        assert!(CanonicalDataset::open_verified(&path, dataset.merkle_root()).is_ok());

        let mut wrong = dataset.merkle_root();
        wrong[0] ^= 1;
        assert!(matches!(
            CanonicalDataset::open_verified(&path, wrong),
            Err(DatasetError::RootMismatch { .. })
        ));
        drop(dataset);
        fs::remove_file(path).unwrap();
    }
}
