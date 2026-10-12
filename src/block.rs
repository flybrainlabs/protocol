use crate::hash::{Hash256, hash_parts};

pub const HEADER_VERSION: u32 = 1;
pub const HEADER_DOMAIN: &[u8] = b"FlyPoW/block-template/v1";

/// The fields a miner may commit to before searching a nonce.
///
/// The prototype uses a leading-zero-bit difficulty instead of a compact
/// 256-bit target. That is intentionally simple, but too coarse for a live
/// network and must be upgraded before a genesis block is frozen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockTemplate {
    pub version: u32,
    pub previous_hash: Hash256,
    pub merkle_root: Hash256,
    pub height: u64,
    pub timestamp: u64,
    pub difficulty_bits: u16,
}

impl BlockTemplate {
    pub fn new(
        previous_hash: Hash256,
        merkle_root: Hash256,
        height: u64,
        timestamp: u64,
        difficulty_bits: u16,
    ) -> Self {
        Self {
            version: HEADER_VERSION,
            previous_hash,
            merkle_root,
            height,
            timestamp,
            difficulty_bits,
        }
    }

    /// Consensus serialization. Never replace this with a language-specific
    /// object serializer.
    pub fn consensus_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(4 + 32 + 32 + 8 + 8 + 2);
        bytes.extend_from_slice(&self.version.to_le_bytes());
        bytes.extend_from_slice(&self.previous_hash);
        bytes.extend_from_slice(&self.merkle_root);
        bytes.extend_from_slice(&self.height.to_le_bytes());
        bytes.extend_from_slice(&self.timestamp.to_le_bytes());
        bytes.extend_from_slice(&self.difficulty_bits.to_le_bytes());
        bytes
    }

    pub fn template_id(&self) -> Hash256 {
        hash_parts(HEADER_DOMAIN, &[&self.consensus_bytes()])
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MinedHeader {
    pub template: BlockTemplate,
    pub nonce: u64,
    pub work_hash: Hash256,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serialization_has_fixed_length() {
        let template = BlockTemplate::new([1; 32], [2; 32], 3, 4, 5);
        assert_eq!(template.consensus_bytes().len(), 86);
        assert_eq!(
            template.consensus_bytes()[0..4],
            HEADER_VERSION.to_le_bytes()
        );
    }
}
