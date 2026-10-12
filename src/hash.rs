use core::fmt;

use sha2::{Digest, Sha256};

pub type Hash256 = [u8; 32];

/// Hashes length-delimited byte strings under an explicit domain.
///
/// Length prefixes make the transcript unambiguous. All integer lengths use
/// little-endian encoding and are therefore stable across architectures.
pub fn hash_parts(domain: &[u8], parts: &[&[u8]]) -> Hash256 {
    let mut hasher = Sha256::new();
    hasher.update((domain.len() as u32).to_le_bytes());
    hasher.update(domain);
    hasher.update((parts.len() as u32).to_le_bytes());

    for part in parts {
        hasher.update((part.len() as u64).to_le_bytes());
        hasher.update(part);
    }

    hasher.finalize().into()
}

pub fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HexError {
    WrongLength { expected: usize, actual: usize },
    InvalidCharacter { index: usize, character: char },
}

impl fmt::Display for HexError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongLength { expected, actual } => {
                write!(f, "expected {expected} hex characters, got {actual}")
            }
            Self::InvalidCharacter { index, character } => {
                write!(f, "invalid hex character {character:?} at index {index}")
            }
        }
    }
}

impl std::error::Error for HexError {}

pub fn decode_hash(value: &str) -> Result<Hash256, HexError> {
    let value = value.strip_prefix("0x").unwrap_or(value);
    if value.len() != 64 {
        return Err(HexError::WrongLength {
            expected: 64,
            actual: value.len(),
        });
    }

    let mut output = [0_u8; 32];
    let bytes = value.as_bytes();
    for (index, output_byte) in output.iter_mut().enumerate() {
        let high_index = index * 2;
        let low_index = high_index + 1;
        let high = decode_nibble(bytes[high_index], high_index)?;
        let low = decode_nibble(bytes[low_index], low_index)?;
        *output_byte = (high << 4) | low;
    }
    Ok(output)
}

fn decode_nibble(value: u8, index: usize) -> Result<u8, HexError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err(HexError::InvalidCharacter {
            index,
            character: value as char,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_round_trip() {
        let value = hash_parts(b"test", &[b"hello", b"world"]);
        assert_eq!(decode_hash(&encode_hex(&value)).unwrap(), value);
    }

    #[test]
    fn rejects_bad_hex() {
        assert!(matches!(
            decode_hash("00"),
            Err(HexError::WrongLength { .. })
        ));
        let mut invalid = "00".repeat(32);
        invalid.replace_range(7..8, "z");
        assert!(matches!(
            decode_hash(&invalid),
            Err(HexError::InvalidCharacter { index: 7, .. })
        ));
    }
}
