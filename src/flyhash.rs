use core::{fmt, str::FromStr};

use crate::hash::{Hash256, hash_parts};

const WIRING_DOMAIN: &[u8] = b"FlyPoW/flyhash-wiring/v1";
const INPUT_DOMAIN: &[u8] = b"FlyPoW/flyhash-input/v1";
const CODE_DOMAIN: &[u8] = b"FlyPoW/flyhash-code/v1";

/// This is a metadata reference, not a hash of the Janelia dataset.
///
/// A production protocol must replace it with a hash of an explicitly
/// versioned, canonical dataset manifest if actual connectome data is made a
/// consensus dependency.
pub const CONNECTOME_REFERENCE: &[u8] = b"Google Research + HHMI Janelia|male Drosophila CNS|2026-09-03|Cell:10.1016/j.cell.2026.08.015|>166000 neurons|125000000 synapses";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FlyHashProfile {
    /// A fast profile shaped like the 2017 FlyHash description: roughly 50
    /// projection-neuron inputs, 2,000 Kenyon-cell outputs, fan-in six, and
    /// five-percent winner activity.
    Reference = 1,
    /// A stress-test profile whose output count mirrors the reported size of
    /// the 2026 male fly CNS connectome. It does not reproduce its 125 million
    /// biological synapses.
    Connectome = 2,
}

impl FlyHashProfile {
    pub fn params(self) -> FlyHashParams {
        match self {
            Self::Reference => FlyHashParams {
                input_dimensions: 50,
                expansion_dimensions: 2_000,
                fan_in: 6,
                winners: 100,
                profile_id: self as u8,
            },
            Self::Connectome => FlyHashParams {
                input_dimensions: 256,
                expansion_dimensions: 166_000,
                fan_in: 6,
                winners: 8_300,
                profile_id: self as u8,
            },
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reference => "reference",
            Self::Connectome => "connectome",
        }
    }
}

impl fmt::Display for FlyHashProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for FlyHashProfile {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.to_ascii_lowercase().as_str() {
            "reference" | "ref" | "flyhash" => Ok(Self::Reference),
            "connectome" | "cns" | "male-cns" => Ok(Self::Connectome),
            _ => Err(format!(
                "unknown profile {value:?}; expected reference or connectome"
            )),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlyHashParams {
    pub input_dimensions: usize,
    pub expansion_dimensions: usize,
    pub fan_in: usize,
    pub winners: usize,
    pub profile_id: u8,
}

impl FlyHashParams {
    pub fn validate(self) -> Result<Self, FlyHashError> {
        if self.input_dimensions == 0 || self.input_dimensions > u16::MAX as usize {
            return Err(FlyHashError::InvalidParams(
                "input_dimensions must be in 1..=65535",
            ));
        }
        if self.fan_in == 0 || self.fan_in > self.input_dimensions {
            return Err(FlyHashError::InvalidParams(
                "fan_in must be in 1..=input_dimensions",
            ));
        }
        if self.expansion_dimensions == 0 || self.expansion_dimensions > u32::MAX as usize {
            return Err(FlyHashError::InvalidParams(
                "expansion_dimensions must be in 1..=u32::MAX",
            ));
        }
        if self.winners == 0 || self.winners > self.expansion_dimensions {
            return Err(FlyHashError::InvalidParams(
                "winners must be in 1..=expansion_dimensions",
            ));
        }
        Ok(self)
    }

    pub fn consensus_bytes(self) -> [u8; 18] {
        let mut bytes = [0_u8; 18];
        bytes[0] = self.profile_id;
        bytes[1..5].copy_from_slice(&(self.input_dimensions as u32).to_le_bytes());
        bytes[5..9].copy_from_slice(&(self.expansion_dimensions as u32).to_le_bytes());
        bytes[9..13].copy_from_slice(&(self.fan_in as u32).to_le_bytes());
        bytes[13..17].copy_from_slice(&(self.winners as u32).to_le_bytes());
        bytes[17] = 1; // Algorithm revision.
        bytes
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FlyHashError {
    InvalidParams(&'static str),
    WrongInputLength { expected: usize, actual: usize },
}

impl fmt::Display for FlyHashError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidParams(message) => f.write_str(message),
            Self::WrongInputLength { expected, actual } => {
                write!(f, "expected {expected} FlyHash inputs, got {actual}")
            }
        }
    }
}

impl std::error::Error for FlyHashError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlyHashOutput {
    /// Winning expanded-neuron indices in ascending order. The ordering is a
    /// canonical encoding choice, not their activation ranking.
    pub winners: Vec<u32>,
    pub code_digest: Hash256,
}

/// Precomputed challenge-specific FlyHash projection graph.
///
/// Wiring depends on the full block challenge but not on the nonce. A miner
/// can therefore build it once per block template and reuse it across nonce
/// trials. A validator rebuilds exactly the same graph once for a submitted
/// header.
#[derive(Debug, Clone)]
pub struct FlyHashEngine {
    params: FlyHashParams,
    challenge: Hash256,
    wiring: Vec<u16>,
}

impl FlyHashEngine {
    pub fn new(params: FlyHashParams, challenge: Hash256) -> Result<Self, FlyHashError> {
        let params = params.validate()?;
        let wiring = build_wiring(params, &challenge);
        Ok(Self {
            params,
            challenge,
            wiring,
        })
    }

    pub fn params(&self) -> FlyHashParams {
        self.params
    }

    pub fn hash_nonce(&self, nonce: u64) -> FlyHashOutput {
        let input = build_input(self.params.input_dimensions, &self.challenge, nonce);
        self.hash_input(nonce, &input)
            .expect("internally generated FlyHash input has the configured length")
    }

    /// Applies the challenge-specific sparse projection and WTA circuit to a
    /// caller-provided feature vector. This is the reusable FlyHash primitive
    /// used for connectome neuron fingerprints.
    pub fn hash_input(&self, nonce: u64, input: &[u8]) -> Result<FlyHashOutput, FlyHashError> {
        if input.len() != self.params.input_dimensions {
            return Err(FlyHashError::WrongInputLength {
                expected: self.params.input_dimensions,
                actual: input.len(),
            });
        }
        let mut activations = Vec::with_capacity(self.params.expansion_dimensions);

        for (neuron_index, sources) in self.wiring.chunks_exact(self.params.fan_in).enumerate() {
            let score = sources
                .iter()
                .map(|&source| input[source as usize] as u32)
                .sum::<u32>();
            activations.push((score, neuron_index as u32));
        }

        // Total ordering makes ties consensus-safe on every architecture.
        activations.select_nth_unstable_by(self.params.winners - 1, |left, right| {
            right.0.cmp(&left.0).then_with(|| left.1.cmp(&right.1))
        });

        let mut winners = activations[..self.params.winners]
            .iter()
            .map(|&(_, index)| index)
            .collect::<Vec<_>>();
        winners.sort_unstable();

        let mut sparse_code = Vec::with_capacity(winners.len() * 4);
        for winner in &winners {
            sparse_code.extend_from_slice(&winner.to_le_bytes());
        }

        let nonce_bytes = nonce.to_le_bytes();
        let params_bytes = self.params.consensus_bytes();
        let code_digest = hash_parts(
            CODE_DOMAIN,
            &[&params_bytes, &self.challenge, &nonce_bytes, &sparse_code],
        );

        Ok(FlyHashOutput {
            winners,
            code_digest,
        })
    }
}

fn build_input(dimensions: usize, challenge: &Hash256, nonce: u64) -> Vec<u8> {
    let mut input = Vec::with_capacity(dimensions);
    let nonce_bytes = nonce.to_le_bytes();
    let mut counter = 0_u32;

    while input.len() < dimensions {
        let counter_bytes = counter.to_le_bytes();
        let digest = hash_parts(INPUT_DOMAIN, &[challenge, &nonce_bytes, &counter_bytes]);
        let take = (dimensions - input.len()).min(digest.len());
        input.extend_from_slice(&digest[..take]);
        counter = counter.wrapping_add(1);
    }
    input
}

fn build_wiring(params: FlyHashParams, challenge: &Hash256) -> Vec<u16> {
    let params_bytes = params.consensus_bytes();
    let seed = hash_parts(WIRING_DOMAIN, &[&params_bytes, challenge]);
    let mut seed_word = [0_u8; 8];
    seed_word.copy_from_slice(&seed[..8]);
    let mut rng = SplitMix64::new(u64::from_le_bytes(seed_word));

    let mut wiring = Vec::with_capacity(params.expansion_dimensions * params.fan_in);
    for _ in 0..params.expansion_dimensions {
        let start = wiring.len();
        while wiring.len() - start < params.fan_in {
            let source = rng.next_bounded(params.input_dimensions as u64) as u16;
            if !wiring[start..].contains(&source) {
                wiring.push(source);
            }
        }
    }
    wiring
}

/// A tiny, fully specified generator used only to expand a SHA-256 seed into
/// projection indices. Cryptographic security comes from the challenge and
/// final SHA-256 transcript, not from SplitMix64 itself.
#[derive(Debug, Clone, Copy)]
struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut value = self.state;
        value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        value ^ (value >> 31)
    }

    fn next_bounded(&mut self, upper_bound: u64) -> u64 {
        ((self.next_u64() as u128 * upper_bound as u128) >> 64) as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profiles_are_valid_and_keep_five_percent() {
        for profile in [FlyHashProfile::Reference, FlyHashProfile::Connectome] {
            let params = profile.params().validate().unwrap();
            assert_eq!(params.winners * 20, params.expansion_dimensions);
        }
    }

    #[test]
    fn output_is_deterministic_and_sparse() {
        let engine = FlyHashEngine::new(FlyHashProfile::Reference.params(), [7; 32]).unwrap();
        let first = engine.hash_nonce(42);
        let second = engine.hash_nonce(42);
        assert_eq!(first, second);
        assert_eq!(first.winners.len(), 100);
        assert!(first.winners.windows(2).all(|pair| pair[0] < pair[1]));
        assert_ne!(first.code_digest, engine.hash_nonce(43).code_digest);
    }

    #[test]
    fn rejects_invalid_parameters() {
        let invalid = FlyHashParams {
            input_dimensions: 4,
            expansion_dimensions: 100,
            fan_in: 5,
            winners: 5,
            profile_id: 99,
        };
        assert!(invalid.validate().is_err());
    }
}
