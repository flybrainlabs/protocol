//! Protocol byte layout for a temporary SubmissionV1 account.
//! This crate deliberately contains no Solana runtime, database, or web server.
use borsh::{BorshDeserialize, BorshSerialize};
use sha2::{Digest, Sha256};

pub const ACCOUNT_BYTES: usize = 1024;
pub const BODY_BYTES: usize = ACCOUNT_BYTES - 8;
pub const DISCRIMINATOR: [u8; 8] = [0x47, 0xbb, 0x2d, 0xfd, 0xfa, 0x06, 0xf9, 0x78];
pub const SUMMARY_DOMAIN: &[u8] = b"FlyPoW/SubmissionV1/summary/v1\0";
pub const ATOMS_PER_FLY: u64 = 100_000_000;
pub const TOTAL_FLY: u64 = 311_833_243;
pub const MINER_FLY: u64 = 224_519_936;
pub const VALIDATOR_FLY: u64 = 56_129_984;
pub const COMMUNITY_FLY: u64 = 31_183_323;

/// The campaign freezes `task_count` and the canonical index before RUNNING.
/// This computes an entitlement, not a minted or transferable token balance.
pub fn task_allocation_atoms(index: u64, task_count: u64, pool_fly: u64) -> Option<u64> {
    if task_count == 0 || index >= task_count {
        return None;
    }
    let pool = u128::from(pool_fly);
    let denominator = u128::from(task_count);
    let upper = u128::from(index).checked_add(1)?.checked_mul(pool)? / denominator;
    let lower = u128::from(index).checked_mul(pool)? / denominator;
    u64::try_from(
        upper
            .checked_sub(lower)?
            .checked_mul(u128::from(ATOMS_PER_FLY))?,
    )
    .ok()
}

#[derive(Debug, Clone, Default, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Header {
    pub schema_version: u16,
    pub status: u8,
    pub bump: u8,
    pub flags: u32,
    pub accept_mask: u16,
    pub reject_mask: u16,
    pub roi_count: u8,
    pub top_count: u8,
    pub time_bin_count: u8,
    pub summary_encoding: u8,
    pub readout_schema_id: u32,
    pub verifier_policy_id: u32,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Identity {
    pub campaign: [u8; 32],
    pub miner: [u8; 32],
    pub payer: [u8; 32],
    pub reward_beneficiary: [u8; 32],
    pub refund_recipient: [u8; 32],
}

#[derive(Debug, Clone, Default, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Task {
    pub body_id: u64,
    pub global_task_index: u64,
    pub target_index: u32,
    pub stimulus_index: u32,
    pub repeat_index: u32,
    pub candidate_seq: u32,
    pub model_neuron_count: u32,
    pub simulation_steps: u32,
    pub time_step_us: u32,
    pub simulation_config_id: u32,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Hashes {
    pub task_id: [u8; 32],
    pub commitment: [u8; 32],
    pub result_root: [u8; 32],
    pub preview_root: [u8; 32],
    pub archive_manifest_hash: [u8; 32],
    pub summary_hash: [u8; 32],
}

#[derive(Debug, Clone, Default, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Lifecycle {
    pub commit_slot: u64,
    pub committed_unix_ts: i64,
    pub reveal_deadline_ts: i64,
    pub verify_deadline_ts: i64,
    pub revealed_slot: u64,
    pub verified_slot: u64,
    pub archive_deadline_ts: i64,
    pub accepted_slot: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Funding {
    pub storage_principal_lamports: u64,
    pub refundable_advance_remaining_lamports: u64,
    pub service_fee_paid_lamports: u64,
    pub slash_paid_lamports: u64,
    pub miner_reward_whole: u64,
    pub validator_reward_whole: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct GlobalSummary {
    pub spikes_a: u64,
    pub spikes_b: u64,
    pub active_a: u64,
    pub active_b: u64,
    pub target_spikes_a: u64,
    pub target_spikes_b: u64,
    pub vnc_spikes_a: u64,
    pub vnc_spikes_b: u64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct TopNeuron {
    pub body_id: u64,
    pub delta_spikes: i32,
    pub first_divergence_step: u32,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct SubmissionV1 {
    pub header: Header,
    pub identity: Identity,
    pub task: Task,
    pub hashes: Hashes,
    pub lifecycle: Lifecycle,
    pub funding: Funding,
    pub global: GlobalSummary,
    pub roi_delta_spikes: [i64; 16],
    pub population_delta_by_bin: [i32; 32],
    pub top: [TopNeuron; 8],
    pub reserved: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReceiptError {
    Length,
    Discriminator,
    Decode,
    Schema,
    Status,
    Flags,
    Votes,
    Counts,
    Reserved,
    SummaryHash,
}

impl SubmissionV1 {
    pub fn encode_account(&self) -> Result<[u8; ACCOUNT_BYTES], ReceiptError> {
        self.validate_shape()?;
        let body = borsh::to_vec(self).map_err(|_| ReceiptError::Decode)?;
        if body.len() != BODY_BYTES {
            return Err(ReceiptError::Length);
        }
        let mut account = [0_u8; ACCOUNT_BYTES];
        account[..8].copy_from_slice(&DISCRIMINATOR);
        account[8..].copy_from_slice(&body);
        Ok(account)
    }

    pub fn decode_account(bytes: &[u8]) -> Result<Self, ReceiptError> {
        if bytes.len() != ACCOUNT_BYTES {
            return Err(ReceiptError::Length);
        }
        if bytes[..8] != DISCRIMINATOR {
            return Err(ReceiptError::Discriminator);
        }
        let record = Self::try_from_slice(&bytes[8..]).map_err(|_| ReceiptError::Decode)?;
        record.validate_shape()?;
        Ok(record)
    }

    /// Hash only immutable scientific values and the frozen readout identity.
    /// Calls after reveal must compare this value with `hashes.summary_hash`.
    pub fn compute_summary_hash(&self, readout_root: &[u8; 32]) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(SUMMARY_DOMAIN);
        hash.update(self.header.schema_version.to_le_bytes());
        hash.update(self.header.readout_schema_id.to_le_bytes());
        hash.update(readout_root);
        hash.update(self.header.flags.to_le_bytes());
        hash.update([
            self.header.roi_count,
            self.header.top_count,
            self.header.time_bin_count,
            self.header.summary_encoding,
        ]);
        hash.update(self.hashes.task_id);
        let mut scientific = Vec::new();
        self.global
            .serialize(&mut scientific)
            .expect("fixed fields");
        self.roi_delta_spikes
            .serialize(&mut scientific)
            .expect("fixed fields");
        self.population_delta_by_bin
            .serialize(&mut scientific)
            .expect("fixed fields");
        self.top.serialize(&mut scientific).expect("fixed fields");
        hash.update(scientific);
        hash.finalize().into()
    }

    pub fn validate_summary(&self, readout_root: &[u8; 32]) -> Result<(), ReceiptError> {
        self.validate_shape()?;
        if self.hashes.summary_hash != self.compute_summary_hash(readout_root) {
            return Err(ReceiptError::SummaryHash);
        }
        Ok(())
    }

    pub fn validate_shape(&self) -> Result<(), ReceiptError> {
        if self.header.schema_version != 1 || self.header.summary_encoding != 1 {
            return Err(ReceiptError::Schema);
        }
        // 0 committed, 1 revealed, 2 accepted, 3 rejected, 4 expired, 5 settled.
        if self.header.status > 5 {
            return Err(ReceiptError::Status);
        }
        // No scientific flags have been defined in V1.
        if self.header.flags != 0 {
            return Err(ReceiptError::Flags);
        }
        if (self.header.accept_mask | self.header.reject_mask) & !0b111 != 0
            || self.header.accept_mask & self.header.reject_mask != 0
        {
            return Err(ReceiptError::Votes);
        }
        if self.header.roi_count > 16
            || self.header.top_count > 8
            || self.header.time_bin_count != 32
        {
            return Err(ReceiptError::Counts);
        }
        let used_top = &self.top[..self.header.top_count as usize];
        for (index, item) in used_top.iter().enumerate() {
            if item.body_id == 0
                || item.first_divergence_step >= self.task.simulation_steps
                || used_top[..index]
                    .iter()
                    .any(|previous| previous.body_id == item.body_id)
            {
                return Err(ReceiptError::Counts);
            }
            if index > 0 {
                let previous = used_top[index - 1];
                let previous_magnitude = i64::from(previous.delta_spikes).abs();
                let current_magnitude = i64::from(item.delta_spikes).abs();
                if previous_magnitude < current_magnitude
                    || (previous_magnitude == current_magnitude && previous.body_id >= item.body_id)
                {
                    return Err(ReceiptError::Counts);
                }
            }
        }
        if self.roi_delta_spikes[self.header.roi_count as usize..]
            .iter()
            .any(|v| *v != 0)
            || self.top[self.header.top_count as usize..].iter().any(|v| {
                *v != TopNeuron {
                    body_id: 0,
                    delta_spikes: 0,
                    first_divergence_step: 0,
                }
            })
            || self.reserved.iter().any(|v| *v != 0)
        {
            return Err(ReceiptError::Reserved);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> SubmissionV1 {
        SubmissionV1 {
            header: Header {
                schema_version: 1,
                status: 1,
                bump: 254,
                flags: 0,
                accept_mask: 0,
                reject_mask: 0,
                roi_count: 2,
                top_count: 0,
                time_bin_count: 32,
                summary_encoding: 1,
                readout_schema_id: 7,
                verifier_policy_id: 9,
            },
            identity: Identity {
                campaign: [1; 32],
                miner: [2; 32],
                payer: [3; 32],
                reward_beneficiary: [4; 32],
                refund_recipient: [5; 32],
            },
            task: Task {
                body_id: 0x0102030405060708,
                global_task_index: 5,
                target_index: 2,
                stimulus_index: 3,
                repeat_index: 1,
                candidate_seq: 0,
                model_neuron_count: 166_700,
                simulation_steps: 256,
                time_step_us: 1_000,
                simulation_config_id: 4,
            },
            hashes: Hashes {
                task_id: [6; 32],
                commitment: [7; 32],
                result_root: [8; 32],
                preview_root: [9; 32],
                archive_manifest_hash: [10; 32],
                summary_hash: [0; 32],
            },
            lifecycle: Lifecycle {
                commit_slot: 100,
                committed_unix_ts: -1,
                reveal_deadline_ts: 300,
                verify_deadline_ts: 600,
                revealed_slot: 103,
                verified_slot: 0,
                archive_deadline_ts: 900,
                accepted_slot: 0,
            },
            funding: Funding {
                storage_principal_lamports: 1_000_000,
                refundable_advance_remaining_lamports: 500_000,
                service_fee_paid_lamports: 0,
                slash_paid_lamports: 0,
                miner_reward_whole: 0,
                validator_reward_whole: 0,
            },
            global: GlobalSummary {
                spikes_a: 1,
                spikes_b: 2,
                active_a: 3,
                active_b: 4,
                target_spikes_a: 0,
                target_spikes_b: 1,
                vnc_spikes_a: 5,
                vnc_spikes_b: 6,
            },
            roi_delta_spikes: [0; 16],
            population_delta_by_bin: [0; 32],
            top: [TopNeuron {
                body_id: 0,
                delta_spikes: 0,
                first_divergence_step: 0,
            }; 8],
            reserved: [0; 32],
        }
    }

    #[test]
    fn account_is_exactly_1024_and_offsets_are_stable() {
        let mut record = sample();
        record.header.top_count = 1;
        record.roi_delta_spikes[0] = -17;
        record.top[0] = TopNeuron {
            body_id: 42,
            delta_spikes: -3,
            first_divergence_step: 0,
        };
        record.hashes.summary_hash = record.compute_summary_hash(&[11; 32]);
        let body = borsh::to_vec(&record).unwrap();
        assert_eq!(body.len(), 1016);
        let bytes = record.encode_account().unwrap();
        assert_eq!(bytes.len(), 1024);
        assert_eq!(&bytes[..8], &DISCRIMINATOR);
        assert_eq!(&bytes[8..10], &1_u16.to_le_bytes());
        assert_eq!(&bytes[32..64], &[1; 32]);
        assert_eq!(&bytes[192..200], &record.task.body_id.to_le_bytes());
        assert_eq!(&bytes[608..616], &(-17_i64).to_le_bytes());
        assert_eq!(&bytes[864..872], &42_u64.to_le_bytes());
        assert_eq!(&bytes[872..876], &(-3_i32).to_le_bytes());
        assert_eq!(SubmissionV1::decode_account(&bytes).unwrap(), record);
        record.validate_summary(&[11; 32]).unwrap();
    }

    #[test]
    fn malformed_length_bits_and_summary_are_rejected() {
        let mut record = sample();
        record.hashes.summary_hash = record.compute_summary_hash(&[0; 32]);
        let bytes = record.encode_account().unwrap();
        assert_eq!(
            SubmissionV1::decode_account(&bytes[..1023]),
            Err(ReceiptError::Length)
        );
        assert_eq!(
            SubmissionV1::decode_account(&[bytes.as_slice(), &[0; 8]].concat()),
            Err(ReceiptError::Length)
        );
        let mut wrong = bytes;
        wrong[0] ^= 1;
        assert_eq!(
            SubmissionV1::decode_account(&wrong),
            Err(ReceiptError::Discriminator)
        );
        record.header.flags = 1;
        assert_eq!(record.encode_account(), Err(ReceiptError::Flags));
        record.header.flags = 0;
        record.header.accept_mask = 0b1000;
        assert_eq!(record.encode_account(), Err(ReceiptError::Votes));
        record.header.accept_mask = 0;
        record.reserved[0] = 1;
        assert_eq!(record.encode_account(), Err(ReceiptError::Reserved));
        record.reserved[0] = 0;
        record.global.spikes_b += 1;
        assert_eq!(
            record.validate_summary(&[0; 32]),
            Err(ReceiptError::SummaryHash)
        );
    }

    #[test]
    fn finite_budget_is_exact_and_independent_of_wallet() {
        assert_eq!(MINER_FLY + VALIDATOR_FLY + COMMUNITY_FLY, TOTAL_FLY);
        for count in [1, 3, 256, 999] {
            let sum: u128 = (0..count)
                .map(|index| u128::from(task_allocation_atoms(index, count, MINER_FLY).unwrap()))
                .sum();
            assert_eq!(sum, u128::from(MINER_FLY) * u128::from(ATOMS_PER_FLY));
        }
        assert_eq!(task_allocation_atoms(256, 256, MINER_FLY), None);
        assert_eq!(task_allocation_atoms(0, 0, MINER_FLY), None);
    }

    #[test]
    fn top_order_and_first_step_are_canonical() {
        let mut record = sample();
        record.header.top_count = 2;
        record.top[0] = TopNeuron {
            body_id: 99,
            delta_spikes: 1,
            first_divergence_step: 0,
        };
        record.top[1] = TopNeuron {
            body_id: 42,
            delta_spikes: i32::MIN,
            first_divergence_step: 1,
        };
        assert_eq!(record.encode_account(), Err(ReceiptError::Counts));
        record.top.swap(0, 1);
        record.top[1].first_divergence_step = record.task.simulation_steps;
        assert_eq!(record.encode_account(), Err(ReceiptError::Counts));
        record.top[1].first_divergence_step = 0;
        assert!(record.encode_account().is_ok());
    }

    #[test]
    fn checked_in_golden_vector_round_trips() {
        let vector = include_bytes!("../../../tests/fixtures/submission-v1.bin");
        let record = SubmissionV1::decode_account(vector).unwrap();
        assert_eq!(record.task.body_id, 0x0102_0304_0506_0708);
        assert_eq!(record.encode_account().unwrap(), *vector);
        record.validate_summary(&[11; 32]).unwrap();
    }
}
