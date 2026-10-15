//! Versioned, finite, prospectively approved task lifecycle. V3 bytes are unchanged.
//! Scientific replay is off chain; only frozen verifier attestations decide validity.
use borsh::{BorshDeserialize, BorshSerialize};
use sha2::{Digest, Sha256};

pub type Key = [u8; 32];
pub const ZERO: Key = [0; 32];
pub const NONE: u32 = u32::MAX;
pub const QUEUE_CAPACITY: usize = 8;
pub const FACTORY_SIZE: usize = 768;
pub const TASK_SIZE: usize = 2048;
pub const SUBMISSION_SIZE: usize = 768;
pub const SCIENCE_SIZE: usize = 128;
pub const DRAFT: u8 = 0;
pub const RUNNING: u8 = 1;
pub const EXHAUSTED: u8 = 2;
pub const CLOSED: u8 = 3;
pub const SCHEDULED: u8 = 0;
pub const ACTIVE: u8 = 1;
pub const SOLVED: u8 = 2;
pub const FAILED: u8 = 3;
pub const COMMITTED: u8 = 1;
pub const REVEALED: u8 = 2;
pub const VALID: u8 = 3;
pub const INVALID: u8 = 4;
pub const TIMED_OUT: u8 = 5;
pub type Result<T> = core::result::Result<T, &'static str>;

pub fn digest(domain: &[u8], bytes: &[u8]) -> Key {
    let mut h = Sha256::new();
    h.update(domain);
    h.update(bytes);
    h.finalize().into()
}
fn bytes<T: BorshSerialize>(v: &T) -> Vec<u8> {
    borsh::to_vec(v).expect("fixed protocol values")
}

/// Hashes bind the complete published scientific specification, including the
/// input domain, calibrated predicate and predetermined background seeds.
#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct Descriptor {
    pub scientific_identity: Key,
    pub goal: Key,
    pub content: Key,
    pub model: Key,
    pub graph: Key,
    pub parameters: Key,
    pub calibration: Key,
    pub input_domain: Key,
    pub reward_atoms: u64,
    pub claim_seconds: u32,
    pub reveal_seconds: u32,
    pub verify_seconds: u32,
    pub max_attempts: u8,
    pub seeds: Vec<u64>,
}
impl Descriptor {
    pub fn validate(&self) -> Result<()> {
        if [
            self.scientific_identity,
            self.goal,
            self.content,
            self.model,
            self.graph,
            self.parameters,
            self.calibration,
            self.input_domain,
        ]
        .contains(&ZERO)
            || self.reward_atoms == 0
            || self.claim_seconds == 0
            || self.claim_seconds >= self.reveal_seconds
            || self.reveal_seconds >= self.verify_seconds
            || self.verify_seconds > 86400
            || self.max_attempts == 0
            || self.max_attempts > 16
            || ![2, 4, 8, 16].contains(&self.seeds.len())
            || self
                .seeds
                .iter()
                .enumerate()
                .any(|(i, s)| self.seeds[..i].contains(s))
        {
            return Err("invalid frozen descriptor");
        }
        Ok(())
    }
    pub fn hash(&self) -> Key {
        digest(b"Flybrain/task-descriptor/v4\0", &bytes(self))
    }
}
pub fn catalog_step(previous: Key, index: u32, d: &Descriptor) -> Key {
    digest(b"Flybrain/task-catalog/v4\0", &bytes(&(previous, index, d)))
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug)]
pub struct Factory {
    pub id: Key,
    pub authority: Key,
    pub genesis: Key,
    pub policy: Key,
    pub mint: Key,
    pub verifiers: [Key; 3],
    pub catalog_root: Key,
    pub uploaded_root: Key,
    pub count: u32,
    pub uploaded: u32,
    pub reward_sum: u64,
    pub budget: u64,
    pub remaining: u64,
    pub reserved: u64,
    pub accepted_unpaid: u64,
    pub paid: u64,
    pub refunded: u64,
    pub next_index: u32,
    pub active_index: u32,
    pub deadline: i64,
    pub state: u8,
    pub paused: bool,
}
impl Factory {
    pub fn accounting(&self) -> Result<()> {
        if self
            .remaining
            .checked_add(self.reserved)
            .and_then(|v| v.checked_add(self.accepted_unpaid))
            .and_then(|v| v.checked_add(self.paid))
            .and_then(|v| v.checked_add(self.refunded))
            != Some(self.budget)
        {
            return Err("budget conservation");
        }
        Ok(())
    }
    pub fn append(&mut self, d: &Descriptor) -> Result<u32> {
        d.validate()?;
        if self.state != DRAFT || self.uploaded >= self.count {
            return Err("catalog frozen/full");
        }
        let sum = self
            .reward_sum
            .checked_add(d.reward_atoms)
            .ok_or("reward overflow")?;
        if sum > self.budget {
            return Err("catalog exceeds finite budget");
        }
        let index = self.uploaded;
        self.uploaded_root = catalog_step(self.uploaded_root, index, d);
        self.uploaded += 1;
        self.reward_sum = sum;
        Ok(index)
    }
    pub fn seal(&mut self) -> Result<()> {
        if self.state != DRAFT
            || self.count == 0
            || self.uploaded != self.count
            || self.catalog_root != self.uploaded_root
        {
            return Err("incomplete/mismatched catalog");
        }
        self.accounting()?;
        self.state = RUNNING;
        Ok(())
    }
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug)]
pub struct Entry {
    pub submission: Key,
    pub sequence: u64,
    pub state: u8,
}
#[derive(BorshSerialize, BorshDeserialize, Clone, Debug)]
pub struct Task {
    pub factory: Key,
    pub index: u32,
    pub descriptor: Descriptor,
    pub state: u8,
    pub attempt: u32,
    pub opened_at: i64,
    pub claim_deadline: i64,
    pub reveal_deadline: i64,
    pub verify_deadline: i64,
    pub next_sequence: u64,
    pub queue: Vec<Entry>,
    pub winner: Key,
    pub beneficiary: Key,
    pub paid: bool,
}
impl Task {
    pub fn new(factory: Key, index: u32, descriptor: Descriptor) -> Self {
        Self {
            factory,
            index,
            descriptor,
            state: SCHEDULED,
            attempt: 0,
            opened_at: 0,
            claim_deadline: 0,
            reveal_deadline: 0,
            verify_deadline: 0,
            next_sequence: 0,
            queue: vec![],
            winner: ZERO,
            beneficiary: ZERO,
            paid: false,
        }
    }
    fn times(&mut self, now: i64) -> Result<()> {
        self.opened_at = now;
        self.claim_deadline = now
            .checked_add(self.descriptor.claim_seconds as i64)
            .ok_or("time overflow")?;
        self.reveal_deadline = now
            .checked_add(self.descriptor.reveal_seconds as i64)
            .ok_or("time overflow")?;
        self.verify_deadline = now
            .checked_add(self.descriptor.verify_seconds as i64)
            .ok_or("time overflow")?;
        Ok(())
    }
    pub fn open(&mut self, f: &mut Factory, now: i64) -> Result<()> {
        if f.state != RUNNING
            || f.paused
            || f.active_index != NONE
            || self.state != SCHEDULED
            || self.index != f.next_index
            || now >= f.deadline
        {
            return Err("cannot open task");
        }
        self.descriptor.validate()?;
        self.times(now)?;
        if self.verify_deadline > f.deadline {
            return Err("insufficient campaign time");
        }
        f.remaining = f
            .remaining
            .checked_sub(self.descriptor.reward_atoms)
            .ok_or("budget exhausted")?;
        f.reserved = f
            .reserved
            .checked_add(self.descriptor.reward_atoms)
            .ok_or("budget overflow")?;
        f.active_index = self.index;
        f.next_index += 1;
        self.state = ACTIVE;
        f.accounting()
    }
    pub fn prune(&mut self, now: i64) {
        self.queue.retain(|e| match e.state {
            COMMITTED => now <= self.reveal_deadline,
            REVEALED => now <= self.verify_deadline,
            VALID => true,
            _ => false,
        });
    }
    pub fn enqueue(&mut self, submission: Key, now: i64) -> Result<u64> {
        if self.state != ACTIVE || now >= self.claim_deadline {
            return Err("claims closed");
        }
        self.prune(now);
        if self.queue.len() >= QUEUE_CAPACITY {
            return Err("verification queue full");
        }
        let seq = self.next_sequence;
        self.next_sequence = seq.checked_add(1).ok_or("sequence overflow")?;
        self.queue.push(Entry {
            submission,
            sequence: seq,
            state: COMMITTED,
        });
        Ok(seq)
    }
    pub fn entry(&mut self, submission: Key) -> Result<&mut Entry> {
        self.queue
            .iter_mut()
            .find(|e| e.submission == submission)
            .ok_or("submission not eligible")
    }
    pub fn accept(
        &mut self,
        f: &mut Factory,
        submission: Key,
        beneficiary: Key,
        now: i64,
    ) -> Result<()> {
        if self.state == SOLVED {
            return if self.winner == submission && self.beneficiary == beneficiary {
                Ok(())
            } else {
                Err("winner frozen")
            };
        }
        if self.state != ACTIVE || f.active_index != self.index {
            return Err("task not active");
        }
        self.prune(now);
        if !self
            .queue
            .first()
            .is_some_and(|e| e.submission == submission && e.state == VALID)
        {
            return Err("earlier eligible commitment or missing quorum");
        }
        let n = self.descriptor.reward_atoms;
        f.reserved = f.reserved.checked_sub(n).ok_or("reservation missing")?;
        f.accepted_unpaid = f
            .accepted_unpaid
            .checked_add(n)
            .ok_or("entitlement overflow")?;
        f.active_index = NONE;
        self.state = SOLVED;
        self.winner = submission;
        self.beneficiary = beneficiary;
        if f.next_index == f.count {
            f.state = EXHAUSTED;
        }
        f.accounting()
    }
    /// A valid quorum survives missed finalization. Infrastructure failures do
    /// not become negative scientific votes and cannot erase an earned result.
    pub fn expire(&mut self, f: &mut Factory, now: i64) -> Result<()> {
        if self.state != ACTIVE || f.active_index != self.index || now <= self.verify_deadline {
            return Err("task not expired");
        }
        self.prune(now);
        if self.queue.iter().any(|e| e.state == VALID) {
            return Err("verified result must finalize");
        }
        let fits = now
            .checked_add(self.descriptor.verify_seconds as i64)
            .is_some_and(|t| t <= f.deadline);
        if self.attempt + 1 < self.descriptor.max_attempts as u32 && !f.paused && fits {
            self.attempt += 1;
            self.next_sequence = 0;
            self.queue.clear();
            self.times(now)?;
        } else {
            let n = self.descriptor.reward_atoms;
            f.reserved = f.reserved.checked_sub(n).ok_or("reservation missing")?;
            f.remaining = f.remaining.checked_add(n).ok_or("budget overflow")?;
            f.active_index = NONE;
            self.state = FAILED;
            if f.next_index == f.count {
                f.state = EXHAUSTED;
            }
        }
        f.accounting()
    }
    pub fn pay(&mut self, f: &mut Factory) -> Result<bool> {
        if self.state != SOLVED || self.winner == ZERO {
            return Err("no accepted entitlement");
        }
        if self.paid {
            return Ok(false);
        }
        let n = self.descriptor.reward_atoms;
        f.accepted_unpaid = f
            .accepted_unpaid
            .checked_sub(n)
            .ok_or("entitlement missing")?;
        f.paid = f.paid.checked_add(n).ok_or("payment overflow")?;
        self.paid = true;
        f.accounting()?;
        Ok(true)
    }
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct Evidence {
    pub candidate: Key,
    pub result: Key,
    pub manifest: Key,
    pub archive: Key,
}
impl Evidence {
    pub fn validate(&self) -> Result<()> {
        if [self.candidate, self.result, self.manifest, self.archive].contains(&ZERO) {
            Err("missing evidence")
        } else {
            Ok(())
        }
    }
}
#[derive(BorshSerialize, BorshDeserialize, Clone, Debug)]
pub struct Submission {
    pub task: Key,
    pub attempt: u32,
    pub sequence: u64,
    pub miner: Key,
    pub beneficiary: Key,
    pub commitment: Key,
    pub commit_slot: u64,
    pub evidence: Evidence,
    pub state: u8,
    pub valid_votes: u8,
    pub invalid_votes: u8,
    pub reports: [Key; 3],
}
impl Submission {
    pub fn vote(&mut self, verifier: usize, valid: bool, report: Key) -> Result<u8> {
        if verifier >= 3 || report == ZERO {
            return Err("invalid verifier/report");
        }
        let bit = 1 << verifier;
        if (self.valid_votes | self.invalid_votes) & bit != 0 {
            return if self.reports[verifier] == report && (self.valid_votes & bit != 0) == valid {
                Ok(self.state)
            } else {
                Err("verifier equivocation")
            };
        }
        if ![REVEALED, VALID, INVALID].contains(&self.state) {
            return Err("not revealed");
        }
        self.reports[verifier] = report;
        if valid {
            self.valid_votes |= bit;
        } else {
            self.invalid_votes |= bit;
        }
        if self.valid_votes.count_ones() >= 2 {
            self.state = VALID;
        }
        if self.invalid_votes.count_ones() >= 2 {
            self.state = INVALID;
        }
        Ok(self.state)
    }
}
pub fn commitment(
    program: Key,
    f: &Factory,
    task: Key,
    attempt: u32,
    miner: Key,
    beneficiary: Key,
    evidence: &Evidence,
    salt: Key,
) -> Key {
    digest(
        b"Flybrain/task-commitment/v4\0",
        &bytes(&(
            program,
            f.genesis,
            f.policy,
            task,
            attempt,
            miner,
            beneficiary,
            evidence,
            salt,
        )),
    )
}
pub fn vote_message(
    program: Key,
    f: &Factory,
    t: &Task,
    submission: Key,
    s: &Submission,
    valid: bool,
    report: Key,
    complete_trials: u8,
) -> Key {
    digest(
        b"Flybrain/task-replay/v4\0",
        &bytes(&(
            program,
            f.genesis,
            f.policy,
            t.factory,
            t.index,
            t.descriptor.hash(),
            submission,
            s.task,
            s.attempt,
            s.sequence,
            s.miner,
            s.beneficiary,
            s.commitment,
            s.commit_slot,
            &s.evidence,
            valid,
            report,
            complete_trials,
        )),
    )
}

/// Stable operation tags under economy Instruction::TaskFactoryV4 (outer tag 11).
#[derive(BorshSerialize, BorshDeserialize)]
pub enum Operation {
    Initialize {
        id: Key,
        catalog_root: Key,
        count: u32,
        budget: u64,
        deadline: i64,
    },
    Append {
        descriptor: Descriptor,
    },
    Seal,
    Advance,
    Commit {
        commitment: Key,
        beneficiary: Key,
    },
    Reveal {
        evidence: Evidence,
        salt: Key,
    },
    Vote {
        valid: bool,
        report: Key,
        complete_trials: u8,
        ed25519_index: u16,
    },
    Finalize,
    Expire,
    Pay,
    Pause {
        paused: bool,
    },
    Close,
}

#[cfg(test)]
mod tests {
    use super::*;
    fn descriptor() -> Descriptor {
        Descriptor {
            scientific_identity: [1; 32],
            goal: [2; 32],
            content: [3; 32],
            model: [4; 32],
            graph: [5; 32],
            parameters: [6; 32],
            calibration: [7; 32],
            input_domain: [8; 32],
            reward_atoms: 100,
            claim_seconds: 10,
            reveal_seconds: 20,
            verify_seconds: 30,
            max_attempts: 2,
            seeds: vec![11, 12],
        }
    }
    fn draft() -> Factory {
        let d = descriptor();
        Factory {
            id: [10; 32],
            authority: [11; 32],
            genesis: [12; 32],
            policy: [13; 32],
            mint: [14; 32],
            verifiers: [[15; 32], [16; 32], [17; 32]],
            catalog_root: catalog_step(ZERO, 0, &d),
            uploaded_root: ZERO,
            count: 1,
            uploaded: 0,
            reward_sum: 0,
            budget: 100,
            remaining: 100,
            reserved: 0,
            accepted_unpaid: 0,
            paid: 0,
            refunded: 0,
            next_index: 0,
            active_index: NONE,
            deadline: 1000,
            state: DRAFT,
            paused: false,
        }
    }
    fn opened() -> (Factory, Task) {
        let mut f = draft();
        f.append(&descriptor()).unwrap();
        f.seal().unwrap();
        let mut t = Task::new([10; 32], 0, descriptor());
        t.open(&mut f, 1).unwrap();
        (f, t)
    }
    #[test]
    fn catalog_is_complete_and_frozen() {
        let mut f = draft();
        assert!(f.seal().is_err());
        f.append(&descriptor()).unwrap();
        f.seal().unwrap();
        assert!(f.append(&descriptor()).is_err());
        assert!(f.seal().is_err());
        let mut f = draft();
        let mut d = descriptor();
        d.reward_atoms = 101;
        assert!(f.append(&d).is_err());
        let mut f = draft();
        f.append(&descriptor()).unwrap();
        f.catalog_root = [9; 32];
        assert!(f.seal().is_err());
    }
    #[test]
    fn winner_respects_earlier_commitments_and_is_durable() {
        let (mut f, mut t) = opened();
        t.enqueue([21; 32], 2).unwrap();
        t.enqueue([22; 32], 2).unwrap();
        t.entry([22; 32]).unwrap().state = VALID;
        assert!(t.accept(&mut f, [22; 32], [23; 32], 3).is_err());
        t.entry([21; 32]).unwrap().state = INVALID;
        t.accept(&mut f, [22; 32], [23; 32], 3).unwrap();
        assert_eq!(f.accepted_unpaid, 100);
        t.accept(&mut f, [22; 32], [23; 32], 4).unwrap();
        assert_eq!(f.accepted_unpaid, 100);
        assert!(t.accept(&mut f, [21; 32], [23; 32], 4).is_err());
        assert!(t.pay(&mut f).unwrap());
        assert!(!t.pay(&mut f).unwrap());
        assert_eq!(f.paid, 100);
    }
    #[test]
    fn a_verified_result_survives_timeout_and_pause() {
        let (mut f, mut t) = opened();
        t.enqueue([21; 32], 2).unwrap();
        t.entry([21; 32]).unwrap().state = VALID;
        f.paused = true;
        assert!(t.expire(&mut f, 999).is_err());
        t.accept(&mut f, [21; 32], [23; 32], 1001).unwrap();
        assert_eq!(f.accepted_unpaid, 100);
    }
    #[test]
    fn timeout_retries_same_task_then_fails_without_discovery() {
        let (mut f, mut t) = opened();
        t.enqueue([21; 32], 2).unwrap();
        t.expire(&mut f, 32).unwrap();
        assert_eq!(t.attempt, 1);
        assert_eq!(f.reserved, 100);
        assert!(t.queue.is_empty());
        t.expire(&mut f, 63).unwrap();
        assert_eq!(t.state, FAILED);
        assert_eq!(t.winner, ZERO);
        assert_eq!(f.remaining, 100);
        assert_eq!(f.accepted_unpaid, 0);
    }
    #[test]
    fn queue_capacity_and_stale_entries_are_bounded() {
        let (_, mut t) = opened();
        for i in 1..=8 {
            t.enqueue([i; 32], 2).unwrap();
        }
        assert!(t.enqueue([9; 32], 2).is_err());
        t.entry([1; 32]).unwrap().state = INVALID;
        t.enqueue([9; 32], 2).unwrap();
        assert_eq!(t.queue.len(), 8);
        t.prune(22);
        assert!(t.queue.is_empty());
    }
    #[test]
    fn quorum_counts_distinct_keys_and_rejects_equivocation() {
        let s = Submission {
            task: [20; 32],
            attempt: 0,
            sequence: 0,
            miner: [21; 32],
            beneficiary: [22; 32],
            commitment: [23; 32],
            commit_slot: 10,
            evidence: Evidence {
                candidate: [24; 32],
                result: [25; 32],
                manifest: [26; 32],
                archive: [27; 32],
            },
            state: REVEALED,
            valid_votes: 0,
            invalid_votes: 0,
            reports: [ZERO; 3],
        };
        let mut s = s;
        assert_eq!(s.vote(0, true, [1; 32]).unwrap(), REVEALED);
        assert_eq!(s.vote(0, true, [1; 32]).unwrap(), REVEALED);
        assert!(s.vote(0, false, [2; 32]).is_err());
        assert_eq!(s.vote(1, true, [2; 32]).unwrap(), VALID);
        assert!(s.vote(3, true, [3; 32]).is_err());
    }
    #[test]
    fn attestation_domain_is_independent_of_vote_arrival_order() {
        let (f, t) = opened();
        let mut s = Submission {
            task: [20; 32],
            attempt: 0,
            sequence: 0,
            miner: [21; 32],
            beneficiary: [22; 32],
            commitment: [23; 32],
            commit_slot: 10,
            evidence: Evidence {
                candidate: [24; 32],
                result: [25; 32],
                manifest: [26; 32],
                archive: [27; 32],
            },
            state: REVEALED,
            valid_votes: 0,
            invalid_votes: 0,
            reports: [ZERO; 3],
        };
        let before = vote_message([99; 32], &f, &t, [30; 32], &s, true, [31; 32], 2);
        s.vote(1, true, [32; 32]).unwrap();
        assert_eq!(
            before,
            vote_message([99; 32], &f, &t, [30; 32], &s, true, [31; 32], 2)
        );
        s.beneficiary = [33; 32];
        assert_ne!(
            before,
            vote_message([99; 32], &f, &t, [30; 32], &s, true, [31; 32], 2)
        );
    }
    #[test]
    fn maximum_accounts_fit_allocations() {
        let (f, mut t) = opened();
        t.descriptor.seeds = (0..16).collect();
        for i in 1..=8 {
            t.enqueue([i; 32], 2).unwrap();
        }
        assert!(bytes(&f).len() + 8 <= FACTORY_SIZE);
        assert!(bytes(&t).len() + 8 <= TASK_SIZE);
    }
    #[test]
    fn no_minimum_interval_between_successful_tasks() {
        let mut f = draft();
        f.count = 2;
        f.budget = 200;
        f.remaining = 200;
        let d = descriptor();
        let mut second = d.clone();
        second.scientific_identity = [9; 32];
        f.catalog_root = catalog_step(catalog_step(ZERO, 0, &d), 1, &second);
        f.append(&d).unwrap();
        f.append(&second).unwrap();
        f.seal().unwrap();
        let mut a = Task::new([10; 32], 0, d);
        let mut b = Task::new([10; 32], 1, second);
        a.open(&mut f, 100).unwrap();
        a.enqueue([21; 32], 100).unwrap();
        a.entry([21; 32]).unwrap().state = VALID;
        a.accept(&mut f, [21; 32], [22; 32], 100).unwrap();
        b.open(&mut f, 100).unwrap();
        assert_eq!(b.opened_at, 100);
        assert_eq!(f.accepted_unpaid, 100);
        assert_eq!(f.reserved, 100);
    }
}
