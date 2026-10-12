//! Versioned financial authorization and canonical 1024-byte mining summaries.
//! Chain ownership, signatures and transfers are enforced by the SBF adapter.
use borsh::{BorshDeserialize, BorshSerialize};

pub type Key = [u8; 32];
pub type Result<T> = std::result::Result<T, &'static str>;
pub const RESULT_SIZE: usize = 1024;
pub const RESULT_TAG: [u8; 8] = *b"FBMRV003";
pub const RESULT_VERSION: u16 = 3;
pub const ROOT_COUNT: usize = 25;

#[repr(usize)]
#[derive(Clone, Copy, Debug)]
pub enum Binding {
    Genesis, Program, Policy, Stage, EconomicTask, Unit, Round, Candidate, Claim,
    Contribution, Model, Graph, Parameters, GoalResult, Manifest, Archive, Miner,
    Beneficiary, OriginalGrantId, OriginalSession, PermanentUnit, OriginalGrant,
    SettlerPolicy, ReplayEvidence, WinnerProof,
}

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ResultRecord {
    pub roots: [Key; ROOT_COUNT],
    pub original_generation: u64,
    pub round_sequence: u64,
    pub claim_sequence: u64,
    pub reward_atoms: u64,
    pub rent_lamports: u64,
    pub accepted_at: u64,
    pub settled_slot: u64,
    pub settled_at: i64,
    pub required_trials: u16,
    pub complete_trials: u16,
    pub steps: u32,
    pub neurons: u32,
    pub metrics_version: u32,
    pub metrics: [i64; 16],
}

impl ResultRecord {
    pub fn get(&self, field: Binding) -> &Key { &self.roots[field as usize] }
    pub fn validate(&self) -> Result<()> {
        if self.roots.iter().enumerate().any(|(i, root)| i != Binding::Unit as usize && *root == [0; 32]) {
            return Err("missing result binding");
        }
        if self.original_generation == 0 || self.round_sequence == 0 || self.claim_sequence == 0 ||
            self.reward_atoms == 0 || self.required_trials < 2 || self.required_trials > 16 ||
            self.complete_trials != self.required_trials || self.steps != 256 ||
            self.neurons == 0 || self.neurons > 1_000_000 || self.metrics_version != 1 ||
            self.metrics[13..].iter().any(|n| *n != 0) {
            return Err("invalid result counters");
        }
        Ok(())
    }
    #[inline(never)]
    pub fn encode(&self) -> Result<[u8; RESULT_SIZE]> {
        self.validate()?;
        let mut bytes = [0u8; RESULT_SIZE];
        bytes[..8].copy_from_slice(&RESULT_TAG);
        bytes[8..10].copy_from_slice(&RESULT_VERSION.to_le_bytes());
        bytes[12..16].copy_from_slice(&(RESULT_SIZE as u32).to_le_bytes());
        for (i, root) in self.roots.iter().enumerate() { bytes[16+i*32..48+i*32].copy_from_slice(root); }
        for (i, value) in [self.original_generation,self.round_sequence,self.claim_sequence,self.reward_atoms,
            self.rent_lamports,self.accepted_at,self.settled_slot,self.settled_at as u64].iter().enumerate() {
            bytes[816+i*8..824+i*8].copy_from_slice(&value.to_le_bytes());
        }
        bytes[880..882].copy_from_slice(&self.required_trials.to_le_bytes());
        bytes[882..884].copy_from_slice(&self.complete_trials.to_le_bytes());
        for (at, value) in [(884,self.steps),(888,self.neurons),(892,self.metrics_version)] {
            bytes[at..at+4].copy_from_slice(&value.to_le_bytes());
        }
        for (i, value) in self.metrics.iter().enumerate() { bytes[896+i*8..904+i*8].copy_from_slice(&value.to_le_bytes()); }
        Ok(bytes)
    }
    #[inline(never)]
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != RESULT_SIZE || bytes[..8] != RESULT_TAG || bytes[8..10] != RESULT_VERSION.to_le_bytes() ||
            bytes[10..12] != [0,0] || bytes[12..16] != (RESULT_SIZE as u32).to_le_bytes() {
            return Err("result size/discriminator/version");
        }
        let u64_at = |at| u64::from_le_bytes(bytes[at..at+8].try_into().unwrap());
        let u32_at = |at| u32::from_le_bytes(bytes[at..at+4].try_into().unwrap());
        let mut roots = [[0;32];ROOT_COUNT];
        for (i, root) in roots.iter_mut().enumerate() { root.copy_from_slice(&bytes[16+i*32..48+i*32]); }
        let mut metrics = [0;16];
        for (i, value) in metrics.iter_mut().enumerate() { *value = u64_at(896+i*8) as i64; }
        let result = Self {roots,original_generation:u64_at(816),round_sequence:u64_at(824),claim_sequence:u64_at(832),
            reward_atoms:u64_at(840),rent_lamports:u64_at(848),accepted_at:u64_at(856),settled_slot:u64_at(864),
            settled_at:u64_at(872) as i64,required_trials:u16::from_le_bytes(bytes[880..882].try_into().unwrap()),
            complete_trials:u16::from_le_bytes(bytes[882..884].try_into().unwrap()),steps:u32_at(884),neurons:u32_at(888),
            metrics_version:u32_at(892),metrics};
        result.validate()?; Ok(result)
    }
    /// A prepared summary has no caller-supplied financial execution fields.
    pub fn validate_prepared(&self) -> Result<()> {
        self.validate()?;
        if self.rent_lamports != 0 || self.accepted_at != 0 || self.settled_slot != 0 || self.settled_at != 0 {
            return Err("prepared execution fields must be zero");
        }
        Ok(())
    }
}

#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
pub struct Grant {
    pub id: Key,
    pub miner: Key,
    pub beneficiary: Key,
    pub session: Key,
    pub policy: Key,
    pub generation: u64,
    pub deposited: u64,
    pub spent: u64,
    pub withdrawn: u64,
    pub successes: u64,
    pub max_spend: u64,
    pub max_result_rent: u64,
    pub max_results: u64,
    pub expires_at: i64,
    pub revoked: bool,
    pub management_rent: u64,
}
impl Grant {
    pub fn validate(&self) -> Result<()> {
        if self.id == [0;32] || self.miner == [0;32] || self.miner != self.beneficiary ||
            self.session == [0;32] || self.policy == [0;32] || self.generation == 0 ||
            self.max_spend == 0 || self.max_result_rent == 0 || self.max_results == 0 ||
            self.spent > self.max_spend || self.successes > self.max_results ||
            self.spent.checked_add(self.withdrawn).ok_or("principal overflow")? > self.deposited {
            return Err("invalid finite grant");
        }
        Ok(())
    }
    pub fn available(&self) -> Result<u64> {
        self.validate()?;
        self.deposited.checked_sub(self.spent).and_then(|n|n.checked_sub(self.withdrawn)).ok_or("principal underflow")
    }
    pub fn check(&self, now:i64, generation:u64, actual_rent:u64) -> Result<()> {
        self.validate()?;
        if self.revoked || now > self.expires_at || generation != self.generation { return Err("grant expired/revoked/generation"); }
        if actual_rent > self.max_result_rent || actual_rent > self.available()? ||
            self.spent.checked_add(actual_rent).ok_or("spend overflow")? > self.max_spend ||
            self.successes.checked_add(1).ok_or("result count overflow")? > self.max_results {
            return Err("grant quota insufficient");
        }
        Ok(())
    }
    pub fn consume(&mut self, now:i64, generation:u64, actual_rent:u64) -> Result<()> {
        self.check(now,generation,actual_rent)?;
        self.spent=self.spent.checked_add(actual_rent).ok_or("spend overflow")?;
        self.successes=self.successes.checked_add(1).ok_or("result count overflow")?;
        Ok(())
    }
    pub fn withdraw(&mut self, amount:u64) -> Result<()> {
        if amount > self.available()? { return Err("withdrawal exceeds unused principal"); }
        self.withdrawn=self.withdrawn.checked_add(amount).ok_or("withdrawal overflow")?; Ok(())
    }
}

#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
pub struct FinancialIntent {
    pub genesis: Key, pub program: Key, pub policy: Key, pub unit_account: Key,
    pub economic_task: Key, pub unit: Key, pub round: Key, pub candidate: Key,
    pub commitment: Key, pub goal_result: Key, pub manifest: Key, pub scientific_identity: Key,
    pub miner: Key, pub beneficiary: Key, pub grant: Key, pub grant_generation:u64,
    pub session: Key, pub reward_atoms:u64, pub max_result_rent:u64,
}
pub fn intent_bytes(intent:&FinancialIntent) -> Vec<u8> {
    let mut bytes=b"flybrainlabs/mining-v3/intent\0".to_vec();
    bytes.extend(borsh::to_vec(intent).expect("fixed financial intent serializes")); bytes
}

#[cfg(test)]
mod tests {
    use super::*;
    fn grant()->Grant { Grant{id:[1;32],miner:[2;32],beneficiary:[2;32],session:[3;32],policy:[4;32],generation:1,
        deposited:30,spent:0,withdrawn:0,successes:0,max_spend:20,max_result_rent:10,max_results:2,
        expires_at:100,revoked:false,management_rent:99} }
    #[test] fn quotas_generations_and_unused_principal_are_distinct_from_auxiliary_rent(){
        let mut g=grant();assert!(g.consume(10,2,10).is_err());assert!(g.consume(10,1,11).is_err());
        g.consume(10,1,10).unwrap();g.consume(11,1,10).unwrap();assert!(g.consume(12,1,0).is_err());
        assert_eq!(g.available().unwrap(),10);assert!(g.withdraw(11).is_err());g.withdraw(10).unwrap();
        assert_eq!(g.available().unwrap(),0);assert_eq!(g.management_rent,99);
        let mut g=grant();g.revoked=true;assert!(g.consume(10,1,1).is_err());g.revoked=false;assert!(g.consume(101,1,1).is_err());
    }
    #[test] fn result_is_exact_canonical_and_prepared_fields_cannot_claim_execution(){
        let mut record=ResultRecord{roots:[[1;32];ROOT_COUNT],original_generation:1,round_sequence:2,claim_sequence:3,
            reward_atoms:100_000_000,rent_lamports:0,accepted_at:0,settled_slot:0,settled_at:0,required_trials:2,
            complete_trials:2,steps:256,neurons:165122,metrics_version:1,metrics:[0;16]};
        record.roots[Binding::Unit as usize]=[0;32];let bytes=record.encode().unwrap();assert_eq!(bytes.len(),1024);
        assert_eq!(ResultRecord::decode(&bytes).unwrap(),record);record.validate_prepared().unwrap();
        record.rent_lamports=1;assert!(record.validate_prepared().is_err());
        let mut altered=bytes;altered[10]=1;assert!(ResultRecord::decode(&altered).is_err());
        let mut altered=bytes;altered[1008]=1;assert!(ResultRecord::decode(&altered).is_err());
        record.complete_trials=1;assert!(record.encode().is_err());
    }
}
