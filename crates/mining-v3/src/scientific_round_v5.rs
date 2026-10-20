//! Prospectively funded scientific rounds. Existing V3/V4 layouts are immutable.
//! The adapter authenticates chain time, randomness source, signatures and funds.
use borsh::{BorshDeserialize, BorshSerialize};
use sha2::{Digest, Sha256};
pub type Key = [u8; 32];
pub type Result<T> = core::result::Result<T, &'static str>;
pub const ZERO: Key = [0; 32];
pub const ROUND_SIZE: usize = 4096;
pub const CLAIM_SIZE: usize = 768;
pub const MARKER_SIZE: usize = 128;
pub const CAPACITY: usize = 12;
pub const COMMITTED: u8 = 0;
pub const REVEALED: u8 = 1;
pub const ACCEPTED: u8 = 2;
pub const REJECTED: u8 = 3;
pub const DUPLICATE: u8 = 4;
pub const PAID: u8 = 5;
pub fn digest<T: BorshSerialize>(domain: &[u8], value: &T) -> Key {
    let mut h = Sha256::new(); h.update(domain); h.update(borsh::to_vec(value).expect("protocol bytes")); h.finalize().into()
}
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
pub struct Specification {
    pub id: Key,
    /// Content-addressed complete question, sets, costs, windows, stress plans,
    /// provenance, resource limits and reward rules, published before commitment.
    pub content: Key,
    /// Model, graph, parameters, initial state, transition, RNG and horizon.
    /// Excludes wallet, goal/readout name and payout policy.
    pub computation_context: Key,
    pub analysis: Key,
    pub audit_inputs: [Key; 4],
    pub reward_atoms: u64,
    pub commit_start: u64,
    pub commit_end: u64,
    pub challenge_slot: u64,
    pub reveal_end: u64,
    pub verify_end: u64,
    pub backgrounds: u8,
}
impl Specification {
    pub fn validate(&self, now: u64) -> Result<()> {
        if [self.id,self.content,self.computation_context,self.analysis].contains(&ZERO)
            || self.audit_inputs.contains(&ZERO) || self.reward_atoms == 0
            || self.reward_atoms.checked_mul(10).is_none()
            || !(now < self.commit_start && self.commit_start < self.commit_end
                && self.commit_end < self.challenge_slot && self.challenge_slot < self.reveal_end
                && self.reveal_end < self.verify_end)
            || self.verify_end - self.commit_start > 216_000
            || ![2,4,8,16].contains(&self.backgrounds) { return Err("invalid frozen scientific round"); }
        Ok(())
    }
}
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
pub struct Round {
    pub specification: Specification,
    pub genesis: Key, pub policy: Key, pub mint: Key, pub verifiers: [Key; 3],
    pub challenge: Key, pub source_slot: u64,
    pub queues: [Vec<Key>; 3], pub cursors: [u8; 3], pub winners: [Key; 10],
    pub remaining: u64, pub accepted_unpaid: u64, pub paid: u64, pub refunded: u64,
    pub closed: bool,
}
impl Round {
    pub fn accounting(&self) -> Result<()> {
        let total = self.remaining.checked_add(self.accepted_unpaid).and_then(|v|v.checked_add(self.paid)).and_then(|v|v.checked_add(self.refunded));
        if total != self.specification.reward_atoms.checked_mul(10)
            || self.queues.iter().any(|q|q.len()>CAPACITY)
            || (0..3).any(|i|self.cursors[i] as usize>self.queues[i].len()) { return Err("round accounting"); }
        Ok(())
    }
    pub fn commit(&mut self, key: Key, claim: &Claim, slot: u64) -> Result<()> {
        let role = claim.role as usize;
        if self.closed || role>2 || slot<self.specification.commit_start || slot>=self.specification.commit_end
            || self.challenge!=ZERO || self.queues[role].len()>=CAPACITY || self.queues.iter().any(|q|q.contains(&key))
            || !((role==0 && claim.assignment==255)||(role>0 && claim.assignment<2)) { return Err("commit window or role"); }
        self.queues[role].push(key); Ok(())
    }
    pub fn challenge(&mut self, source_slot: u64, source: Key, now: u64) -> Result<()> {
        if self.closed || now<self.specification.challenge_slot || now>self.specification.challenge_slot.saturating_add(128)
            || source_slot<self.specification.challenge_slot || source_slot>now || source==ZERO { return Err("challenge source/window"); }
        let challenge = digest(b"Flybrain/scientific-challenge/v5\0", &(self.genesis,self.specification.id,source_slot,source));
        if self.challenge!=ZERO && (self.challenge!=challenge || self.source_slot!=source_slot) { return Err("challenge immutable"); }
        self.challenge=challenge; self.source_slot=source_slot; Ok(())
    }
    pub fn head(&self, role: u8) -> Option<Key> { self.queues.get(role as usize)?.get(self.cursors[role as usize] as usize).copied() }
    /// Resolve in commitment order, independently of verifier completion order.
    /// Invalid/withheld/duplicate claims consume no contribution place.
    pub fn resolve(&mut self, key: Key, c: &mut Claim, duplicate: bool, slot: u64) -> Result<bool> {
        if [ACCEPTED,PAID].contains(&c.state) { return Ok(false); }
        if self.closed || self.head(c.role)!=Some(key) { return Err("not eligible queue head"); }
        let complete = c.complete_votes.count_ones()>=2;
        let scientific = c.positive_votes.count_ones()>=2;
        let negative = (c.complete_votes & !c.positive_votes).count_ones()>=2;
        let invalid = c.invalid_votes.count_ones()>=2;
        let expired = !(complete && (scientific||negative)) &&
            (slot>self.specification.verify_end || c.state==COMMITTED && slot>self.specification.reveal_end);
        if !invalid && !expired && !(complete && (scientific||negative)) { return Err("head still pending"); }
        let place = match c.role {
            0 => (0..6).find(|i|self.winners[*i]==ZERO),
            1 => Some(6+c.assignment as usize).filter(|i|self.winners[*i]==ZERO),
            2 => Some(8+c.assignment as usize).filter(|i|self.winners[*i]==ZERO),
            _ => None,
        };
        let accept = !expired && complete && (c.role>0 || scientific) && !duplicate && place.is_some();
        if accept {
            self.remaining=self.remaining.checked_sub(self.specification.reward_atoms).ok_or("budget exhausted")?;
            self.accepted_unpaid=self.accepted_unpaid.checked_add(self.specification.reward_atoms).ok_or("amount overflow")?;
            self.winners[place.unwrap()]=key; c.state=ACCEPTED;
        } else { c.state=if duplicate {DUPLICATE} else {REJECTED}; }
        self.cursors[c.role as usize]+=1; self.accounting()?; Ok(accept)
    }
    pub fn close(&mut self, slot: u64) -> Result<u64> {
        if self.closed {return Ok(0);}
        if (slot<=self.specification.verify_end && self.winners.contains(&ZERO))
            || (0..3).any(|i|self.cursors[i] as usize!=self.queues[i].len()) {return Err("round remains open or unresolved");}
        // Accepted claims remain payable, including after successor rounds open.
        self.closed=true; let refund=self.remaining; self.remaining=0;
        self.refunded=self.refunded.checked_add(refund).ok_or("refund overflow")?;
        self.accounting()?; Ok(refund)
    }
    pub fn pay(&mut self, claim: &mut Claim) -> Result<u64> {
        if claim.state==PAID {return Ok(0);}
        if claim.state!=ACCEPTED {return Err("no earned entitlement");}
        let amount=self.specification.reward_atoms;
        self.accepted_unpaid=self.accepted_unpaid.checked_sub(amount).ok_or("unpaid accounting")?;
        self.paid=self.paid.checked_add(amount).ok_or("paid overflow")?;
        claim.state=PAID; self.accounting()?; Ok(amount)
    }
}
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
pub struct Claim {
    pub round: Key, pub miner: Key, pub beneficiary: Key, pub commitment: Key,
    pub role: u8, pub assignment: u8, pub input: Key, pub manifest: Key, pub result: Key,
    pub computation: Key, pub state: u8, pub complete_votes: u8, pub positive_votes: u8, pub invalid_votes: u8,
    pub reports: [Key; 3],
}
pub fn input_commitment(program: Key, r: &Round, c: &Claim, input: Key, salt: Key) -> Key {
    digest(b"Flybrain/scientific-input-commitment/v5\0", &(program,r.genesis,r.policy,c.round,c.miner,c.beneficiary,c.role,c.assignment,input,salt))
}
pub fn computation(r: &Round, role: u8, assignment: u8, input: Key) -> Key {
    digest(b"Flybrain/scientific-computation/v5\0", &(r.specification.computation_context,r.challenge,role,assignment,r.specification.backgrounds,input))
}
pub fn seed(r: &Round, role: u8, assignment: u8, index: u8) -> u64 {
    let h=digest(b"Flybrain/scientific-background/v5\0", &(r.challenge,role,assignment,index));
    u64::from_le_bytes(h[..8].try_into().unwrap())
}
impl Claim {
    pub fn reveal(&mut self, program: Key, r: &Round, input: Key, salt: Key, manifest: Key, result: Key, slot: u64) -> Result<()> {
        if self.state!=COMMITTED || r.closed || r.challenge==ZERO || slot<r.specification.challenge_slot
            || slot>r.specification.reveal_end || [input,salt,manifest,result].contains(&ZERO)
            || input_commitment(program,r,self,input,salt)!=self.commitment {return Err("invalid reveal");}
        if self.role>0 && r.specification.audit_inputs[2*(self.role as usize-1)+self.assignment as usize]!=input {return Err("assigned audit input");}
        self.input=input; self.manifest=manifest; self.result=result;
        self.computation=computation(r,self.role,self.assignment,input); self.state=REVEALED; Ok(())
    }
    pub fn vote(&mut self, index: usize, complete: bool, passed: bool, report: Key) -> Result<()> {
        if index>=3 || self.state!=REVEALED || report==ZERO || passed && !complete {return Err("invalid verifier vote");}
        let bit=1<<index;
        if (self.complete_votes|self.invalid_votes)&bit!=0 {
            if self.reports[index]==report && (self.complete_votes&bit!=0)==complete && (self.positive_votes&bit!=0)==passed {return Ok(());}
            return Err("conflicting verifier vote");
        }
        self.reports[index]=report;
        if complete {self.complete_votes|=bit;}else{self.invalid_votes|=bit;}
        if passed {self.positive_votes|=bit;}
        Ok(())
    }
}
pub fn vote_message(program: Key, r: &Round, key: Key, c: &Claim, complete: bool, passed: bool, report: Key) -> Key {
    digest(b"Flybrain/scientific-verdict/v5\0", &(program,r.genesis,r.policy,c.round,key,c.commitment,c.input,c.computation,
        r.specification.analysis,r.specification.content,c.manifest,c.result,c.beneficiary,complete,passed,report))
}
#[derive(BorshSerialize, BorshDeserialize)]
pub enum Operation {
    Initialize { specification: Specification },
    Commit { commitment: Key, beneficiary: Key, role: u8, assignment: u8 },
    Challenge,
    Reveal { input: Key, salt: Key, manifest: Key, result: Key },
    Vote { complete: bool, passed: bool, report: Key, ed25519_index: u16 },
    Resolve,
    Pay,
    Close,
}

#[cfg(test)]
mod tests {
    use super::*;
    fn round()->Round {
        Round{specification:Specification{id:[1;32],content:[2;32],computation_context:[3;32],analysis:[4;32],audit_inputs:[[5;32];4],reward_atoms:20,
            commit_start:10,commit_end:100,challenge_slot:105,reveal_end:500,verify_end:1000,backgrounds:2},
            genesis:[6;32],policy:[7;32],mint:[8;32],verifiers:[[9;32],[10;32],[11;32]],challenge:ZERO,source_slot:0,
            queues:std::array::from_fn(|_|Vec::new()),cursors:[0;3],winners:[ZERO;10],remaining:200,accepted_unpaid:0,paid:0,refunded:0,closed:false}
    }
    fn claim(role:u8,assignment:u8)->Claim {
        Claim{round:[12;32],miner:[13;32],beneficiary:[14;32],commitment:[15;32],role,assignment,input:ZERO,manifest:ZERO,result:ZERO,
            computation:ZERO,state:COMMITTED,complete_votes:0,positive_votes:0,invalid_votes:0,reports:[ZERO;3]}
    }
    fn verified(c:&mut Claim,passed:bool){c.state=REVEALED;c.vote(0,true,passed,[21;32]).unwrap();c.vote(1,true,passed,[22;32]).unwrap();}
    #[test]
    fn commitment_precedes_immutable_challenge_and_binds_claim(){
        let mut r=round();r.specification.validate(0).unwrap();let mut c=claim(0,255);
        c.commitment=input_commitment([23;32],&r,&c,[5;32],[24;32]);
        assert!(r.challenge(105,[25;32],104).is_err());
        assert!(c.reveal([23;32],&r,[5;32],[24;32],[26;32],[27;32],106).is_err());
        r.commit([16;32],&c,11).unwrap();r.challenge(105,[25;32],106).unwrap();
        assert!(r.commit([17;32],&c,106).is_err());assert!(r.challenge(106,[29;32],107).is_err());
        let mut stolen=c.clone();stolen.miner=[30;32];assert!(stolen.reveal([23;32],&r,[5;32],[24;32],[26;32],[27;32],106).is_err());
        c.reveal([23;32],&r,[5;32],[24;32],[26;32],[27;32],106).unwrap();
        assert_eq!(c.computation,computation(&r,0,255,[5;32]));
        assert_ne!(seed(&r,0,255,0),seed(&r,1,0,0));
        assert_ne!(seed(&r,0,255,0),seed(&r,0,255,1));
    }
    #[test]
    fn ten_places_include_correct_negative_audits_and_finite_payments(){
        let mut r=round();let mut claims=Vec::new();
        for i in 0..10_u8 {
            let (role,assignment)=if i<6 {(0,255)} else if i<8 {(1,i-6)} else {(2,i-8)};
            let c=claim(role,assignment);r.commit([i+40;32],&c,11).unwrap();claims.push(c);
        }
        r.challenge(105,[25;32],106).unwrap();
        for (i,c) in claims.iter_mut().enumerate(){verified(c,i<6);assert!(r.resolve([i as u8+40;32],c,false,200).unwrap());}
        assert_eq!(r.accepted_unpaid,200);assert_eq!(r.remaining,0);assert!(!r.winners.contains(&ZERO));
        assert_eq!(r.close(201).unwrap(),0);
        for c in &mut claims {assert_eq!(r.pay(c).unwrap(),20);assert_eq!(r.pay(c).unwrap(),0);}
        assert_eq!(r.paid,200);r.accounting().unwrap();
    }
    #[test]
    fn ordering_withholding_duplicates_and_late_settlement_preserve_entitlements(){
        let mut r=round();let mut first=claim(0,255);let mut second=claim(0,255);
        r.commit([40;32],&first,11).unwrap();r.commit([41;32],&second,12).unwrap();verified(&mut second,true);
        assert!(r.resolve([41;32],&mut second,false,200).is_err());assert!(r.resolve([40;32],&mut first,false,499).is_err());
        assert!(!r.resolve([40;32],&mut first,false,501).unwrap());
        assert!(r.close(1001).is_err()); // The earlier verified result is still eligible.
        assert!(r.resolve([41;32],&mut second,false,1001).unwrap());
        assert_eq!(r.close(1002).unwrap(),180);assert_eq!(r.accepted_unpaid,20);
        assert_eq!(r.pay(&mut second).unwrap(),20);r.accounting().unwrap();
        let mut r=round();let mut c=claim(2,0);r.commit([40;32],&c,11).unwrap();verified(&mut c,false);
        assert!(!r.resolve([40;32],&mut c,true,200).unwrap());assert_eq!(c.state,DUPLICATE);assert_eq!(r.remaining,200);
    }
    #[test]
    fn invalid_votes_and_changed_audit_assignments_do_not_earn(){
        let mut r=round();r.challenge(105,[25;32],106).unwrap();let mut c=claim(1,0);
        c.commitment=input_commitment([23;32],&r,&c,[31;32],[24;32]);
        assert!(c.reveal([23;32],&r,[31;32],[24;32],[26;32],[27;32],106).is_err());
        c.state=REVEALED;c.vote(0,false,false,[21;32]).unwrap();
        assert!(c.vote(0,true,true,[22;32]).is_err());assert!(c.vote(1,false,true,[22;32]).is_err());
    }
}
