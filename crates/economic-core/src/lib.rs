//! V2 checked atom accounting. Asset-specific books; confirmed, in-flight and
//! refundable liabilities are disjoint. Historical campaign V1 is unchanged.
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
pub const CAP: u64 = 31_183_324_300_000_000;
pub const POOLS: [u64; 3] = [
    22_451_993_600_000_000,
    5_612_998_400_000_000,
    3_118_332_300_000_000,
];
pub type Result<T> = std::result::Result<T, &'static str>;
#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, BorshSerialize, BorshDeserialize,
)]
pub struct Atoms(pub u64);
impl Serialize for Atoms {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&self.0.to_string())
    }
}
impl<'de> Deserialize<'de> for Atoms {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let s = <String as Deserialize>::deserialize(d)?;
        let n = s.parse::<u64>().map_err(serde::de::Error::custom)?;
        if s != n.to_string() {
            return Err(serde::de::Error::custom("canonical decimal atoms"));
        }
        Ok(Self(n))
    }
}
fn add(a: u64, b: u64) -> Result<u64> {
    a.checked_add(b).ok_or("amount overflow")
}
fn sub(a: u64, b: u64) -> Result<u64> {
    a.checked_sub(b).ok_or("insufficient budget")
}
#[derive(Clone, Debug, Default, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct Vault {
    pub balance: Atoms,
    pub reserved: Atoms,
    pub confirmed: Atoms,
    pub inflight: Atoms,
    pub refunds: Atoms,
    pub other: Atoms,
    pub paid: Atoms,
}
impl Vault {
    pub fn free(&self) -> Result<u64> {
        let sum = [
            self.reserved.0,
            self.confirmed.0,
            self.inflight.0,
            self.refunds.0,
            self.other.0,
        ]
        .into_iter()
        .try_fold(0, add)?;
        sub(self.balance.0, sum)
    }
    pub fn reserve(&mut self, n: u64) -> Result<()> {
        if n == 0 || self.free()? < n {
            return Err("unfunded reservation");
        }
        self.reserved.0 = add(self.reserved.0, n)?;
        Ok(())
    }
    pub fn confirm(&mut self, n: u64) -> Result<()> {
        let from = sub(self.reserved.0, n)?;
        let to = add(self.confirmed.0, n)?;
        self.reserved.0 = from;
        self.confirmed.0 = to;
        Ok(())
    }
    pub fn lock(&mut self, n: u64) -> Result<()> {
        let from = sub(self.confirmed.0, n)?;
        let to = add(self.inflight.0, n)?;
        self.confirmed.0 = from;
        self.inflight.0 = to;
        Ok(())
    }
    pub fn paid(&mut self, n: u64) -> Result<()> {
        let from = sub(self.inflight.0, n)?;
        let balance = sub(self.balance.0, n)?;
        let paid = add(self.paid.0, n)?;
        self.inflight.0 = from;
        self.balance.0 = balance;
        self.paid.0 = paid;
        Ok(())
    }
    pub fn unlock_proven_failed(&mut self, n: u64) -> Result<()> {
        let from = sub(self.inflight.0, n)?;
        let to = add(self.confirmed.0, n)?;
        self.inflight.0 = from;
        self.confirmed.0 = to;
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Stage {
    pub policy: String,
    pub asset: String,
    pub pool: u8,
    pub budget: Atoms,
    pub remaining: Atoms,
    pub refund_remaining: Atoms,
    pub deadline: u64,
    pub closed: bool,
    pub refund_recipient: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EconomicSlotKey {
    pub genesis_hash: String,
    pub program_id: String,
    pub economic_task_id: String,
    pub kind: String,
    pub unit_id: String,
}
impl EconomicSlotKey {
    pub fn validate(&self) -> Result<()> {
        if self.genesis_hash.is_empty() || self.program_id.is_empty() || self.economic_task_id.is_empty()
            || !["discovery", "coverage", "verification", "readout", "community"].contains(&self.kind.as_str())
            || self.unit_id.len()!=64 || !self.unit_id.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
            || (self.kind=="discovery" && self.unit_id!="0".repeat(64)) {return Err("invalid EconomicSlotKey/v1");}
        Ok(())
    }
    pub fn canonical(&self) -> Result<String> {
        self.validate()?;
        // A tuple has an unambiguous canonical encoding in both Rust and JS.
        serde_json::to_string(&["Flybrain/EconomicSlotKey/v1", &self.genesis_hash, &self.program_id,
            &self.economic_task_id, &self.kind, &self.unit_id]).map_err(|_| "slot key encoding")
    }
}
pub fn kind_pool(kind: &str) -> Result<u8> {
    match kind {"discovery"|"coverage"|"readout"=>Ok(0),"verification"=>Ok(1),"community"=>Ok(2),_=>Err("unknown slot kind")}
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Slot {
    // Empty defaults mean a historical, unbound v2 book; never an inferred chain identity.
    #[serde(default)] pub genesis_hash: String,
    #[serde(default)] pub program_id: String,
    #[serde(default)] pub unit_id: String,
    #[serde(default)] pub slot_pda: String,
    pub stage: String,
    pub economic_task: String,
    pub kind: String,
    pub beneficiary: String,
    pub amount: Atoms,
    pub contribution: String,
    pub accepted: bool,
    pub released: bool,
    pub paid: Atoms,
    pub inflight: Atoms,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Payment {
    #[serde(default)] pub payment_id: String,
    #[serde(default)] pub consumption_pda: String,
    pub slot: String,
    pub amount: Atoms,
    pub transaction: String,
    pub status: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Book {
    pub asset: String,
    pub vaults: [Vault; 3],
    pub stages: BTreeMap<String, Stage>,
    pub slots: BTreeMap<String, Slot>,
    pub payments: BTreeMap<String, Payment>,
}
impl Book {
    pub fn new(asset: String, balances: [u64; 3]) -> Self {
        Self {
            asset,
            vaults: balances.map(|n| Vault {
                balance: Atoms(n),
                ..Default::default()
            }),
            stages: BTreeMap::new(),
            slots: BTreeMap::new(),
            payments: BTreeMap::new(),
        }
    }
    // Apply on a copy, commit only after every invariant passes. Database callers
    // must persist this together with the append-only event in one transaction.
    pub fn atomic<T>(&mut self, f: impl FnOnce(&mut Self) -> Result<T>) -> Result<T> {
        let mut next = self.clone();
        let result = f(&mut next)?;
        next.reconcile()?;
        *self = next;
        Ok(result)
    }
    pub fn normalize_legacy_payment_keys(&mut self) -> Result<bool> {
        let mut next=BTreeMap::new();let mut changed=false;
        for (old,mut p) in self.payments.clone(){
            if p.payment_id.is_empty(){p.payment_id=old.clone();changed=true;}
            let key=self.payment_key_for_slot(&p.slot,&p.payment_id)?;changed|=key!=old;
            if next.insert(key,p).is_some(){return Err("ambiguous legacy payment migration");}
        }
        self.payments=next;self.reconcile()?;Ok(changed)
    }
    pub fn open_stage(&mut self, id: String, s: Stage) -> Result<()> {
        if self.stages.contains_key(&id)
            || s.asset != self.asset
            || s.pool > 2
            || s.budget != s.remaining
            || s.refund_remaining.0 != 0
            || s.closed
            || s.policy.is_empty()
            || s.refund_recipient.is_empty()
        {
            return Err("invalid immutable stage");
        }
        self.vaults[s.pool as usize].reserve(s.budget.0)?;
        self.stages.insert(id, s);
        Ok(())
    }
    // Business key is independent of policy, receipt, event id and wallet.
    pub fn reserve_slot(&mut self, key: String, s: Slot) -> Result<()> {
        if self.slots.contains_key(&key)
            || self
                .slots
                .values()
                .any(|x| x.genesis_hash == s.genesis_hash && x.program_id == s.program_id && x.economic_task == s.economic_task && x.kind == s.kind && x.unit_id == s.unit_id)
            || !["discovery", "coverage", "verification", "readout", "community"].contains(&s.kind.as_str())
            || s.amount.0 == 0
            || s.accepted
            || s.released
            || s.paid.0 != 0
            || s.inflight.0 != 0
            || s.beneficiary.is_empty()
            || s.contribution.is_empty()
        {
            return Err("duplicate/invalid reward slot");
        }
        let stage = self.stages.get_mut(&s.stage).ok_or("unknown stage")?;
        if stage.closed || stage.pool != kind_pool(&s.kind)? {
            return Err("stage closed or wrong pool");
        }
        if !s.genesis_hash.is_empty() || !s.program_id.is_empty() || !s.unit_id.is_empty() {
            let identity=EconomicSlotKey {genesis_hash:s.genesis_hash.clone(),program_id:s.program_id.clone(),economic_task_id:s.economic_task.clone(),kind:s.kind.clone(),unit_id:s.unit_id.clone()};
            identity.validate()?;
            if s.slot_pda.is_empty() {return Err("slot PDA required");}
        }
        stage.remaining.0 = sub(stage.remaining.0, s.amount.0)?;
        self.slots.insert(key, s);
        Ok(())
    }
    pub fn accept(&mut self, key: &str, contribution: &str) -> Result<()> {
        let s = self.slots.get_mut(key).ok_or("unknown reward slot")?;
        if s.released || s.contribution != contribution {
            return Err("acceptance binding");
        }
        if s.accepted {
            return Ok(());
        }
        let stage = &self.stages[&s.stage];
        if stage.closed{return Err("stage closed");}
        self.vaults[stage.pool as usize].confirm(s.amount.0)?;
        s.accepted = true;
        Ok(())
    }
    pub fn release_unaccepted(&mut self, key: &str) -> Result<()> {
        let s = self.slots.get_mut(key).ok_or("unknown reward slot")?;
        if s.accepted || s.released || self.stages[&s.stage].closed {
            return Err("confirmed rights cannot be released");
        }
        s.released = true;
        let stage = self.stages.get_mut(&s.stage).ok_or("unknown stage")?;
        stage.remaining.0 = add(stage.remaining.0, s.amount.0)?;
        Ok(())
    }
    pub fn begin_payment(
        &mut self,
        id: String,
        key: &str,
        recipient: &str,
        asset: &str,
        amount: u64,
        transaction: String,
    ) -> Result<()> {
        let payment_key=self.payment_key_for_slot(key,&id)?;
        if self.payments.contains_key(&payment_key)
            || transaction.is_empty()
            || asset != self.asset
            || amount == 0
        {
            return Err("payment identity/asset");
        }
        let s = self.slots.get_mut(key).ok_or("unknown reward slot")?;
        let remaining = sub(sub(s.amount.0, s.paid.0)?, s.inflight.0)?;
        if !s.accepted || s.beneficiary != recipient || amount > remaining {
            return Err("payment recipient/amount");
        }
        self.vaults[self.stages[&s.stage].pool as usize].lock(amount)?;
        s.inflight.0 = add(s.inflight.0, amount)?;
        self.payments.insert(
            payment_key,
            Payment {
                payment_id: id,
                consumption_pda: String::new(),
                slot: key.into(),
                amount: Atoms(amount),
                transaction,
                status: "submitted".into(),
            },
        );
        Ok(())
    }
    pub fn payment_key(slot: &str, payment_id: &str) -> String {
        serde_json::to_string(&["Flybrain/PaymentKey/v1",slot,payment_id]).expect("strings")
    }
    pub fn payment_key_for_slot(&self,key:&str,id:&str)->Result<String>{
        let slot=self.slots.get(key).ok_or("unknown slot")?;
        if slot.genesis_hash.is_empty()&&slot.program_id.is_empty(){return Ok(Self::payment_key(key,id));}
        serde_json::to_string(&["Flybrain/PaymentKey/v1",&slot.genesis_hash,&slot.program_id,key,id]).map_err(|_|"payment key encoding")
    }
    pub fn resolve_payment(&mut self, slot: &str, payment_id: &str, finalized: bool, proven_unexecuted: bool) -> Result<()> {
        self.resolve(&self.payment_key_for_slot(slot,payment_id)?,finalized,proven_unexecuted)
    }
    // Unknown/timeouts remain locked. Only finalized consumption or definitive
    // non-execution after expiry may change the liability bucket.
    pub fn resolve(&mut self, id: &str, finalized: bool, proven_unexecuted: bool) -> Result<()> {
        if finalized == proven_unexecuted {
            return Err("unknown or inconsistent transaction outcome");
        }
        // Old books keep their original global keys; new composite keys may be
        // addressed by paymentId only when there is exactly one matching slot.
        let found:Vec<_>=self.payments.iter().filter(|(k,p)|k.as_str()==id || p.payment_id==id).map(|(k,_)|k.clone()).collect();
        if found.len()!=1 {return Err("unknown or ambiguous payment; use composite key");}
        let p = self.payments.get_mut(&found[0]).ok_or("unknown payment")?;
        if p.status != "submitted" {
            return if (finalized && p.status == "paid") || (!finalized && p.status == "failed") {
                Ok(())
            } else {
                Err("conflicting finality")
            };
        }
        let s = self.slots.get_mut(&p.slot).ok_or("missing slot")?;
        let v = &mut self.vaults[self.stages[&s.stage].pool as usize];
        if finalized {
            v.paid(p.amount.0)?;
            s.paid.0 = add(s.paid.0, p.amount.0)?;
            p.status = "paid".into();
        } else {
            v.unlock_proven_failed(p.amount.0)?;
            p.status = "failed".into();
        }
        s.inflight.0 = sub(s.inflight.0, p.amount.0)?;
        Ok(())
    }
    pub fn close_stage(&mut self, id: &str) -> Result<u64> {
        let s = self.stages.get_mut(id).ok_or("unknown stage")?;
        if s.closed {
            return Err("already closed");
        }
        if self
            .slots
            .values()
            .any(|x| x.stage == id && !x.accepted && !x.released)
        {
            return Err("in-progress service reservations");
        }
        let n = s.remaining.0;
        let v = &mut self.vaults[s.pool as usize];
        v.reserved.0 = sub(v.reserved.0, n)?;
        if s.refund_recipient != "global-pool" {
            v.refunds.0 = add(v.refunds.0, n)?;
        }
        s.remaining.0 = 0;
        s.refund_remaining.0 = if s.refund_recipient == "global-pool" {
            0
        } else {
            n
        };
        s.closed = true;
        Ok(n)
    }
    pub fn refund(&mut self, id: &str, recipient: &str, amount: u64) -> Result<()> {
        let s = self.stages.get_mut(id).ok_or("unknown stage")?;
        if !s.closed || s.refund_recipient != recipient || amount == 0 {
            return Err("refund binding");
        }
        let remaining = sub(s.refund_remaining.0, amount)?;
        let v = &mut self.vaults[s.pool as usize];
        let refunds = sub(v.refunds.0, amount)?;
        let balance = sub(v.balance.0, amount)?;
        v.refunds.0 = refunds;
        v.balance.0 = balance;
        s.refund_remaining.0 = remaining;
        Ok(())
    }
    pub fn reconcile(&self) -> Result<()> {
        for (index, v) in self.vaults.iter().enumerate() {
            v.free()?;
            let mut reserved = 0;
            let mut confirmed = 0;
            let mut inflight = 0;
            let mut refunds = 0;
            let mut paid = 0;
            for s in self.stages.values().filter(|s| s.pool as usize == index) {
                reserved = add(reserved, s.remaining.0)?;
                refunds = add(refunds, s.refund_remaining.0)?;
            }
            for s in self
                .slots
                .values()
                .filter(|s| self.stages[&s.stage].pool as usize == index)
            {
                if add(s.paid.0, s.inflight.0)? > s.amount.0
                    || (!s.accepted && (s.paid.0 != 0 || s.inflight.0 != 0))
                {
                    return Err("overpayment");
                }
                if s.accepted {
                    confirmed = add(confirmed, sub(sub(s.amount.0, s.paid.0)?, s.inflight.0)?)?;
                    inflight = add(inflight, s.inflight.0)?;
                    paid = add(paid, s.paid.0)?;
                } else if !s.released {
                    reserved = add(reserved, s.amount.0)?;
                }
            }
            if [reserved, confirmed, inflight, refunds, paid]
                != [
                    v.reserved.0,
                    v.confirmed.0,
                    v.inflight.0,
                    v.refunds.0,
                    v.paid.0,
                ]
            {
                return Err("liability reconciliation mismatch");
            }
        }
        Ok(())
    }
}
/// Fixed integer allocation in atoms, with deterministic cumulative remainder.
pub fn quota(pool: u64, index: u64, count: u64) -> Result<u64> {
    if count == 0 || index >= count {
        return Err("allocation bounds");
    }
    Ok((((index as u128 + 1) * pool as u128 / count as u128)
        - (index as u128 * pool as u128 / count as u128)) as u64)
}
#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> Book {
        let mut b = Book::new("solana:genesis:mint:8".into(), [1000, 0, 0]);
        b.open_stage(
            "s".into(),
            Stage {
                policy: "p".into(),
                asset: b.asset.clone(),
                pool: 0,
                budget: Atoms(700),
                remaining: Atoms(700),
                refund_remaining: Atoms(0),
                deadline: 9,
                closed: false,
                refund_recipient: "customer".into(),
            },
        )
        .unwrap();
        b.reserve_slot(
            "task/discovery".into(),
            Slot {
                genesis_hash:String::new(),program_id:String::new(),unit_id:String::new(),slot_pda:String::new(),
                stage: "s".into(),
                economic_task: "task".into(),
                kind: "discovery".into(),
                beneficiary: "miner".into(),
                amount: Atoms(100),
                contribution: "c".into(),
                accepted: false,
                released: false,
                paid: Atoms(0),
                inflight: Atoms(0),
            },
        )
        .unwrap();
        b
    }
    #[test]
    fn amounts_and_supply() {
        assert_eq!(POOLS.into_iter().sum::<u64>(), CAP);
        assert!(serde_json::from_str::<Atoms>("31183324300000000").is_err());
        assert_eq!(
            serde_json::from_str::<Atoms>("\"31183324300000000\"")
                .unwrap()
                .0,
            CAP
        );
        let total = (0..71).map(|k| quota(CAP, k, 71).unwrap()).sum::<u64>();
        assert_eq!(total, CAP);
    }
    #[test]
    fn partial_and_unknown_payment_survives_restart() {
        let mut b = fixture();
        b.accept("task/discovery", "c").unwrap();
        b.begin_payment(
            "pay1".into(),
            "task/discovery",
            "miner",
            &b.asset.clone(),
            40,
            "tx1".into(),
        )
        .unwrap();
        assert!(b.resolve("pay1", false, false).is_err());
        let mut b: Book = serde_json::from_str(&serde_json::to_string(&b).unwrap()).unwrap();
        assert!(b
            .atomic(|b| b.begin_payment(
                "pay2".into(),
                "task/discovery",
                "miner",
                &b.asset.clone(),
                61,
                "tx2".into()
            ))
            .is_err());
        b.resolve("pay1", true, false).unwrap();
        b.resolve("pay1", true, false).unwrap();
        b.begin_payment(
            "pay2".into(),
            "task/discovery",
            "miner",
            &b.asset.clone(),
            60,
            "tx2".into(),
        )
        .unwrap();
        b.resolve("pay2", false, true).unwrap();
        b.begin_payment(
            "pay3".into(),
            "task/discovery",
            "miner",
            &b.asset.clone(),
            60,
            "tx3".into(),
        )
        .unwrap();
        b.resolve("pay3", true, false).unwrap();
        assert_eq!(b.slots["task/discovery"].paid.0, 100);
        assert_eq!(b.vaults[0].paid.0, 100);
    }
    #[test]
    fn cancellation_preserves_rights_and_no_duplicate_slot() {
        let mut b = fixture();
        b.accept("task/discovery", "c").unwrap();
        let mut duplicate = b.slots["task/discovery"].clone();
        duplicate.beneficiary = "new-wallet".into();
        duplicate.contribution = "new-event".into();
        assert!(b.reserve_slot("task/discovery".into(), duplicate).is_err());
        assert_eq!(b.close_stage("s").unwrap(), 600);
        b.refund("s", "customer", 600).unwrap();
        b.begin_payment(
            "p".into(),
            "task/discovery",
            "miner",
            &b.asset.clone(),
            100,
            "tx".into(),
        )
        .unwrap();
        b.resolve("p", true, false).unwrap();
        assert_eq!(b.vaults[0].balance.0, 300);
        b.reconcile().unwrap();
    }
    #[test]
    fn budgets_wrong_assets_and_rejection_service() {
        let mut b = fixture();
        let s = b.stages["s"].clone();
        assert!(b.open_stage("second".into(), s).is_err());
        b.accept("task/discovery", "c").unwrap();
        assert!(b
            .begin_payment(
                "p".into(),
                "task/discovery",
                "other",
                &b.asset.clone(),
                10,
                "tx".into()
            )
            .is_err());
        assert!(b
            .begin_payment(
                "p".into(),
                "task/discovery",
                "miner",
                "wrong-mint",
                10,
                "tx".into()
            )
            .is_err());
        b.vaults[1].balance=Atoms(100);
        let mut verification_stage=b.stages["s"].clone();verification_stage.pool=1;verification_stage.budget=Atoms(100);verification_stage.remaining=Atoms(100);
        b.open_stage("vs".into(),verification_stage).unwrap();
        let slot = Slot {
            genesis_hash:String::new(),program_id:String::new(),unit_id:String::new(),slot_pda:String::new(),
            stage: "vs".into(),
            economic_task: "task".into(),
            kind: "verification".into(),
            beneficiary: "verifier".into(),
            amount: Atoms(20),
            contribution: "correct-rejection/job/1".into(),
            accepted: false,
            released: false,
            paid: Atoms(0),
            inflight: Atoms(0),
        };
        b.reserve_slot("job/1/verify".into(), slot).unwrap();
        b.accept("job/1/verify", "correct-rejection/job/1").unwrap();
        assert!(b.release_unaccepted("job/1/verify").is_err());
        assert_eq!(b.vaults[0].confirmed.0, 100);assert_eq!(b.vaults[1].confirmed.0, 20);
    }
}

#[cfg(test)]mod explorer_identity_tests {
 use super::*;
 fn book()->Book{let mut b=Book::new("isolated-v2-atoms".into(),[1000,1000,1000]);for pool in 0..3 {b.open_stage(format!("s{pool}"),Stage{policy:"p".into(),asset:b.asset.clone(),pool,budget:Atoms(500),remaining:Atoms(500),refund_remaining:Atoms(0),deadline:9,closed:false,refund_recipient:"global-pool".into()}).unwrap();}b}
 fn slot(kind:&str,unit:u8)->Slot{Slot{genesis_hash:"genesis".into(),program_id:"program".into(),unit_id:if kind=="discovery"{"0".repeat(64)}else{format!("{unit:064x}")},slot_pda:format!("{kind}-{unit}"),stage:format!("s{}",kind_pool(kind).unwrap()),economic_task:"task".into(),kind:kind.into(),beneficiary:"wallet".into(),amount:Atoms(100),contribution:format!("contribution-{kind}-{unit}"),accepted:false,released:false,paid:Atoms(0),inflight:Atoms(0)}}
 #[test]fn multi_unit_community_and_payment_consumption_match_chain_identity(){
  let mut b=book();for (kind,unit)in [("discovery",0),("coverage",1),("coverage",2),("verification",1),("verification",2),("community",1)] {let s=slot(kind,unit);let key=s.slot_pda.clone();let c=s.contribution.clone();b.reserve_slot(key.clone(),s).unwrap();b.accept(&key,&c).unwrap();}
  assert_eq!(b.vaults[0].confirmed.0,300);assert_eq!(b.vaults[1].confirmed.0,200);assert_eq!(b.vaults[2].confirmed.0,100);
  for key in ["coverage-1","coverage-2"]{b.begin_payment("same-payment-id".into(),key,"wallet",&b.asset.clone(),40,"one-transaction-two-claims".into()).unwrap();b.resolve_payment(key,"same-payment-id",true,false).unwrap();}
  assert_eq!(b.slots["coverage-1"].paid.0,40);assert_eq!(b.slots["coverage-2"].paid.0,40);assert_eq!(b.vaults[0].paid.0,80);assert!(b.resolve("same-payment-id",true,false).is_err());b.reconcile().unwrap();
 }
 #[test]fn pending_reservation_prevents_close_but_accepted_rights_survive(){
  let mut b=book();let s=slot("coverage",1);b.reserve_slot("a".into(),s.clone()).unwrap();assert!(b.atomic(|b|b.close_stage("s0")).is_err());b.release_unaccepted("a").unwrap();assert_eq!(b.close_stage("s0").unwrap(),500);
  let s=slot("verification",1);b.reserve_slot("v".into(),s.clone()).unwrap();b.accept("v",&s.contribution).unwrap();b.close_stage("s1").unwrap();b.begin_payment("payment".into(),"v","wallet",&b.asset.clone(),100,"tx".into()).unwrap();b.resolve_payment("v","payment",true,false).unwrap();assert_eq!(b.slots["v"].paid.0,100);b.reconcile().unwrap();
 }
}
