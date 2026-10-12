//! Service funds have no issuance operation. A ledger is one bounded vault
//! partition; every customer, reserve and unpaid revenue in it is aggregated.
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
pub type Key = [u8; 32];
pub type Result<T> = std::result::Result<T, &'static str>;
pub const CAP: u64 = 31_183_324_300_000_000;
pub const MAX_OBJECTS: usize = 64;
pub const MAX_RECEIPTS: usize = 2048;

pub fn atoms(s: &str) -> Result<u128> {
    if s.is_empty() || s.len() > 39 || !s.bytes().all(|b| b.is_ascii_digit()) || (s.len() > 1 && s.starts_with('0')) { return Err("INVALID_INPUT: canonical atoms"); }
    s.parse().map_err(|_| "RESOURCE_LIMIT: atom overflow")
}
pub fn add(a: u128, b: u128) -> Result<u128> { a.checked_add(b).ok_or("RESOURCE_LIMIT: money overflow") }
pub fn sub(a: u128, b: u128) -> Result<u128> { a.checked_sub(b).ok_or("INSUFFICIENT_FLY: reserved funds") }
pub fn proportional(total: u128, units: u64, all: u64) -> Result<u128> {
    if all == 0 || units > all { return Err("INVALID_INPUT: ratio"); }
    add((total / u128::from(all)).checked_mul(u128::from(units)).ok_or("RESOURCE_LIMIT: ratio overflow")?, (total % u128::from(all)) * u128::from(units) / u128::from(all))
}
pub fn pools(total: u128, basis: [u16; 4]) -> Result<([u128; 4], u128)> {
    if basis.iter().map(|b| u32::from(*b)).sum::<u32>() != 10_000 { return Err("INVALID_INPUT: pool policy"); }
    let mut p = [0; 4]; let mut used = 0;
    for i in 0..4 { p[i] = proportional(total, basis[i] as u64, 10_000)?; used = add(used, p[i])?; }
    Ok((p, sub(total, used)?))
}
/// JSON always encodes atoms as decimal strings; Borsh uses a checked u128.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, BorshSerialize, BorshDeserialize)]
pub struct Amount(pub u128);
impl Serialize for Amount { fn serialize<S: serde::Serializer>(&self, s:S) -> std::result::Result<S::Ok,S::Error> { s.serialize_str(&self.0.to_string()) } }
impl<'de> Deserialize<'de> for Amount { fn deserialize<D:serde::Deserializer<'de>>(d:D)->std::result::Result<Self,D::Error> { let s=<String as Deserialize>::deserialize(d)?; atoms(&s).map(Self).map_err(serde::de::Error::custom) } }

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub struct Asset { pub genesis:Key, pub issuance_program:Key, pub service_program:Key, pub token_program:Key, pub mint:Key, pub vault:Key, pub vault_authority:Key, pub policy:Key, pub decimals:u8, pub production:bool }
#[derive(Clone, Debug)]
pub struct MintObservation { pub asset:Asset, pub supply:u64, pub initialized:bool, pub issued_cap:u64, pub issuance_record_verified:bool, pub mint_authority_revoked:bool, pub freeze_authority_revoked:bool }
impl Asset {
    pub fn verify(&self, observation:&MintObservation, production:bool)->Result<()> {
        if observation.asset!=*self || self.decimals!=8 || production!=self.production || [self.genesis,self.issuance_program,self.service_program,self.token_program,self.mint,self.vault,self.vault_authority,self.policy].contains(&[0;32]) { return Err("ASSET_MISMATCH: complete asset identity"); }
        if !observation.initialized || observation.supply>CAP || observation.issued_cap!=CAP || !observation.issuance_record_verified || !observation.mint_authority_revoked || !observation.freeze_authority_revoked { return Err("ASSET_MISMATCH: issuance or authority evidence"); }
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct Share { pub entitlement:Key, pub beneficiary:Key, pub units:u64, pub claimed:Amount, pub beneficiary_sequence:u64 }
#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct Version { pub id:Key, pub artifact:Key, pub policy:Key, pub basis:[u16;4], pub shares:Vec<Share>, pub payees:[Key;3], pub matured:Amount, pub paid:[Amount;4], pub released:bool }
impl Version {
    pub fn units(&self)->Result<u64> { self.shares.iter().try_fold(0u64,|a,s|a.checked_add(s.units).ok_or("RESOURCE_LIMIT: shares overflow")) }
    pub fn validate(&self)->Result<()> {
        pools(self.matured.0,self.basis)?;
        if self.id==[0;32]||self.artifact==[0;32]||self.policy==[0;32]||self.shares.is_empty()||self.shares.len()>MAX_OBJECTS||self.payees.contains(&[0;32])||self.units()?==0 { return Err("INVALID_INPUT: frozen version"); }
        for (i,s) in self.shares.iter().enumerate() {
            if s.entitlement==[0;32]||s.beneficiary==[0;32]||s.units==0||self.shares[..i].iter().any(|x|x.entitlement==s.entitlement) { return Err("INVALID_INPUT: stable unique entitlement"); }
        }
        let (p,_)=pools(self.matured.0,self.basis)?;
        let mut claimed=0;
        for s in &self.shares { if s.claimed.0>proportional(p[0],s.units,self.units()?)? { return Err("INSUFFICIENT_FLY: excessive claim"); } claimed=add(claimed,s.claimed.0)?; }
        if claimed!=self.paid[0].0 || (0..4).any(|i| self.paid[i].0>p[i]) { return Err("INSUFFICIENT_FLY: excessive pool payout"); }
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct Customer { pub id:Key, pub wallet:Key, pub available:Amount, pub reserved:Amount }
#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct Allowance { pub id:Key, pub customer:Key, pub session:Key, pub version:Key, pub price_policy:Key, pub limit:Amount, pub used:Amount, pub reserved:Amount, pub expires:u64, pub revoked:bool }
#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct Order { pub id:Key, pub customer:Key, pub allowance:Key, pub version:Key, pub request:Key, pub amount:Amount, pub refunded:Amount, pub matured:Amount, pub receipt:Key, pub reserved:bool, pub consumed:bool }
#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct Business { pub id:Key, pub digest:Key }
#[derive(Clone, Debug, Default, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct Ledger { pub customers:Vec<Customer>, pub allowances:Vec<Allowance>, pub orders:Vec<Order>, pub versions:Vec<Version>, pub receipts:Vec<Business>, pub accounted_balance:Amount }
#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub enum Operation {
    Deposit { customer:Key, wallet:Key, amount:Amount },
    Authorize { allowance:Allowance },
    Revoke { allowance:Key },
    Publish { version:Version },
    Retire { version:Key },
    Reserve { order:Key, allowance:Key, request:Key, amount:Amount, now:u64 },
    Consume { order:Key, receipt:Key },
    Refund { order:Key, amount:Amount },
    Mature { order:Key, amount:Amount },
    Claim { version:Key, entitlement:Key, beneficiary:Key, amount:Amount },
    Pay { version:Key, pool:u8, beneficiary:Key, amount:Amount, fulfillment:Key },
    Beneficiary { version:Key, entitlement:Key, old:Key, new:Key, sequence:u64 },
    Withdraw { customer:Key, wallet:Key, amount:Amount },
}
impl Ledger {
    pub fn obligations(&self)->Result<u128> {
        let mut total=0;
        for c in &self.customers { total=add(total,add(c.available.0,c.reserved.0)?)?; }
        for o in &self.orders { if o.consumed { total=add(total,sub(sub(o.amount.0,o.refunded.0)?,o.matured.0)?)?; } }
        for v in &self.versions { let paid=v.paid.iter().try_fold(0,|n,a|add(n,a.0))?; total=add(total,sub(v.matured.0,paid)?)?; }
        Ok(total)
    }
    pub fn validate(&self,actual_balance:u128)->Result<()> {
        if [self.customers.len(),self.allowances.len(),self.orders.len(),self.versions.len()].iter().any(|n|*n>MAX_OBJECTS)||self.receipts.len()>MAX_RECEIPTS { return Err("RESOURCE_LIMIT: vault partition inventory"); }
        for v in &self.versions {v.validate()?;}
        if self.obligations()?!=self.accounted_balance.0 || self.accounted_balance.0>actual_balance {return Err("INSUFFICIENT_FLY: global vault coverage");}
        for c in &self.customers { let expected=self.orders.iter().filter(|o|o.customer==c.id&&o.reserved).try_fold(0,|n,o|add(n,o.amount.0))?; if expected!=c.reserved.0 {return Err("INVALID_INPUT: customer reservation ledger");} }
        for a in &self.allowances { if add(a.used.0,a.reserved.0)?>a.limit.0 {return Err("INSUFFICIENT_FLY: allowance limit");} }
        Ok(())
    }
    /// Clone first: rejected commands cannot leave half-updated host state.
    /// On-chain invocation also rolls back the actual SPL transfer on error.
    pub fn apply(&mut self,business:Key,op:Operation,actual_balance:u128)->Result<bool> {
        if business==[0;32] {return Err("INVALID_INPUT: business identity");}
        let bytes=borsh::to_vec(&op).map_err(|_|"INVALID_INPUT: operation")?;
        let digest:Key=Sha256::digest(bytes).into();
        if let Some(old)=self.receipts.iter().find(|r|r.id==business) {return if old.digest==digest {Ok(false)} else {Err("IDEMPOTENCY_CONFLICT: business content")};}
        let mut next=self.clone(); next.execute(op)?;
        next.receipts.push(Business{id:business,digest});next.validate(actual_balance)?;*self=next;Ok(true)
    }
    fn customer(&self,id:&Key)->Result<usize> {self.customers.iter().position(|c|&c.id==id).ok_or("NOT_FOUND: customer")}
    fn allowance(&self,id:&Key)->Result<usize> {self.allowances.iter().position(|c|&c.id==id).ok_or("NOT_FOUND: allowance")}
    fn order(&self,id:&Key)->Result<usize> {self.orders.iter().position(|c|&c.id==id).ok_or("NOT_FOUND: order")}
    fn version(&self,id:&Key)->Result<usize> {self.versions.iter().position(|c|&c.id==id).ok_or("NOT_FOUND: version")}
    fn execute(&mut self,op:Operation)->Result<()> {
        match op {
            Operation::Deposit{customer,wallet,amount}=> {
                if customer==[0;32]||wallet==[0;32]||amount.0==0 {return Err("INVALID_INPUT: deposit");}
                let i=if let Some(i)=self.customers.iter().position(|c|c.id==customer) {if self.customers[i].wallet!=wallet{return Err("AUTHORIZATION: customer wallet");}i} else {self.customers.push(Customer{id:customer,wallet,available:Amount(0),reserved:Amount(0)});self.customers.len()-1};
                self.customers[i].available.0=add(self.customers[i].available.0,amount.0)?; self.accounted_balance.0=add(self.accounted_balance.0,amount.0)?;
            },
            Operation::Authorize{allowance:a}=> { self.customer(&a.customer)?;self.version(&a.version)?;
                if a.id==[0;32]||a.session==[0;32]||a.price_policy==[0;32]||a.limit.0==0||a.used.0!=0||a.reserved.0!=0||a.expires==0||a.revoked||self.allowances.iter().any(|x|x.id==a.id){return Err("INVALID_INPUT: finite allowance");}self.allowances.push(a);
            },
            Operation::Revoke{allowance}=>{let i=self.allowance(&allowance)?;self.allowances[i].revoked=true;},
            Operation::Publish{version:v}=>{v.validate()?;if !v.released||v.matured.0!=0||v.paid.iter().any(|a|a.0!=0)||v.shares.iter().any(|s|s.claimed.0!=0||s.beneficiary_sequence!=0)||self.versions.iter().any(|x|x.id==v.id){return Err("INVALID_INPUT: new frozen version");}self.versions.push(v);},
            Operation::Retire{version}=>{let i=self.version(&version)?;self.versions[i].released=false;},
            Operation::Reserve{order,allowance,request,amount,now}=>{
                let ai=self.allowance(&allowance)?;let a=&self.allowances[ai];let ci=self.customer(&a.customer)?;let vi=self.version(&a.version)?;
                if a.revoked||now>=a.expires||!self.versions[vi].released||amount.0==0||request==[0;32]||order==[0;32]||self.orders.iter().any(|o|o.id==order){return Err("AUTHORIZATION: unavailable allowance or order");}
                if add(add(a.used.0,a.reserved.0)?,amount.0)?>a.limit.0 {return Err("INSUFFICIENT_FLY: finite budget");}
                self.orders.push(Order{id:order,customer:a.customer,allowance,version:a.version,request,amount,refunded:Amount(0),matured:Amount(0),receipt:[0;32],reserved:true,consumed:false});
                self.customers[ci].available.0=sub(self.customers[ci].available.0,amount.0)?;self.customers[ci].reserved.0=add(self.customers[ci].reserved.0,amount.0)?;self.allowances[ai].reserved.0=add(self.allowances[ai].reserved.0,amount.0)?;
            },
            Operation::Consume{order,receipt}=>{let oi=self.order(&order)?;let o=self.orders[oi].clone();if !o.reserved||o.consumed||receipt==[0;32]||self.orders.iter().any(|x|x.receipt==receipt){return Err("CONFLICT: delivery receipt");}
                let ci=self.customer(&o.customer)?;let ai=self.allowance(&o.allowance)?;self.customers[ci].reserved.0=sub(self.customers[ci].reserved.0,o.amount.0)?;self.allowances[ai].reserved.0=sub(self.allowances[ai].reserved.0,o.amount.0)?;self.allowances[ai].used.0=add(self.allowances[ai].used.0,o.amount.0)?;
                self.orders[oi].reserved=false;self.orders[oi].consumed=true;self.orders[oi].receipt=receipt;
            },
            Operation::Refund{order,amount}=>{let oi=self.order(&order)?;let o=self.orders[oi].clone();if amount.0==0||o.matured.0>0 {return Err("CONFLICT: refund after maturity");}let ci=self.customer(&o.customer)?;let ai=self.allowance(&o.allowance)?;
                if o.reserved {if amount!=o.amount {return Err("INVALID_INPUT: reserved refund is complete");}self.customers[ci].reserved.0=sub(self.customers[ci].reserved.0,amount.0)?;self.allowances[ai].reserved.0=sub(self.allowances[ai].reserved.0,amount.0)?;self.orders[oi].reserved=false;self.orders[oi].consumed=true;}
                if !self.orders[oi].consumed||add(o.refunded.0,amount.0)?>o.amount.0 {return Err("CONFLICT: refundable upper bound");}
                self.orders[oi].refunded.0=add(o.refunded.0,amount.0)?;self.customers[ci].available.0=add(self.customers[ci].available.0,amount.0)?;
            },
            Operation::Mature{order,amount}=>{let oi=self.order(&order)?;let o=self.orders[oi].clone();if !o.consumed||o.receipt==[0;32]||amount.0==0||add(add(o.refunded.0,o.matured.0)?,amount.0)?>o.amount.0 {return Err("CONFLICT: maturity coverage");}let vi=self.version(&o.version)?;self.orders[oi].matured.0=add(o.matured.0,amount.0)?;self.versions[vi].matured.0=add(self.versions[vi].matured.0,amount.0)?;},
            Operation::Claim{version,entitlement,beneficiary,amount}=>{let vi=self.version(&version)?;let v=&mut self.versions[vi];let total=v.units()?;let si=v.shares.iter().position(|s|s.entitlement==entitlement).ok_or("NOT_FOUND: entitlement")?;let earned=proportional(pools(v.matured.0,v.basis)?.0[0],v.shares[si].units,total)?;
                if v.shares[si].beneficiary!=beneficiary||amount.0==0||add(v.shares[si].claimed.0,amount.0)?>earned {return Err("AUTHORIZATION: beneficiary or claim upper bound");}
                v.shares[si].claimed.0=add(v.shares[si].claimed.0,amount.0)?;v.paid[0].0=add(v.paid[0].0,amount.0)?;self.accounted_balance.0=sub(self.accounted_balance.0,amount.0)?;
            },
            Operation::Pay{version,pool,beneficiary,amount,fulfillment}=>{let vi=self.version(&version)?;let v=&mut self.versions[vi];let i=pool as usize;
                if !(1..4).contains(&i)||v.payees[i-1]!=beneficiary||amount.0==0||fulfillment==[0;32]||add(v.paid[i].0,amount.0)?>pools(v.matured.0,v.basis)?.0[i] {return Err("AUTHORIZATION: contracted payee fulfillment");}v.paid[i].0=add(v.paid[i].0,amount.0)?;self.accounted_balance.0=sub(self.accounted_balance.0,amount.0)?;
            },
            Operation::Beneficiary{version,entitlement,old,new,sequence}=>{let vi=self.version(&version)?;let s=self.versions[vi].shares.iter_mut().find(|s|s.entitlement==entitlement).ok_or("NOT_FOUND: entitlement")?;if s.beneficiary!=old||new==[0;32]||s.beneficiary_sequence.checked_add(1)!=Some(sequence){return Err("AUTHORIZATION: beneficiary sequence");}s.beneficiary=new;s.beneficiary_sequence=sequence;},
            Operation::Withdraw{customer,wallet,amount}=>{let ci=self.customer(&customer)?;if self.customers[ci].wallet!=wallet||amount.0==0 {return Err("AUTHORIZATION: withdrawal wallet");}self.customers[ci].available.0=sub(self.customers[ci].available.0,amount.0)?;self.accounted_balance.0=sub(self.accounted_balance.0,amount.0)?;}
        } Ok(())
    }
}
/// Rational inheritance DAG: each edge has integer units in a frozen common
/// denominator. Paths accumulate into one entitlement; duplicate edges reject.
pub fn inherit(nodes:&[(Key,Vec<(Key,u64)>)], root:Key, scale:u64)->Result<Vec<(Key,u64)>> {
    fn visit(nodes:&[(Key,Vec<(Key,u64)>)],key:Key,units:u64,scale:u64,path:&mut Vec<Key>,out:&mut Vec<(Key,u64)>)->Result<()> {
        if path.contains(&key)||path.len()>32 {return Err("INVALID_INPUT: inheritance cycle");}path.push(key);
        if let Some((_,edges))=nodes.iter().find(|(k,_)|*k==key) {let mut sum=0u64;for (i,(child,c)) in edges.iter().enumerate(){if *c==0||edges[..i].iter().any(|(k,_)|k==child){return Err("INVALID_INPUT: duplicate inheritance edge");}sum=sum.checked_add(*c).ok_or("RESOURCE_LIMIT: inheritance")?;}if sum!=scale {return Err("INVALID_INPUT: inheritance coefficient sum");}
            for (child,c) in edges { let product=(units as u128)*(*c as u128);if product%(scale as u128)!=0 {return Err("INVALID_INPUT: choose an exact inheritance denominator");}let u=u64::try_from(product/(scale as u128)).map_err(|_|"RESOURCE_LIMIT: inheritance units")?;visit(nodes,*child,u,scale,path,out)?; }
        } else if let Some((_,u))=out.iter_mut().find(|(k,_)|*k==key) {*u=u.checked_add(units).ok_or("RESOURCE_LIMIT: inherited sum")?;} else {out.push((key,units));}
        path.pop();Ok(())
    }
    if scale==0||nodes.len()>MAX_OBJECTS||nodes.iter().enumerate().any(|(i,(k,_))|nodes[..i].iter().any(|(x,_)|x==k)){return Err("INVALID_INPUT: inheritance inventory");}
    let mut out=vec![];visit(nodes,root,scale,scale,&mut vec![],&mut out)?;out.sort_by_key(|(k,_)|*k);Ok(out)
}
