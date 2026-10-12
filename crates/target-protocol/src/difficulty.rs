//! Fixed point, persisted feedback. Only accepted discovery times are successes.
use crate::Result;
use serde::{Deserialize,Serialize};
const Q:u64=1_000_000;
#[derive(Clone,Debug,Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub struct Level {pub profile_id:String,pub required_backgrounds:u32,pub difficulty_micros:u64,pub calibration_hash:String,pub enabled:bool}
#[derive(Clone,Debug,Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub struct Controller {
    pub schema:String,pub family_key:String,pub desired_micros:u64,pub applied_index:usize,
    pub smoothed_ms:Option<u64>,pub valid_samples:u32,pub dwell:u32,pub healthy_timeouts:u32,
    pub tau_ms:u64,pub last_observation_at:u64,pub reason:String,
}
fn isqrt(n:u128)->u128{if n<2{return n;}let mut x=n;let mut y=(x+1)/2;while y<x{x=y;y=(x+n/x)/2;}x}
impl Controller {
    pub fn new(family_key:String,levels:&[Level],tau_ms:u64)->Result<Self>{
        Self::validate_levels(levels)?;if tau_ms==0||tau_ms>86_400_000{return Err("target cadence bounds".into());}
        Ok(Self{schema:"flypow-difficulty-controller-v2".into(),family_key,desired_micros:levels[0].difficulty_micros,applied_index:0,smoothed_ms:None,valid_samples:0,dwell:0,healthy_timeouts:0,tau_ms,last_observation_at:0,reason:"sample-insufficient".into()})
    }
    pub fn validate_levels(levels:&[Level])->Result<()>{if levels.is_empty()||levels.len()>4||levels.iter().any(|l|!l.enabled||![2,4,8,16].contains(&l.required_backgrounds)||l.difficulty_micros==0||l.difficulty_micros>1000*Q||crate::root(&l.calibration_hash).is_err())||levels.windows(2).any(|w|w[0].difficulty_micros>=w[1].difficulty_micros||w[0].required_backgrounds>=w[1].required_backgrounds){return Err("enabled calibrated ordered levels required".into());}Ok(())}
    pub fn observe(&mut self,levels:&[Level],family:&str,at:u64,discovery_ms:Option<u64>,healthy:bool)->Result<()> {
        Self::validate_levels(levels)?;if self.family_key!=family{*self=Self::new(family.to_string(),levels,self.tau_ms)?;self.reason="new-family-cold-start".into();}
        if at<self.last_observation_at{return Err("authority clock rollback".into());}self.last_observation_at=at;
        if !healthy{self.reason="infrastructure-excluded".into();return Ok(());}
        self.dwell=self.dwell.saturating_add(1);
        let Some(ms)=discovery_ms else {self.healthy_timeouts=self.healthy_timeouts.saturating_add(1);self.reason="healthy-timeout-censored".into();
            if self.healthy_timeouts>=3&&self.dwell>=4 {self.applied_index=self.applied_index.saturating_sub(1);self.desired_micros=levels[self.applied_index].difficulty_micros;self.healthy_timeouts=0;self.dwell=0;self.reason="bounded-healthy-timeout-fallback".into();}return Ok(());};
        if ms>86_400_000{return Err("discovery window bounds".into());}let ms=ms.max(1);self.healthy_timeouts=0;self.valid_samples=self.valid_samples.saturating_add(1);
        self.smoothed_ms=Some(self.smoothed_ms.map_or(ms,|old|((old as u128*7+ms as u128)/8) as u64));
        if self.valid_samples<16{self.reason="sample-insufficient".into();return Ok(());}
        let ratio=isqrt(self.tau_ms as u128*Q as u128*Q as u128/self.smoothed_ms.unwrap() as u128).clamp(800_000,1_250_000) as u64;
        self.desired_micros=((self.desired_micros as u128*ratio as u128)/Q as u128).clamp(levels[0].difficulty_micros as u128,levels.last().unwrap().difficulty_micros as u128) as u64;
        self.reason="smoothed-bounded-feedback".into();
        if self.dwell>=4 {
            if self.applied_index+1<levels.len() && self.desired_micros as u128*20>=(levels[self.applied_index].difficulty_micros as u128+levels[self.applied_index+1].difficulty_micros as u128)*11 {self.applied_index+=1;self.dwell=0;self.reason="one-calibrated-level-up".into();}
            else if self.applied_index>0&&self.desired_micros as u128*20<=(levels[self.applied_index-1].difficulty_micros as u128+levels[self.applied_index].difficulty_micros as u128)*9 {self.applied_index-=1;self.dwell=0;self.reason="one-calibrated-level-down".into();}
        }
        if self.applied_index+1==levels.len(){self.reason="calibrated-ceiling".into();}Ok(())
    }
}
#[cfg(test)]mod tests{
    use super::*;
    fn levels()->Vec<Level>{[2,4,8,16].iter().enumerate().map(|(i,r)|Level{profile_id:format!("r{r}"),required_backgrounds:*r,difficulty_micros:Q*(1<<i),calibration_hash:"a".repeat(64),enabled:true}).collect()}
    #[test]fn feedback_freezes_current_and_moves_persistent_desired(){let l=levels();let mut c=Controller::new("f".into(),&l,300000).unwrap();for at in 1..50 {c.observe(&l,"f",at,Some(30000),true).unwrap();}assert!(c.applied_index>=2);let high=c.applied_index;for at in 50..110{c.observe(&l,"f",at,Some(3_000_000),true).unwrap();}assert!(c.applied_index<high);assert!(c.desired_micros>=Q);}
    #[test]fn infrastructure_and_family_and_timeout(){let l=levels();let mut c=Controller::new("f".into(),&l,300000).unwrap();for at in 1..10{c.observe(&l,"f",at,None,false).unwrap();}assert_eq!(c.valid_samples,0);assert_eq!(c.healthy_timeouts,0);c.applied_index=2;c.desired_micros=4*Q;for at in 10..14{c.observe(&l,"f",at,None,true).unwrap();}assert_eq!(c.applied_index,1);c.observe(&l,"g",20,Some(0),true).unwrap();assert_eq!(c.applied_index,0);assert_eq!(c.valid_samples,1);assert!(c.observe(&l,"g",19,Some(1),true).is_err());}
}
