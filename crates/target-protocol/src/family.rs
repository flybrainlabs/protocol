//! Versioned comparable-family descriptions. Per-goal calibration never loses
//! its identity. Historical rounds without this optional extension still parse.
use crate::{Result,GoalSpec,id,root,value,difficulty::Level};
use serde::{Serialize,Deserialize};
use serde_json::Value;
#[derive(Clone,Debug,Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub struct Member {pub goal_id:String,pub calibration_hash:String,pub normalization_numerator:u64,pub normalization_denominator:u64}
#[derive(Clone,Debug,Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub struct FamilyLevel {pub required_backgrounds:u32,pub difficulty_micros:u64}
#[derive(Clone,Debug,Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub struct Family {
 pub schema:String,pub revision:u32,pub graph_root:String,pub model_root:String,pub parameter_profile_hash:String,pub evaluator_version:String,
 pub reference_goal_id:String,pub preregistration_hash:String,pub normalization_version:String,pub members:Vec<Member>,pub levels:Vec<FamilyLevel>,pub limits:Vec<String>,
}
impl Family {
 pub fn identity(&self)->Result<String>{id("comparable-difficulty-family",&value(self))}
 pub fn validate(&self)->Result<()> {
  if self.schema!="flypow-comparable-difficulty-family-v1"||self.revision==0||self.normalization_version!="reference-work-r2-ratio-v1"||self.evaluator_version!="full-events-selective-v1"||self.members.len()<2||self.members.len()>128||self.levels.is_empty()||self.levels.len()>4{return Err("comparable family schema/limits".into());}
  for r in [&self.graph_root,&self.model_root,&self.parameter_profile_hash,&self.reference_goal_id,&self.preregistration_hash]{root(r)?;}
  let mut goals=std::collections::BTreeSet::new();for m in &self.members{root(&m.goal_id)?;root(&m.calibration_hash)?;if !goals.insert(&m.goal_id)||m.normalization_numerator==0||m.normalization_denominator==0||m.normalization_numerator>86_400_000||m.normalization_denominator>86_400_000{return Err("family member normalization bounds".into());}}
  if !goals.contains(&self.reference_goal_id){return Err("family reference member".into());}if self.levels[0].required_backgrounds!=2||self.levels[0].difficulty_micros!=1_000_000{return Err("family reference R2 level".into());}crate::difficulty::Controller::validate_levels(&self.controller_levels()?)
 }
 pub fn controller_levels(&self)->Result<Vec<Level>> {let h=self.identity()?;Ok(self.levels.iter().map(|l|Level{profile_id:format!("comparable-r{}-v{}",l.required_backgrounds,self.revision),required_backgrounds:l.required_backgrounds,difficulty_micros:l.difficulty_micros,calibration_hash:h.clone(),enabled:true}).collect())}
 pub fn member(&self,g:&GoalSpec)->Result<&Member>{
  if self.graph_root!=g.graph_root||self.model_root!=g.model_root||self.parameter_profile_hash!=g.parameter_profile_hash||self.evaluator_version!=g.evaluator_version{return Err("family model/evaluator identity".into());}
  let gid=g.goal_id()?;self.members.iter().find(|m|m.goal_id==gid&&m.calibration_hash==g.calibration_hash).ok_or("family goal/calibration membership".into())
 }
 pub fn validate_evidence(&self,evidence:&[(GoalSpec,Value)])->Result<()> {
  self.validate()?;let reference=evidence.iter().find(|(g,_)|g.goal_id().ok().as_deref()==Some(&self.reference_goal_id)).ok_or("family reference evidence missing")?;
  let refwork=reference.1["levels"][0]["estimatedWorkMilliseconds"].as_u64().ok_or("family reference work")?;
  let mut intervals=Vec::new();
  for m in &self.members {let (g,c)=evidence.iter().find(|(g,_)|g.goal_id().ok().as_deref()==Some(&m.goal_id)).ok_or("family member evidence missing")?;self.member(g)?;
   if c["activationAllowed"]!=true||c["preregistrationHash"]!=self.preregistration_hash||crate::hash(&crate::canonical(c)?)!=m.calibration_hash||g.input_domain_hash!=reference.0.input_domain_hash||g.stimulus_set_root!=reference.0.stimulus_set_root{return Err("family calibration/preregistration/kernel input mismatch".into());}
   let work=c["levels"][0]["estimatedWorkMilliseconds"].as_u64().ok_or("family measured work")?;if m.normalization_numerator!=refwork||m.normalization_denominator!=work{return Err("family normalization must use measured R2 work".into());}
   let interval=&c["levels"][0]["wilson95PartsPerMillion"];intervals.push((interval[0].as_u64().ok_or("family interval")?,interval[1].as_u64().ok_or("family interval")?));
   for l in &self.levels {let measured=c["levels"].as_array().ok_or("calibration levels")?.iter().find(|x|x["requiredBackgrounds"]==l.required_backgrounds).ok_or("family level lacks member calibration")?;
    if measured["enabled"]!=true||measured["challengeEffective"]!=true||measured["heldOutSuccesses"].as_u64().unwrap_or(0)==0||measured["sampleCount"].as_u64().unwrap_or(0)<16{return Err("family includes uncalibrated member level".into());}
    let d=measured["difficultyMicros"].as_u64().ok_or("family level measurement")?;if d as u128*4>l.difficulty_micros as u128*5||l.difficulty_micros as u128*4>d as u128*5{return Err("family normalized level cost differs by over 25 percent".into());}
   }
  }
  if intervals.iter().map(|x|x.0).max()>intervals.iter().map(|x|x.1).min(){return Err("family pass-rate confidence intervals do not overlap".into());}Ok(())
 }
}
pub fn validate_extension(pre:&Value,goal:&GoalSpec)->Result<()> {
 let Some(extension)=pre["difficultyPolicy"].get("comparableFamily") else{return Ok(());};
 let family:Family=serde_json::from_value(extension["descriptor"].clone()).map_err(|e|e.to_string())?;family.validate()?;let m=family.member(goal)?;
 if extension.as_object().is_none_or(|o|o.len()!=4)||extension["familyId"]!=family.identity()?||extension["normalizationNumerator"]!=m.normalization_numerator||extension["normalizationDenominator"]!=m.normalization_denominator||!family.levels.iter().any(|l|pre["requiredBackgrounds"]==l.required_backgrounds&&pre["difficultyMicros"]==l.difficulty_micros){return Err("frozen comparable family binding".into());}Ok(())
}
