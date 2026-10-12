//! V2 development target protocol. Separate domains; no changes to V1 identities.
pub mod difficulty;
pub mod family;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
pub type Result<T> = std::result::Result<T, String>;

pub fn hex(bytes: &[u8]) -> String { bytes.iter().map(|b|format!("{b:02x}")).collect() }
pub fn unhex(s: &str) -> Result<Vec<u8>> {
    if s.len()%2!=0 || !s.bytes().all(|c|c.is_ascii_digit() || (b'a'..=b'f').contains(&c)){return Err("canonical lowercase hex required".into());}
    (0..s.len()).step_by(2).map(|i|u8::from_str_radix(&s[i..i+2],16).map_err(|_|"hex".into())).collect()
}
pub fn hash(bytes: &[u8])->String { hex(&Sha256::digest(bytes)) }
pub fn root(s: &str)->Result<()> { if s.len()!=64{return Err("root width".into());}unhex(s).map(|_|()) }
pub fn canonical(v: &Value)->Result<Vec<u8>> {
    fn check(v: &Value)->Result<()> { match v {
        Value::Number(n) => {let x=n.as_i64().ok_or("integer required")?;if x.unsigned_abs()>9_007_199_254_740_991{return Err("unsafe JSON integer".into());}},
        Value::Array(a)=>for x in a {check(x)?},
        Value::Object(o)=>for (k,x) in o {if !k.is_ascii(){return Err("ASCII object keys required".into());}check(x)?}, _=>{}
    };Ok(()) }
    check(v)?;serde_json::to_vec(v).map_err(|e|e.to_string())
}
pub fn id(domain: &str,v:&Value)->Result<String> {
    let mut bytes=format!("FlyPoW/{domain}/v2\0").into_bytes();bytes.extend(canonical(v)?);Ok(hash(&bytes))
}
pub fn value<T: Serialize>(x:&T)->Value {serde_json::to_value(x).expect("protocol serializes")}
pub fn body(s:&str)->Result<u64>{let n=s.parse::<u64>().map_err(|_|"bodyId u64")?;if n==0||n.to_string()!=s{return Err("canonical nonzero bodyId".into());}Ok(n)}
pub fn parameters()->Value{json!({"parameterVersion":"lif-point-v0-dev","timeStepUs":1000,"leakDivisor":8,"threshold":100,"reset":0,"membraneLimit":1000000,"refractorySteps":2,"synapticUnit":1,"synapticDelaySteps":1,"backgroundProbabilityU16":256,"backgroundCurrent":10,"observeStart":0,"steps":256})}

#[derive(Clone,Debug,Serialize,Deserialize,PartialEq,Eq)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub struct Member {pub body_id:String,pub model_index:u32}
#[derive(Clone,Debug,Serialize,Deserialize,PartialEq,Eq)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub struct CandidateInput {pub stimulated_body_id:String,pub start_step:u32,pub end_step:u32,pub current:u32}
#[derive(Clone,Debug,Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub struct InputDomain {pub starts:Vec<u32>,pub durations:Vec<u32>,pub currents:Vec<u32>}
#[derive(Clone,Debug,Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub struct Window {pub start_offset:u32,pub end_offset:u32,pub min_target_net:i64,pub min_positive_cells:u32,pub max_off_target:u64,pub selectivity_numerator:u32,pub selectivity_denominator:u32}
#[derive(Clone,Debug,Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub struct GoalSpec {
    pub schema:String,pub family:String,pub description:String,pub dataset:String,
    pub source_root:String,pub registry_root:String,pub graph_root:String,pub model_root:String,pub model_data_root:String,pub parameter_profile_hash:String,
    pub parameter_version:String,pub neuron_count:u32,pub steps:u32,pub time_step_us:u32,
    pub stimulus_set:Vec<Member>,pub response_set:Vec<Member>,pub off_target_set:Vec<Member>,
    pub stimulus_set_root:String,pub response_set_root:String,pub off_target_set_root:String,pub off_target_coverage:String,
    pub input_domain:InputDomain,pub input_domain_hash:String,pub generator_version:String,pub evaluator_version:String,
    pub windows:Vec<Window>,pub max_stimulus_cost:u64,pub max_trial_bytes:u64,pub max_candidate_bytes:u64,
    pub calibration_hash:String,
}
impl GoalSpec {
    pub fn goal_id(&self)->Result<String>{id("goal-id",&value(self))}
    pub fn validate(&self)->Result<()> {
        if self.schema!="flypow-goal-v2"||self.family!="evoked-selective-response-v1"||self.parameter_version!="lif-point-v0-dev"||self.evaluator_version!="full-events-selective-v1"||self.generator_version!="rect-domain-v1"||self.steps!=256||self.time_step_us!=1000||self.neuron_count==0||self.neuron_count>1_000_000{return Err("unsupported scientific profile".into());}
        for r in [&self.source_root,&self.registry_root,&self.graph_root,&self.model_root,&self.model_data_root,&self.parameter_profile_hash,&self.calibration_hash]{root(r)?;}
        if self.parameter_profile_hash!=id("parameter-profile",&parameters())?{return Err("unknown frozen parameters".into());}
        let mut all=BTreeSet::new();let mut bodies=BTreeSet::new();
        for (name,set,claimed) in [("S",&self.stimulus_set,&self.stimulus_set_root),("G",&self.response_set,&self.response_set_root),("O",&self.off_target_set,&self.off_target_set_root)] {
            if set.is_empty()||set.len()>self.neuron_count as usize||set.windows(2).any(|w|w[0].model_index>=w[1].model_index){return Err(format!("{name} sorted nonempty set required"));}
            for m in set {body(&m.body_id)?;if m.model_index>=self.neuron_count||!all.insert(m.model_index)||!bodies.insert(m.body_id.clone()){return Err("S/G/O must be disjoint".into());}}
            if id("member-set",&value(set))?!=*claimed{return Err("member root mismatch".into());}
        }
        if self.off_target_coverage.is_empty()||id("input-domain",&value(&self.input_domain))?!=self.input_domain_hash{return Err("input domain identity".into());}
        let d=&self.input_domain;
        for a in [&d.starts,&d.durations,&d.currents]{if a.is_empty()||a.len()>256||a.windows(2).any(|w|w[0]>=w[1]){return Err("sorted quantized domain".into());}}
        if d.durations[0]==0||d.currents[0]==0||*d.currents.last().unwrap()>1_000_000||self.windows.len()!=2||self.max_stimulus_cost==0||self.max_stimulus_cost>9_007_199_254_740_991||self.max_trial_bytes<480||self.max_trial_bytes>128*1024*1024||self.max_candidate_bytes>512*1024*1024{return Err("scientific resource/domain bound".into());}
        let mut prior=0;for w in &self.windows {
            if w.start_offset<prior||w.end_offset<=w.start_offset||w.end_offset>self.steps||w.min_target_net<=0||w.min_positive_cells==0||w.min_positive_cells as usize>self.response_set.len()||w.selectivity_numerator==0||w.selectivity_denominator==0||w.max_off_target>9_007_199_254_740_991{return Err("invalid frozen evaluation windows".into());}prior=w.end_offset;
        }
        let bound=[self.stimulus_set.len(),d.starts.len(),d.durations.len(),d.currents.len()].into_iter().try_fold(1usize,|a,b|a.checked_mul(b)).ok_or("domain product overflow")?;if bound>1_000_000{return Err("unbounded domain product".into());}
        if self.inputs().is_empty(){return Err("empty or unbounded domain".into());}Ok(())
    }
    pub fn inputs(&self)->Vec<CandidateInput>{let mut out=Vec::new();for s in &self.stimulus_set {for &start in &self.input_domain.starts {for &duration in &self.input_domain.durations {for &current in &self.input_domain.currents {
        if let Some(end)=start.checked_add(duration) {if end.checked_add(self.windows.last().map_or(0,|w|w.end_offset)).is_some_and(|x|x<=self.steps)&&(current as u64)*(duration as u64)<=self.max_stimulus_cost {out.push(CandidateInput{stimulated_body_id:s.body_id.clone(),start_step:start,end_step:end,current});}}
    }}}}out}
    pub fn validate_input(&self,x:&CandidateInput)->Result<u32>{body(&x.stimulated_body_id)?;let m=self.stimulus_set.iter().find(|m|m.body_id==x.stimulated_body_id).ok_or("stimulus outside S")?;
        let duration=x.end_step.checked_sub(x.start_step).ok_or("stimulus boundaries")?;
        if duration==0||!self.input_domain.starts.contains(&x.start_step)||!self.input_domain.durations.contains(&duration)||!self.input_domain.currents.contains(&x.current)||x.end_step.checked_add(self.windows[1].end_offset).is_none_or(|v|v>self.steps)||(x.current as u64)*(duration as u64)>self.max_stimulus_cost{return Err("input outside frozen quantized domain".into());}Ok(m.model_index)
    }
}

#[derive(Clone,Debug,Serialize,Deserialize,PartialEq,Eq)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub struct WindowMetrics {pub target_net:i64,pub positive_cells:u32,pub off_target_abs:u64,pub passed:bool}
#[derive(Clone,Debug,Serialize,Deserialize,PartialEq,Eq)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub struct TrialMetrics {pub windows:Vec<WindowMetrics>,pub stimulus_cost:u64,pub baseline_spikes:u64,pub passed:bool}

/// Inspect ALL sorted full archive events, independent of the display trace.
pub fn evaluate(goal:&GoalSpec,input:&CandidateInput,bytes:&[u8])->Result<TrialMetrics>{
    goal.validate()?;let target=goal.validate_input(input)?;
    let u32_at=|at|u32::from_le_bytes(bytes[at..at+4].try_into().unwrap());
    if bytes.len()<480||bytes.len() as u64>goal.max_trial_bytes||&bytes[..8]!=b"FBRP1\0\0\0"||u32_at(8)!=goal.neuron_count||u32_at(12)!=target||u32_at(16)!=goal.steps{return Err("complete FBRP identity/bound required".into());}
    let a=u32_at(472) as usize;let b=u32_at(476) as usize;
    if 480usize.checked_add((a+b).checked_mul(8).ok_or("event length overflow")?)!=Some(bytes.len()){return Err("incomplete FBRP events".into());}
    if u64::from_le_bytes(bytes[24..32].try_into().unwrap())!=a as u64||u64::from_le_bytes(bytes[32..40].try_into().unwrap())!=b as u64{return Err("event summary disagreement".into());}
    let mut sets=BTreeMap::new();for m in &goal.response_set{sets.insert(m.model_index,true);}for m in &goal.off_target_set{sets.insert(m.model_index,false);}
    let mut counts=vec![BTreeMap::<u32,i64>::new();goal.windows.len()];
    for (start,len,sign) in [(480,a,-1i64),(480+a*8,b,1)]{
        let mut prior=None;for at in (start..start+len*8).step_by(8){let step=u32_at(at);let index=u32_at(at+4);
            if step>=goal.steps||index>=goal.neuron_count||prior.is_some_and(|p|p>=(step,index)){return Err("event order/duplicate/range".into());}prior=Some((step,index));
            if sets.contains_key(&index){for (k,w) in goal.windows.iter().enumerate(){if step>=input.end_step+w.start_offset&&step<input.end_step+w.end_offset {*counts[k].entry(index).or_default()+=sign;}}}
        }
    }
    let mut windows=Vec::new();for (w,c) in goal.windows.iter().zip(counts){let mut net=0i64;let mut positive=0u32;let mut off=0u64;
        for (i,delta) in c {if sets[&i]{net=net.checked_add(delta).ok_or("target sum overflow")?;positive+=u32::from(delta>0);}else{off=off.checked_add(delta.unsigned_abs()).ok_or("off-target overflow")?;}}
        // Zero off-target denominator: positive target response passes selectivity.
        let selective=net>0&&(net as u128)*(w.selectivity_denominator as u128)>=(off as u128)*(w.selectivity_numerator as u128);
        windows.push(WindowMetrics{target_net:net,positive_cells:positive,off_target_abs:off,passed:net>=w.min_target_net&&positive>=w.min_positive_cells&&off<=w.max_off_target&&selective});
    }
    let cost=(input.current as u64)*((input.end_step-input.start_step) as u64);let passed=cost<=goal.max_stimulus_cost&&windows.iter().all(|w|w.passed);
    Ok(TrialMetrics{windows,stimulus_cost:cost,baseline_spikes:a as u64,passed})
}

pub fn derive_seed(pre_hash:&str,entropy:&str,j:u32)->Result<String>{root(pre_hash)?;root(entropy)?;let mut b=b"FlyPoW/background-seed/v2\0".to_vec();b.extend(unhex(pre_hash)?);b.extend(unhex(entropy)?);b.extend(j.to_le_bytes());let d=Sha256::digest(b);Ok(format!("{:016x}",u64::from_le_bytes(d[..8].try_into().unwrap())))}
pub fn candidate_id(round:&str,input:&CandidateInput)->Result<String>{root(round)?;id("candidate-id",&json!({"roundId":round,"input":input}))}
pub fn trial_id(round:&str,goal:&GoalSpec,input:&CandidateInput,j:u32,seed:&str)->Result<String>{if seed.len()!=16{ return Err("u64 seed width".into());}unhex(seed)?;id("trial-id",&json!({"candidateId":candidate_id(round,input)?,"goalId":goal.goal_id()?,"repeatIndex":j,"seedHex":seed,"input":input,"parameterProfileHash":goal.parameter_profile_hash}))}
#[derive(Clone,Debug,Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub struct TrialArtifact {pub trial_id:String,pub repeat_index:u32,pub seed_hex:String,pub result_root:String,pub bytes:u64,pub metrics:TrialMetrics}
#[derive(Clone,Debug,Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub struct CandidateManifest {pub schema:String,pub round_id:String,pub goal_id:String,pub candidate_id:String,pub input:CandidateInput,pub trials:Vec<TrialArtifact>,pub goal_result_root:String}
pub fn result_root(trials:&[TrialArtifact])->Result<String>{id("goal-result-root",&value(&trials))}
pub fn validate_manifest(m:&CandidateManifest,round:&Value)->Result<()> {
    validate_round(round)?;let goal:GoalSpec=serde_json::from_value(round["goal"].clone()).map_err(|e|e.to_string())?;
    if m.schema!="flypow-candidate-manifest-v2"||m.round_id!=round["roundId"]||m.goal_id!=goal.goal_id()?||m.candidate_id!=candidate_id(&m.round_id,&m.input)?||m.goal_result_root!=result_root(&m.trials)?||m.trials.len()!=round["pre"]["requiredBackgrounds"].as_u64().ok_or("R")? as usize{return Err("candidate evidence identity/count".into());}
    goal.validate_input(&m.input)?;let mut total=0u64;
    for (j,t) in m.trials.iter().enumerate(){root(&t.result_root)?;if t.repeat_index!=j as u32||t.seed_hex!=round["seeds"][j]||t.trial_id!=trial_id(&m.round_id,&goal,&m.input,j as u32,&t.seed_hex)?||t.bytes<480||t.bytes>goal.max_trial_bytes||!t.metrics.passed{return Err("trial order/seed/identity/qualification".into());}total=total.checked_add(t.bytes).ok_or("candidate bytes")?;}
    if total>goal.max_candidate_bytes{return Err("candidate archive budget".into());}Ok(())
}
pub fn validate_round(r:&Value)->Result<()> {
    let goal:GoalSpec=serde_json::from_value(r["goal"].clone()).map_err(|e|e.to_string())?;goal.validate()?;
    let p=&r["pre"];if p["protocolVersion"]!=2||p["goalId"]!=goal.goal_id()?||p["goalDefinitionHash"]!=goal.goal_id()?||p["calibrationHash"]!=goal.calibration_hash||p["inputDomainHash"]!=goal.input_domain_hash||p["parameterProfileHash"]!=goal.parameter_profile_hash||p["graphRoot"]!=goal.graph_root||p["modelRoot"]!=goal.model_root||p["evaluatorVersion"]!=goal.evaluator_version{return Err("frozen round science".into());}
    family::validate_extension(p,&goal)?;
    if let Some(policy)=p.get("difficultyPolicy"){if p["difficultyPolicyHash"]!=id("difficulty-policy",policy)?{return Err("frozen difficulty policy hash".into());}}
    let ph=id("pre-round",p)?;if r["preRoundSpecHash"]!=ph||r["entropySource"]!="authority-csprng-dev-v1"||r["seedDerivationVersion"]!="sha256-pre-entropy-u32le-u64le-v1"{return Err("round derivation".into());}
    let entropy=r["roundEntropy"].as_str().ok_or("entropy")?;let seeds=r["seeds"].as_array().ok_or("seeds")?;
    let required=p["requiredBackgrounds"].as_u64().ok_or("R")?;
    if ![2,4,8,16].contains(&required)||seeds.len()<required as usize||seeds.len()>16{return Err("background count".into());}
    for (j,s) in seeds.iter().enumerate(){if s!=&Value::String(derive_seed(&ph,entropy,j as u32)?){return Err("shared seed prefix mismatch".into());}}
    let rid=id("round-id",&json!({"preRoundSpecHash":ph,"roundEntropy":entropy,"entropySource":r["entropySource"],"seedDerivationVersion":r["seedDerivationVersion"],"seeds":seeds}))?;
    if r["roundId"]!=rid||r["signedRevision"]!=1{return Err("round identity/revision".into());}
    let opened=p["openedAt"].as_u64().ok_or("openedAt")?;let claim=p["claimDeadline"].as_u64().ok_or("claimDeadline")?;let reveal=p["revealDeadline"].as_u64().ok_or("revealDeadline")?;let verify=p["verificationDeadline"].as_u64().ok_or("verificationDeadline")?;
    if opened>=claim||claim>=reveal||reveal>=verify||verify-opened>86400{return Err("bounded round deadlines".into());}Ok(())
}
pub fn unsigned_round(r:&Value)->Value{let mut x=r.clone();x.as_object_mut().unwrap().remove("signature");x}
pub fn commitment(round:&Value,miner:&str,m:&CandidateManifest,salt:&str)->Result<String>{validate_manifest(m,round)?;root(miner)?;root(salt)?;id("claim-commitment",&json!({"networkId":round["pre"]["networkId"],"authorityId":round["pre"]["authorityId"],"roundId":m.round_id,"goalId":m.goal_id,"difficultyPolicyHash":round["pre"]["difficultyPolicyHash"],"requiredBackgrounds":round["pre"]["requiredBackgrounds"],"minerId":miner,"candidateId":m.candidate_id,"goalResultRoot":m.goal_result_root,"manifestHash":id("candidate-manifest",&value(m))?,"salt":salt}))}
pub fn claim_id(round:&str,miner:&str,commitment:&str)->Result<String>{root(round)?;root(miner)?;root(commitment)?;id("claim-id",&json!({"roundId":round,"minerId":miner,"commitment":commitment}))}
