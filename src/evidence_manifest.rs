//! An additive public outer envelope. Existing scientific evidence roots and
//! AcceptanceId remain unchanged; there is no circular hash dependency.
use flypow_target_protocol::{id,root,Result};
use serde_json::Value;
pub fn validate(v:&Value)->Result<()> {
    let obj=v.as_object().ok_or("INVALID_INPUT: EvidenceManifest object")?;
    let allowed=["schema","kind","genesisHash","programId","policyHash","economicTaskId","unitId","contributionId","acceptanceId","goalId","roundId","claimId","readoutId","modelRoot","graphRoot","parameterProfileHash","evaluatorVersion","judgement","authorizationId","publicEvidence","privateCommitments"];
    if obj.keys().any(|k|!allowed.contains(&k.as_str()))||v["schema"]!="flybrain-evidence-manifest-v1"{return Err("INVALID_INPUT: EvidenceManifest schema/whitelist".into());}
    let kind=v["kind"].as_str().ok_or("evidence kind")?;
    if !["discovery","coverage","verification","readout","community"].contains(&kind){return Err("evidence kind".into());}
    for key in ["genesisHash","programId","evaluatorVersion"]{if v[key].as_str().is_none_or(|s|s.is_empty()||s.len()>128){return Err(format!("evidence required {key}"));}}
    for key in ["genesisHash","programId"]{if crate::explorer_types::base58_width(v[key].as_str().unwrap())!=Some(32){return Err("chain identity base58 width".into());}}
    for key in ["policyHash","economicTaskId","unitId","contributionId","authorizationId"]{root(v[key].as_str().ok_or("evidence identity")?)?;}
    if kind=="discovery"&&v["unitId"]!="0".repeat(64){return Err("discovery singleton unit".into());}
    let scientific=["discovery","coverage","readout"].contains(&kind);
    if scientific {for key in ["acceptanceId","goalId","readoutId","modelRoot","graphRoot","parameterProfileHash"]{root(v[key].as_str().ok_or("scientific evidence required")?)?;}}
    if kind=="discovery"{for key in ["roundId","claimId"]{root(v[key].as_str().ok_or("winning protocol source required")?)?;}}
    if v["judgement"]!="accepted" && !(kind=="verification"&&v["judgement"]=="correct-rejection"){return Err("evidence judgement".into());}
    let commitments=v["privateCommitments"].as_array().ok_or("private commitment array")?;if commitments.len()>16{return Err("commitment bound".into());}
    for c in commitments{if c["schema"]!="randomized-sha256-commitment-v1"||c.as_object().is_none_or(|o|o.len()!=2){return Err("private commitments must be randomized; never publish plaintext or salt".into());}root(c["root"].as_str().ok_or("commitment root")?)?;}
    let public=v["publicEvidence"].as_array().ok_or("public evidence array")?;if public.len()>32{return Err("evidence bound".into());}for e in public{if e.as_object().is_none_or(|o|o.len()!=3)||!e["kind"].is_string()||!e["id"].is_string(){return Err("public reference whitelist".into());}root(e["sha256"].as_str().ok_or("public evidence checksum")?)?;root(e["id"].as_str().ok_or("public reference identity")?)?;if !["scientific-package","goal-result","authorization-statement","external-evaluation"].contains(&e["kind"].as_str().unwrap_or("")){return Err("public reference kind".into());}}
    Ok(())
}
pub fn digest(v:&Value)->Result<String>{validate(v)?;id("economic-evidence-manifest-v1",v)}
