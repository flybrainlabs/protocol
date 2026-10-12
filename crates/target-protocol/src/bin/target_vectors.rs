//! Cross implementation fixture reader; no scientific simulation or authority activation.
use flypow_target_protocol as p;
use serde_json::{Value,json};
use std::io::{self,Read};
fn main(){let mut text=String::new();io::stdin().read_to_string(&mut text).unwrap();let x:Value=serde_json::from_str(&text).unwrap();let result=(||->p::Result<Value>{
    if x["op"]=="canonical" {return Ok(json!({"canonicalHex":p::hex(&p::canonical(&x["value"])?) ,"identity":p::id("vector",&x["value"])?}));}
    if x["op"]=="family" {let f:p::family::Family=serde_json::from_value(x["family"].clone()).map_err(|e|e.to_string())?;f.validate()?;let mut evidence=Vec::new();for row in x["evidence"].as_array().ok_or("evidence")?{evidence.push((serde_json::from_value(row["goal"].clone()).map_err(|e|e.to_string())?,row["calibration"].clone()));}f.validate_evidence(&evidence)?;return Ok(json!({"familyId":f.identity()?}));}
    let g:p::GoalSpec=serde_json::from_value(x["goal"].clone()).map_err(|e|e.to_string())?;g.validate()?;let input:p::CandidateInput=serde_json::from_value(x["input"].clone()).map_err(|e|e.to_string())?;g.validate_input(&input)?;
    if x["op"]=="evaluate"{return Ok(p::value(&p::evaluate(&g,&input,&p::unhex(x["archiveHex"].as_str().ok_or("archive")?)?)?));}
    let r=&x["round"];p::validate_round(r)?;let rid=r["roundId"].as_str().ok_or("round")?;let cid=p::candidate_id(rid,&input)?;
    let tids:Vec<String>=r["seeds"].as_array().ok_or("seeds")?.iter().enumerate().map(|(j,s)|p::trial_id(rid,&g,&input,j as u32,s.as_str().unwrap())).collect::<p::Result<_>>()?;
    Ok(json!({"goalId":g.goal_id()?,"candidateId":cid,"trialIds":tids,"roundId":rid,"inputCount":g.inputs().len()}))
})();println!("{}",match result{Ok(v)=>json!({"ok":v}),Err(e)=>json!({"error":e})});}
