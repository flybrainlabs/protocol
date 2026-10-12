//! Full-model V2 simulation / replay; does not interpret GLOBAL_TASK_INDEX.
use flypow_target_protocol::{GoalSpec,CandidateInput,evaluate,hash};
use flypow_sim_core::{Graph,ModelMeta,Parameters,Task,simulate_pair_observed,encode_response};
use std::{cell::Cell,env,fs,io::Write,time::Instant};
fn execute(phase:&Cell<&str>)->Result<serde_json::Value,Box<dyn std::error::Error>>{
    let a:Vec<_>=env::args().collect();if a.len()!=7&&a.len()!=8{return Err("usage: target_trial GRAPH MODEL GOAL.json INPUT.json SEED_HEX RESPONSE.bin [--verify]".into());}
    let verify=a.len()==8&&a[7]=="--verify";if a.len()==8&&!verify{return Err("unknown option".into());}
    let started=Instant::now();let goal:GoalSpec=serde_json::from_slice(&fs::read(&a[3])?)?;let input:CandidateInput=serde_json::from_slice(&fs::read(&a[4])?)?;goal.validate()?;let target=goal.validate_input(&input)?;
    let gb=fs::read(&a[1])?;let mb=fs::read(&a[2])?;if hash(&gb)!=goal.graph_root||hash(&mb)!=goal.model_data_root{return Err("frozen model bytes".into());}
    let g=Graph::parse(&gb).map_err(|e|format!("{e:?}"))?;let m=ModelMeta::parse(&mb,&g).map_err(|e|format!("{e:?}"))?;
    if g.neuron_count!=goal.neuron_count as usize||flypow_target_protocol::hex(&g.registry_root)!=goal.registry_root{return Err("registry mismatch".into());}
    for set in [&goal.stimulus_set,&goal.response_set,&goal.off_target_set]{for member in set{if g.body_id(member.model_index as usize)!=flypow_target_protocol::body(&member.body_id)?{return Err("set member mismatch".into());}}}
    if a[5].len()!=16{return Err("u64 seed encoding".into());}flypow_target_protocol::unhex(&a[5])?;let seed=u64::from_str_radix(&a[5],16)?;
    let task=Task{target_index:target as usize,steps:goal.steps,observe_start:0,stimulus_start:input.start_step,stimulus_end:input.end_step,stimulus_current:input.current as i64,public_seed:seed};let mut counters=None;
    let response=simulate_pair_observed(&g,&m.signs,&m.vnc,&m.roi_masks,Parameters::development_v0(),task,|p|counters=Some(p)).map_err(|e|format!("{e:?}"))?;
    let bytes=encode_response(&response,goal.neuron_count,target,goal.steps).map_err(|e|format!("{e:?}"))?;let metrics=evaluate(&goal,&input,&bytes)?;
    phase.set("RETRYABLE_INFRA_ERROR");
    let replay_matches=if verify {fs::read(&a[6])?==bytes}else{false};
    if !verify {let mut f=fs::OpenOptions::new().create_new(true).write(true).open(&a[6])?;f.write_all(&bytes)?;}
    let c=counters.unwrap();Ok(serde_json::json!({"schema":"flypow-target-trial-measurement-v2","seedHex":a[5],"resultRoot":hash(&bytes),"bytes":bytes.len(),"elapsedMs":started.elapsed().as_millis(),"replayStatus":if !verify{"SIMULATED"}else if replay_matches&&metrics.passed{"VALID"}else{"INVALID_RESULT"},"fullReplay":verify&&c.completed_steps==goal.steps,"metrics":metrics,"neuronUpdates":c.neuron_updates,"synapticAdditions":c.synapse_transmissions,"steps":c.completed_steps,"replayVerified":verify&&replay_matches}))
}
fn main(){
    if env::args().nth(1).as_deref()==Some("--capabilities"){
        println!("{}",serde_json::json!({"schema":"flybrain-native-replay-capabilities-v1","structuredReplayVersion":1,"parameterProfileHashes":[flypow_target_protocol::id("parameter-profile",&flypow_target_protocol::parameters()).unwrap()],"evaluatorVersions":["full-events-selective-v1"],"steps":[256],"maxNeurons":1_000_000}));return;
    }
    let phase=Cell::new("LOCAL_MODEL_ERROR");
    match execute(&phase){Ok(result)=>println!("{result}"),Err(error)=>{println!("{}",serde_json::json!({"schema":"flybrain-native-replay-error-v1","replayStatus":phase.get(),"fullReplay":false,"completeTrials":0,"reason":error.to_string()}));eprintln!("{}: {error}",phase.get());std::process::exit(1);}}
}
