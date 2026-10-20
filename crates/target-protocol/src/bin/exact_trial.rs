//! Complete-model exact event executor. The JSON-lines mode retains one verified
//! graph and serializes jobs; it never admits a miner-supplied event frontier.
use flypow_sim_core::{encode_response, Graph, ModelMeta, Parameters, SimSession, Task};
use flypow_target_protocol::{body, evaluate_complete, hash, hex, CandidateInput, GoalSpec};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{env, fs, io::{self, BufRead, Read, Write}, time::Instant};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Request {
    id: String,
    goal: GoalSpec,
    input: CandidateInput,
    seed_hex: String,
    response_path: String,
    #[serde(default)] verify: bool,
    #[serde(default)] dense_oracle: bool,
}
struct Model<'a> { graph: Graph<'a>, meta: ModelMeta, graph_hash: String, model_hash: String }
fn run(model: &Model<'_>, q: &Request) -> Result<Value, Box<dyn std::error::Error>> {
    let start = Instant::now();
    let g = &q.goal;
    g.validate()?;
    let target = g.validate_input(&q.input)?;
    if model.graph_hash != g.graph_root || model.model_hash != g.model_data_root
        || model.graph.neuron_count != g.neuron_count as usize || hex(&model.graph.registry_root) != g.registry_root {
        return Err("registered model identity mismatch".into());
    }
    for set in [&g.stimulus_set, &g.response_set, &g.off_target_set] {
        for member in set {
            if model.graph.body_id(member.model_index as usize) != body(&member.body_id)? {
                return Err("registered set membership mismatch".into());
            }
        }
    }
    if q.seed_hex.len() != 16 || !q.seed_hex.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)) {
        return Err("canonical u64 seed required".into());
    }
    let t = Task { target_index: target as usize, steps: g.steps, observe_start: 0,
        stimulus_start: q.input.start_step, stimulus_end: q.input.end_step,
        stimulus_current: i64::from(q.input.current), public_seed: u64::from_str_radix(&q.seed_hex, 16)? };
    let mut s = SimSession::new(&model.graph, &model.meta.signs, &model.meta.vnc, &model.meta.roi_masks,
        Parameters::development_v0(), t, g.max_trial_bytes as usize, &[], 0).map_err(|e| format!("{e:?}"))?;
    if !q.dense_oracle { s.enable_sparse().map_err(|e| format!("invariant not admitted: {e:?}"))?; }
    while !s.advance(65536, |_| {}).map_err(|e| format!("{e:?}"))? {}
    let counters = s.progress();
    let backend = if s.used_dense_fallback() {"dense-fallback-v1"} else if q.dense_oracle {"dense-v1"} else {"exact-events-v1"};
    let response = s.finalize().map_err(|e| format!("{e:?}"))?;
    let bytes = encode_response(&response, g.neuron_count, target, g.steps).map_err(|e| format!("{e:?}"))?;
    let metrics = evaluate_complete(g, &q.input, &bytes)?;
    let compute_ms = start.elapsed().as_secs_f64() * 1000.0;
    let matches = if q.verify { fs::read(&q.response_path)? == bytes } else {
        let mut f = fs::OpenOptions::new().create_new(true).write(true).open(&q.response_path)?;
        f.write_all(&bytes)?; f.sync_all()?; true
    };
    Ok(json!({"schema":"flybrain-exact-trial-v1", "id":q.id, "seedHex":q.seed_hex,
        "verificationMethod":if q.dense_oracle {"dense-v1"} else {"exact-events-v1"},"executionBackend":backend,
        "completeModelVerified":q.verify && matches, "fullReplay":q.dense_oracle && q.verify && matches,
        "replayStatus":if !q.verify {"SIMULATED"} else if matches {"COMPUTATION_VALID"} else {"INVALID_RESULT"},
        "scientificPassed":metrics.passed,"metrics":metrics,"offTargetCoverage":"all-outside-response-set","resultRoot":hash(&bytes),"bytes":bytes.len(),
        "pureComputeMs":compute_ms,"elapsedMs":start.elapsed().as_secs_f64()*1000.0,
        "neuronUpdates":counters.neuron_updates,"synapticAdditions":counters.synapse_transmissions,
        "logicalNeuronTicksCovered":2*model.graph.neuron_count as u64*u64::from(g.steps),"steps":counters.completed_steps}))
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = env::args().collect();
    if args.len() == 2 && args[1] == "--capabilities" {
        println!("{}",json!({"schema":"flybrain-exact-trial-capabilities-v1","methods":["exact-events-v1","dense-v1"],
            "parameterProfileHashes":[flypow_target_protocol::id("parameter-profile",&flypow_target_protocol::parameters())?],
            "completeModel":true,"residentModel":true,"serializedJobs":true,"negativeScientificOutcomes":true})); return Ok(());
    }
    if args.len() != 4 || args[1] != "--serve" { return Err("usage: exact_trial --serve GRAPH MODEL (JSON lines on stdin)".into()); }
    let load = Instant::now();
    let gb = fs::read(&args[2])?; let mb = fs::read(&args[3])?;
    let graph = Graph::parse(&gb).map_err(|e| format!("{e:?}"))?;
    let meta = ModelMeta::parse(&mb, &graph).map_err(|e| format!("{e:?}"))?;
    let model = Model {graph,meta,graph_hash:hash(&gb),model_hash:hash(&mb)};
    eprintln!("verified resident model loaded in {:.3} ms",load.elapsed().as_secs_f64()*1000.0);
    let mut reader = io::stdin().lock(); let mut output = io::stdout().lock();
    loop {
        // Bound the request before allocating an unbounded JSON string.
        let mut line = Vec::new();
        let count = (&mut reader).take(1024*1024+1).read_until(b'\n', &mut line)?;
        if count == 0 { break; }
        if count > 1024*1024 { return Err("request limit".into()); }
        let value = match serde_json::from_slice::<Request>(&line) {
            Ok(q) => match run(&model,&q) { Ok(v) => v, Err(e) => json!({"id":q.id,"error":e.to_string(),"completeModelVerified":false}) },
            Err(_) => json!({"error":"invalid request","completeModelVerified":false}),
        };
        writeln!(output,"{value}")?; output.flush()?;
    }
    Ok(())
}
