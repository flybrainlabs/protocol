//! Generate a local, uncalibrated aIPg10 catalog; never an active paid campaign.
use flypow_task_catalog::{Campaign, CatalogFile, MerkleTree, Stimulus, Target, hex, parse_hex32};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    env, fs,
    io::{BufWriter, Write},
    path::Path,
};

fn field(json: &Value, name: &str) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    parse_hex32(json[name].as_str().ok_or(format!("missing {name}"))?)
        .map_err(|_| format!("invalid {name}").into())
}

fn sha(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = env::args().collect();
    if args.len() != 5 && args.len() != 6 {
        eprintln!(
            "usage: catalog_draft GRAPH.bin MODEL.bin MODEL_CONFIG.json NEW_OUTPUT_DIR [128|256|512]"
        );
        std::process::exit(2);
    }
    let graph = fs::read(&args[1])?;
    let model = fs::read(&args[2])?;
    let config: Value = serde_json::from_slice(&fs::read(&args[3])?)?;
    let graph_sha = sha(&graph);
    let model_sha = sha(&model);
    if config["state"] != "UNCALIBRATED_DEV_ONLY"
        || graph_sha != field(&config, "graph_root_sha256")?
        || model_sha != field(&config, "metadata_sha256")?
        || graph.len() < 52
        || &graph[..8] != b"FBGR1\0\0\0"
    {
        return Err("model configuration or graph identity mismatch".into());
    }
    let count = u32::from_le_bytes(graph[8..12].try_into()?) as usize;
    if count
        != config["model_neuron_count"]
            .as_u64()
            .ok_or("missing neuron count")? as usize
        || graph.len() < 52 + 8 * count
        || graph[20..52] != field(&config, "registry_root_sha256")?
    {
        return Err("registry count or identity mismatch".into());
    }
    let ids: Vec<u64> = graph[52..52 + 8 * count]
        .as_chunks::<8>()
        .0
        .iter()
        .map(|entry| u64::from_le_bytes(*entry))
        .collect();
    let targets = [16789_u64, 16961, 18708, 87973]
        .iter()
        .map(|body_id| {
            let index = ids
                .binary_search(body_id)
                .map_err(|_| format!("official body {body_id} absent"))?;
            Ok(Target {
                body_id: *body_id,
                model_index: index as u32,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    let steps = if args.len() == 6 {
        args[5].parse::<u32>()?
    } else {
        32
    };
    let mut stimuli = Vec::new();
    for start_step in [0, 4, 8, 12] {
        for duration in [1, 2, 4, 8] {
            for current in [50, 100, 150, 200] {
                stimuli.push(Stimulus {
                    start_step,
                    end_step: start_step + duration,
                    current,
                });
            }
        }
    }
    stimuli.sort_unstable();
    if steps != 32 {
        stimuli =
            flypow_task_catalog::duration_stimuli(steps).map_err(|_| "unknown duration profile")?;
    }
    let mut experiment_hasher = Sha256::new();
    experiment_hasher.update(b"FlyPoW/experiment/lif-rectangular-v0-dev\0");
    experiment_hasher.update(field(&config, "model_root_sha256")?);
    experiment_hasher.update(32_u32.to_le_bytes());
    experiment_hasher.update(1000_u32.to_le_bytes());
    experiment_hasher.update(0_u32.to_le_bytes()); // observation starts at step zero
    for stimulus in &stimuli {
        experiment_hasher.update(stimulus.start_step.to_le_bytes());
        experiment_hasher.update(stimulus.end_step.to_le_bytes());
        experiment_hasher.update(stimulus.current.to_le_bytes());
    }
    let mut campaign = Campaign {
        campaign_id: sha(b"FlyPoW/aipg10/local-catalog-v0/NO-PAYMENT"),
        source_root: field(&config, "source_root_sha256")?,
        registry_root: field(&config, "registry_root_sha256")?,
        graph_root: graph_sha,
        model_root: field(&config, "model_root_sha256")?,
        experiment_root: experiment_hasher.finalize().into(),
        public_seed: sha(b"FlyPoW/LOCAL-DEVELOPMENT-SEED-ONLY/v0"),
        model_neuron_count: count as u32,
        simulation_steps: steps,
        time_step_us: 1000,
        targets,
        stimuli,
        repeats: 4,
    };
    let profile_definition = if steps == 32 {
        None
    } else {
        let definition = flypow_task_catalog::duration_definition(&campaign);
        let (id, experiment, seed) = flypow_task_catalog::duration_roots(&campaign, &definition);
        campaign.campaign_id = id;
        campaign.experiment_root = experiment;
        campaign.public_seed = seed;
        Some(definition)
    };
    let task_count = campaign
        .validate()
        .map_err(|error| format!("catalog error: {error:?}"))?;
    let tree = MerkleTree::build(&campaign).map_err(|error| format!("tree error: {error:?}"))?;
    let output = Path::new(&args[4]);
    fs::create_dir(output)?; // refuses to overwrite existing pilot data
    let manifest = CatalogFile {
        state: "UNCALIBRATED_DEV_ONLY_NO_PAYMENT".into(),
        campaign,
        graph_data_sha256: graph_sha,
        model_data_sha256: model_sha,
        task_manifest_root: tree.root(),
        profile_definition,
    };
    fs::write(
        output.join("catalog.json"),
        serde_json::to_vec_pretty(&manifest)?,
    )?;
    let mut writer = BufWriter::new(fs::File::create_new(output.join("tasks.jsonl"))?);
    for k in 0..task_count {
        let task = manifest
            .campaign
            .task(k)
            .map_err(|error| format!("task error: {error:?}"))?;
        serde_json::to_writer(
            &mut writer,
            &serde_json::json!({
                "task": task, "merkle_proof": tree.proof(k).map_err(|error| format!("proof error: {error:?}"))?
            }),
        )?;
        writer.write_all(b"\n")?;
    }
    writer.flush()?;
    println!(
        "state={}; targets={}; tasks={}; task_manifest_root={}",
        manifest.state,
        manifest.campaign.targets.len(),
        task_count,
        hex(&tree.root())
    );
    Ok(())
}
