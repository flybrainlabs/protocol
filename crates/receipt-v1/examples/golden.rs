use flypow_receipt_v1::{SubmissionV1, TopNeuron};

fn main() {
    let path = std::env::args().nth(1).expect("output path required");
    let mut record = SubmissionV1::default();
    record.header.schema_version = 1;
    record.header.status = 1;
    record.header.roi_count = 1;
    record.header.top_count = 1;
    record.header.time_bin_count = 32;
    record.header.summary_encoding = 1;
    record.header.readout_schema_id = 7;
    record.identity.campaign = [1; 32];
    record.identity.miner = [2; 32];
    record.task.body_id = 0x0102_0304_0506_0708;
    record.task.model_neuron_count = 165_122;
    record.task.simulation_steps = 32;
    record.hashes.task_id = [6; 32];
    record.global.spikes_a = 3;
    record.global.spikes_b = 4;
    record.roi_delta_spikes[0] = -17;
    record.population_delta_by_bin[0] = -2;
    record.top[0] = TopNeuron {
        body_id: 42,
        delta_spikes: -1,
        first_divergence_step: 0,
    };
    record.hashes.summary_hash = record.compute_summary_hash(&[11; 32]);
    std::fs::write(path, record.encode_account().expect("valid account")).expect("write vector");
}
