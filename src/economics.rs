//! Fixed-supply monetary policy. Amounts are integer atoms, never floats.
pub const ATOMS_PER_COIN: u64 = 100_000_000;
pub const TOTAL_SUPPLY_COINS: u64 = 311_833_243;
pub const TOTAL_SUPPLY_ATOMS: u64 = TOTAL_SUPPLY_COINS * ATOMS_PER_COIN;
pub const COMMUNITY_RESERVE_ATOMS: u64 = TOTAL_SUPPLY_ATOMS / 10;
pub const MINING_RESERVE_ATOMS: u64 = TOTAL_SUPPLY_ATOMS - COMMUNITY_RESERVE_ATOMS;
pub const EMISSION_TRANCHE_ATOMS: u64 = TOTAL_SUPPLY_ATOMS / 10;
pub const FIRST_STAGE_BLOCKS: u64 = 10_080;
pub const EMISSION_STAGES: u64 = 9;
pub const INITIAL_SUBSIDY_ATOMS: u64 = EMISSION_TRANCHE_ATOMS.div_ceil(FIRST_STAGE_BLOCKS);
pub const TARGET_BLOCK_SECONDS: u64 = 60;
pub const VALIDATOR_STAKE_ATOMS: u64 = 10_000 * ATOMS_PER_COIN;
pub const AIRDROP_ATOMS: u64 = VALIDATOR_STAKE_ATOMS;
pub const BOOTSTRAP_SEATS: u64 = 10;
pub const CAMPAIGN_WEEKS: u64 = 52;
pub const WEEKLY_WINNERS: u64 = 10;
pub const BOOTSTRAP_BUDGET: u64 = BOOTSTRAP_SEATS * AIRDROP_ATOMS;
pub const WEEKLY_BUDGET: u64 = CAMPAIGN_WEEKS * WEEKLY_WINNERS * AIRDROP_ATOMS;
pub const GRANT_LOCK_SECONDS: u64 = 90 * 86_400;
pub const UNBONDING_SECONDS: u64 = 7 * 86_400;
pub const COMPUTATIONS_PER_DAY: u64 = 3;
pub const INVITES_PER_WEEK: u64 = 10;
pub const POINTS_PER_TASK: u64 = 10;
pub const NETWORK_DIFFICULTY_BITS: u16 = 8;
pub const MAX_COMMITTEE: usize = 21;
pub const WEEK_SECONDS: u64 = 604_800;
pub fn stage_position(height: u64) -> Option<(u64, u64)> {
    if height == 0 {
        return None;
    }
    let mut offset = height - 1;
    for stage in 0..EMISSION_STAGES {
        let blocks = FIRST_STAGE_BLOCKS << stage;
        if offset < blocks {
            return Some((stage, offset));
        }
        offset -= blocks;
    }
    None
}
pub fn block_subsidy_atoms(height: u64) -> u64 {
    let Some((stage, offset)) = stage_position(height) else {
        return 0;
    };
    let blocks = FIRST_STAGE_BLOCKS << stage;
    EMISSION_TRANCHE_ATOMS / blocks + u64::from(offset < EMISSION_TRANCHE_ATOMS % blocks)
}
pub fn mined_before_height(height: u64) -> u64 {
    if height == 0 {
        return 0;
    }
    let Some((stage, offset)) = stage_position(height) else {
        return MINING_RESERVE_ATOMS;
    };
    let blocks = FIRST_STAGE_BLOCKS << stage;
    stage * EMISSION_TRANCHE_ATOMS
        + offset * (EMISSION_TRANCHE_ATOMS / blocks)
        + offset.min(EMISSION_TRANCHE_ATOMS % blocks)
}
pub fn capped_subsidy(height: u64, already_mined: u64) -> u64 {
    block_subsidy_atoms(height).min(MINING_RESERVE_ATOMS.saturating_sub(already_mined))
}
pub fn emission_schedule() -> Vec<serde_json::Value> {
    (0..EMISSION_STAGES).map(|stage|{
        let blocks=FIRST_STAGE_BLOCKS<<stage;
        serde_json::json!({"stage":stage+1,"blocks":blocks,"target_weeks":1_u64<<stage,"cumulative_weeks":(1_u64<<(stage+1))-1,
            "tranche_atoms":EMISSION_TRANCHE_ATOMS.to_string(),"reward_floor_atoms":(EMISSION_TRANCHE_ATOMS/blocks).to_string(),
            "extra_atom_blocks":EMISSION_TRANCHE_ATOMS%blocks})
    }).collect()
}
pub fn split_reward(reward: u64) -> (u64, u64) {
    let miner = reward * 4 / 5;
    (miner, reward - miner)
}
pub fn theoretical_supply_cap_atoms() -> u128 {
    TOTAL_SUPPLY_ATOMS as u128
}
pub fn format_atoms(atoms: u64) -> String {
    format!("{}.{:08}", atoms / ATOMS_PER_COIN, atoms % ATOMS_PER_COIN)
}
pub fn parse_coins(value: &str) -> Result<u64, &'static str> {
    if value.is_empty() || value.len() > 40 {
        return Err("Invalid token amount");
    }
    let mut parts = value.split('.');
    let whole = parts.next().unwrap();
    let fraction = parts.next().unwrap_or("");
    if parts.next().is_some()
        || whole.is_empty()
        || !whole.bytes().all(|b| b.is_ascii_digit())
        || fraction.len() > 8
        || !fraction.bytes().all(|b| b.is_ascii_digit())
    {
        return Err("Use a positive decimal amount with at most 8 decimal places");
    }
    let whole: u64 = whole.parse().map_err(|_| "Amount overflow")?;
    let frac: u64 = if fraction.is_empty() {
        0
    } else {
        fraction.parse().map_err(|_| "Invalid amount")?
    };
    whole
        .checked_mul(ATOMS_PER_COIN)
        .and_then(|a| a.checked_add(frac * 10_u64.pow(8 - fraction.len() as u32)))
        .ok_or("Amount overflow")
}
pub fn week_id(now: u64) -> u64 {
    (now + 3 * 86_400) / WEEK_SECONDS
}
pub fn week_end(id: u64) -> u64 {
    (id + 1) * WEEK_SECONDS - 3 * 86_400
}
pub fn quorum(members: usize) -> usize {
    if members == 0 { 0 } else { members * 2 / 3 + 1 }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_tranches_and_cap() {
        assert_eq!(
            COMMUNITY_RESERVE_ATOMS + MINING_RESERVE_ATOMS,
            TOTAL_SUPPLY_ATOMS
        );
        assert_eq!(format_atoms(COMMUNITY_RESERVE_ATOMS), "31183324.30000000");
        let mut first = 1;
        let mut total = 0;
        for stage in 0..EMISSION_STAGES {
            let count = FIRST_STAGE_BLOCKS << stage;
            let tranche = (first..first + count).map(block_subsidy_atoms).sum::<u64>();
            assert_eq!(tranche, EMISSION_TRANCHE_ATOMS);
            assert_eq!(mined_before_height(first), total);
            total += tranche;
            first += count;
        }
        assert_eq!(total, MINING_RESERVE_ATOMS);
        assert_eq!(block_subsidy_atoms(first), 0);
        assert_eq!(first - 1, 5_150_880);
        assert_eq!(
            mined_before_height(FIRST_STAGE_BLOCKS + 1),
            EMISSION_TRANCHE_ATOMS
        );
        assert_eq!(block_subsidy_atoms(1), 309_358_375_993);
        assert_eq!(
            split_reward(block_subsidy_atoms(1)),
            (247_486_700_794, 61_871_675_199)
        );
        assert_eq!(capped_subsidy(1, MINING_RESERVE_ATOMS - 1), 1);
    }
    #[test]
    fn money_is_never_float() {
        assert_eq!(parse_coins("10000").unwrap(), VALIDATOR_STAKE_ATOMS);
        assert_eq!(parse_coins("0.00000001").unwrap(), 1);
        for invalid in ["-1", "NaN", "1e8", "1.000000001", " 1", "1.2.3"] {
            assert!(parse_coins(invalid).is_err());
        }
    }
}
