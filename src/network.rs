//! Local testnet coordinator: signatures, atomic balances, staking and grants.
//! This is NOT a peer-to-peer implementation of Byzantine consensus.
use crate::{
    Hash256,
    economics::*,
    hash::{decode_hash, encode_hex, hash_parts},
};
use ed25519_dalek::{Signature, VerifyingKey};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{path::Path, sync::Mutex};

type Result<T> = std::result::Result<T, String>;
pub struct Network {
    db: Mutex<Connection>,
    pub id: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignedAction {
    pub public_key: String,
    pub nonce: String,
    pub expires_at: u64,
    pub action: String,
    pub payload: String,
    pub signature: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkBinding {
    pub ticket: String,
    pub network_id: String,
    pub owner: String,
    pub height: u64,
    pub previous_hash: String,
    pub timestamp: u64,
    pub message: String,
}
#[derive(Clone, Debug)]
struct Account {
    address: String,
    nonce: u64,
    balance: u64,
    stake: u64,
    locked_liquid: u64,
    locked_stake: u64,
    grant_unlock: u64,
    unbond_at: u64,
    active: bool,
    referrer: Option<String>,
    qualified: bool,
    created_at: u64,
}
fn error(e: impl std::fmt::Display) -> String {
    e.to_string()
}
fn get_u(db: &Connection, key: &str) -> Result<u64> {
    db.query_row("SELECT value FROM meta WHERE key=?", [key], |r| {
        r.get::<_, String>(0)
    })
    .map_err(error)?
    .parse()
    .map_err(error)
}
fn set_u(db: &Connection, key: &str, value: u64) -> Result<()> {
    db.execute(
        "UPDATE meta SET value=? WHERE key=?",
        params![value.to_string(), key],
    )
    .map_err(error)?;
    Ok(())
}
fn get_s(db: &Connection, key: &str) -> Result<String> {
    db.query_row("SELECT value FROM meta WHERE key=?", [key], |r| r.get(0))
        .map_err(error)
}
fn set_s(db: &Connection, key: &str, value: &str) -> Result<()> {
    db.execute("UPDATE meta SET value=? WHERE key=?", params![value, key])
        .map_err(error)?;
    Ok(())
}
fn scalar(db: &Connection, sql: &str, args: impl rusqlite::Params) -> Result<u64> {
    db.query_row(sql, args, |r| r.get(0)).map_err(error)
}
fn acct(db: &Connection, address: &str) -> Result<Option<Account>> {
    db.query_row("SELECT address,nonce,balance,stake,locked_liquid,locked_stake,grant_unlock,unbond_at,active,referrer,qualified,created_at FROM accounts WHERE address=?",[address],|r|Ok(Account{
 address:r.get(0)?,nonce:r.get(1)?,balance:r.get(2)?,stake:r.get(3)?,locked_liquid:r.get(4)?,locked_stake:r.get(5)?,grant_unlock:r.get(6)?,unbond_at:r.get(7)?,active:r.get::<_,u64>(8)?==1,referrer:r.get(9)?,qualified:r.get::<_,u64>(10)?==1,created_at:r.get(11)?})).optional().map_err(error)
}
fn journal(
    db: &Connection,
    kind: &str,
    from: &str,
    to: &str,
    amount: u64,
    now: u64,
    reference: &str,
) -> Result<()> {
    db.execute(
        "INSERT INTO journal(kind,sender,recipient,amount,time,reference) VALUES(?,?,?,?,?,?)",
        params![kind, from, to, amount, now, reference],
    )
    .map_err(error)?;
    Ok(())
}
pub fn valid_address(a: &str) -> bool {
    a.len() == 44
        && a.starts_with("fly1")
        && a[4..]
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}
pub fn address_from_public_key(public_key: &Hash256) -> String {
    let digest = hash_parts(b"FlyPoW/wallet-address/v1", &[public_key]);
    format!("fly1{}", encode_hex(&digest[..20]))
}
pub fn signing_message(network_id: &str, a: &SignedAction) -> Vec<u8> {
    format!(
        "FlyPoW signed action v1\n{}\n{}\n{}\n{}\n{}\n{}",
        network_id, a.public_key, a.nonce, a.expires_at, a.action, a.payload
    )
    .into_bytes()
}
fn authenticate(network_id: &str, a: &SignedAction, now: u64) -> Result<(String, u64, Value)> {
    if a.payload.len() > 8192
        || a.action.len() > 40
        || a.expires_at < now
        || a.expires_at > now + 300
    {
        return Err("Signature expired or request too large".into());
    }
    let public = decode_hash(&a.public_key).map_err(error)?;
    if a.signature.len() != 128 || !a.signature.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("Invalid signature encoding".into());
    }
    let mut signature = [0; 64];
    for (i, b) in signature.iter_mut().enumerate() {
        *b = u8::from_str_radix(&a.signature[i * 2..i * 2 + 2], 16).map_err(error)?;
    }
    VerifyingKey::from_bytes(&public)
        .map_err(error)?
        .verify_strict(
            &signing_message(network_id, a),
            &Signature::from_bytes(&signature),
        )
        .map_err(|_| "Wallet signature is invalid".to_owned())?;
    let nonce = a
        .nonce
        .parse::<u64>()
        .map_err(|_| "Invalid wallet nonce".to_owned())?;
    let payload: Value = serde_json::from_str(&a.payload).map_err(error)?;
    if !payload.is_object() {
        return Err("Action payload must be an object".into());
    }
    Ok((address_from_public_key(&public), nonce, payload))
}
pub fn bound_merkle(message: &str, b: &NetworkBinding) -> Hash256 {
    hash_parts(
        b"FlyPoW/network-coinbase/v1",
        &[
            b.network_id.as_bytes(),
            b.owner.as_bytes(),
            b.ticket.as_bytes(),
            message.as_bytes(),
        ],
    )
}
fn allowed_payload(p: &Value, keys: &[&str]) -> Result<()> {
    if p.as_object()
        .unwrap()
        .keys()
        .any(|k| !keys.contains(&k.as_str()))
    {
        return Err("Unexpected action field".into());
    }
    Ok(())
}
fn required<'a>(p: &'a Value, key: &str) -> Result<&'a str> {
    p[key].as_str().ok_or_else(|| format!("Missing {key}"))
}
impl Network {
    pub fn open(path: &Path, now: u64) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(error)?;
        }
        let mut db = Connection::open(path).map_err(error)?;
        db.busy_timeout(std::time::Duration::from_secs(5))
            .map_err(error)?;
        db.execute_batch(include_str!("../config/network-schema.sql"))
            .map_err(error)?;
        let tx = db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(error)?;
        let exists: Option<String> = tx
            .query_row("SELECT value FROM meta WHERE key='network_id'", [], |r| {
                r.get(0)
            })
            .optional()
            .map_err(error)?;
        let id = if let Some(id) = exists {
            id
        } else {
            let mut entropy = [0; 32];
            getrandom::fill(&mut entropy).map_err(error)?;
            let id = format!("flypow-local-{}", &encode_hex(&entropy)[..16]);
            let values = [
                ("network_id", id.clone()),
                ("community_remaining", COMMUNITY_RESERVE_ATOMS.to_string()),
                ("mined", "0".into()),
                ("height", "0".into()),
                ("tip", "00".repeat(32)),
                ("last_block_time", now.to_string()),
                ("campaign_start", week_id(now).to_string()),
                (
                    "last_settled_week",
                    week_id(now).saturating_sub(1).to_string(),
                ),
                ("weekly_spent", "0".into()),
                ("bootstrap_spent", "0".into()),
                ("schema_version", "1".into()),
            ];
            for (k, v) in values {
                tx.execute("INSERT INTO meta(key,value) VALUES(?,?)", params![k, v])
                    .map_err(error)?;
            }
            id
        };
        tx.commit().map_err(error)?;
        Ok(Self {
            db: Mutex::new(db),
            id,
        })
    }
    pub fn execute(&self, a: &SignedAction, now: u64) -> Result<Value> {
        let (address, nonce, payload) = authenticate(&self.id, a, now)?;
        let mut db = self.db.lock().map_err(error)?;
        let tx = db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(error)?;
        tx.execute(
            "UPDATE accounts SET locked_liquid=0,locked_stake=0 WHERE grant_unlock<=?",
            [now],
        )
        .map_err(error)?;
        let existing = acct(&tx, &address)?;
        if existing.as_ref().map_or(0, |x| x.nonce) != nonce {
            return Err("Wallet nonce has changed; retry the action".into());
        }
        if a.action != "register" && existing.is_none() {
            return Err("Register this wallet first".into());
        }
        let result = match a.action.as_str() {
            "register" => {
                allowed_payload(&payload, &["referrer"])?;
                if existing.is_some() {
                    return Err("Wallet is already registered".into());
                }
                let parent = payload["referrer"].as_str().filter(|s| !s.is_empty());
                if let Some(parent) = parent
                    && (parent == address || acct(&tx, parent)?.is_none())
                {
                    return Err("Invalid referral wallet".into());
                }
                tx.execute(
                    "INSERT INTO accounts(address,public_key,referrer,created_at) VALUES(?,?,?,?)",
                    params![
                        address,
                        encode_hex(&decode_hash(&a.public_key).map_err(error)?),
                        parent,
                        now
                    ],
                )
                .map_err(error)?;
                json!({"registered":true,"address":address})
            }
            "transfer" => {
                allowed_payload(&payload, &["to", "amount"])?;
                let to = required(&payload, "to")?;
                let amount = parse_coins(required(&payload, "amount")?).map_err(error)?;
                let account = existing.as_ref().unwrap();
                if amount == 0 || !valid_address(to) || to == address || acct(&tx, to)?.is_none() {
                    return Err("Choose a registered recipient and a positive amount".into());
                }
                if amount > account.balance.saturating_sub(account.locked_liquid) {
                    return Err("Insufficient unlocked balance".into());
                }
                tx.execute(
                    "UPDATE accounts SET balance=balance-? WHERE address=?",
                    params![amount, address],
                )
                .map_err(error)?;
                tx.execute(
                    "UPDATE accounts SET balance=balance+? WHERE address=?",
                    params![amount, to],
                )
                .map_err(error)?;
                journal(
                    &tx,
                    "transfer",
                    &address,
                    to,
                    amount,
                    now,
                    &format!("{address}:{nonce}"),
                )?;
                json!({"transferred_atoms":amount.to_string(),"to":to})
            }
            "bootstrap" => {
                allowed_payload(&payload, &[])?;
                let account = existing.as_ref().unwrap();
                if !account.qualified {
                    return Err(
                        "Complete a wallet-bound computation before claiming a launch seat".into(),
                    );
                }
                if scalar(
                    &tx,
                    "SELECT count(*) FROM awards WHERE address=?",
                    [&address],
                )? > 0
                {
                    return Err("A launch award is limited to one per wallet".into());
                }
                let seats = scalar(
                    &tx,
                    "SELECT count(*) FROM awards WHERE kind='bootstrap'",
                    [],
                )?;
                if seats >= BOOTSTRAP_SEATS {
                    return Err("All founding seats are taken; join the weekly ranking".into());
                }
                distribute_grant(&tx, &address, AIRDROP_ATOMS, now, "bootstrap")?;
                tx.execute("INSERT INTO awards(address,kind,week,rank,amount,claimed,time) VALUES(?,'bootstrap',?, ?,?,1,?)",params![address,week_id(now),seats+1,AIRDROP_ATOMS,now]).map_err(error)?;
                set_u(
                    &tx,
                    "bootstrap_spent",
                    get_u(&tx, "bootstrap_spent")? + AIRDROP_ATOMS,
                )?;
                json!({"awarded_atoms":AIRDROP_ATOMS.to_string(),"grant_unlock":now+GRANT_LOCK_SECONDS})
            }
            "claim_weekly" => {
                allowed_payload(&payload, &[])?;
                let award: Option<(u64, bool)> = tx
                    .query_row(
                        "SELECT amount,claimed FROM awards WHERE address=? AND kind='weekly'",
                        [&address],
                        |r| Ok((r.get(0)?, r.get::<_, u64>(1)? == 1)),
                    )
                    .optional()
                    .map_err(error)?;
                let (amount, claimed) = award.ok_or("No settled weekly award is available")?;
                if claimed {
                    return Err("This award was already claimed".into());
                }
                // Weekly funds were reserved when the round settled.
                credit_reserved_grant(&tx, &address, amount, now, "weekly_airdrop")?;
                tx.execute(
                    "UPDATE awards SET claimed=1,time=? WHERE address=?",
                    params![now, address],
                )
                .map_err(error)?;
                json!({"awarded_atoms":amount.to_string(),"grant_unlock":now+GRANT_LOCK_SECONDS})
            }
            "stake" => {
                allowed_payload(&payload, &[])?;
                let account = existing.as_ref().unwrap();
                if account.stake != 0 || account.unbond_at != 0 {
                    return Err("This wallet already has a validator bond".into());
                }
                if account.balance < VALIDATOR_STAKE_ATOMS {
                    return Err("10,000 FLY is required to become a validator".into());
                }
                let locked = account.locked_liquid.min(VALIDATOR_STAKE_ATOMS);
                tx.execute("UPDATE accounts SET balance=balance-?,stake=?,locked_liquid=locked_liquid-?,locked_stake=?,active=1 WHERE address=?",params![VALIDATOR_STAKE_ATOMS,VALIDATOR_STAKE_ATOMS,locked,locked,address]).map_err(error)?;
                journal(
                    &tx,
                    "stake",
                    &address,
                    "VALIDATOR_BOND",
                    VALIDATOR_STAKE_ATOMS,
                    now,
                    &address,
                )?;
                json!({"validator":true,"staked_atoms":VALIDATOR_STAKE_ATOMS.to_string()})
            }
            "unstake" => {
                allowed_payload(&payload, &[])?;
                let account = existing.as_ref().unwrap();
                if !account.active || account.stake == 0 {
                    return Err("No active validator bond".into());
                }
                if scalar(
                    &tx,
                    "SELECT count(*) FROM candidates c WHERE c.status='pending' AND EXISTS(SELECT 1 FROM json_each(c.committee) WHERE value=?) AND NOT EXISTS(SELECT 1 FROM votes v WHERE v.candidate=c.hash AND v.address=?)",
                    params![address, address],
                )? > 0
                {
                    return Err("Finish assigned attestations before starting unbonding".into());
                }
                let due = (now + UNBONDING_SECONDS).max(if account.locked_stake > 0 {
                    account.grant_unlock
                } else {
                    0
                });
                tx.execute(
                    "UPDATE accounts SET active=0,unbond_at=? WHERE address=?",
                    params![due, address],
                )
                .map_err(error)?;
                json!({"unbond_at":due})
            }
            "withdraw_stake" => {
                allowed_payload(&payload, &[])?;
                let account = existing.as_ref().unwrap();
                if account.unbond_at == 0 || now < account.unbond_at {
                    return Err("The validator bond is still locked".into());
                }
                tx.execute("UPDATE accounts SET balance=balance+stake,stake=0,locked_stake=0,unbond_at=0 WHERE address=?",[&address]).map_err(error)?;
                journal(
                    &tx,
                    "unstake_release",
                    "VALIDATOR_BOND",
                    &address,
                    account.stake,
                    now,
                    &address,
                )?;
                json!({"released_atoms":account.stake.to_string()})
            }
            "mine" => {
                allowed_payload(&payload, &["message"])?;
                let message = required(&payload, "message")?;
                if message.len() > 1024 {
                    return Err("Message exceeds 1024 bytes".into());
                }
                let mut entropy = [0; 32];
                getrandom::fill(&mut entropy).map_err(error)?;
                let binding = NetworkBinding {
                    ticket: encode_hex(&entropy),
                    network_id: self.id.clone(),
                    owner: address.clone(),
                    height: get_u(&tx, "height")? + 1,
                    previous_hash: get_s(&tx, "tip")?,
                    timestamp: now,
                    message: message.to_owned(),
                };
                tx.execute(
                    "INSERT INTO tickets(id,owner,binding,expires) VALUES(?,?,?,?)",
                    params![
                        binding.ticket,
                        address,
                        serde_json::to_string(&binding).map_err(error)?,
                        now + 300
                    ],
                )
                .map_err(error)?;
                json!({"ticket":binding.ticket,"difficulty_bits":NETWORK_DIFFICULTY_BITS,"binding":binding})
            }
            _ => return Err("Unsupported signed action".into()),
        };
        tx.execute(
            "UPDATE accounts SET nonce=nonce+1 WHERE address=?",
            [&address],
        )
        .map_err(error)?;
        tx.commit().map_err(error)?;
        Ok(json!({"ok":true,"address":address,"result":result}))
    }
    pub fn consume_ticket(&self, id: &str, message: &str, now: u64) -> Result<NetworkBinding> {
        let mut db = self.db.lock().map_err(error)?;
        let tx = db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(error)?;
        let (binding, expires, used): (String, u64, bool) = tx
            .query_row(
                "SELECT binding,expires,used FROM tickets WHERE id=?",
                [id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get::<_, u64>(2)? != 0)),
            )
            .map_err(|_| "Mining authorization not found".to_owned())?;
        if used || expires < now {
            return Err("Mining authorization expired or was already used".into());
        }
        let binding: NetworkBinding = serde_json::from_str(&binding).map_err(error)?;
        if binding.message != message {
            return Err("The mining message differs from the signed request".into());
        }
        tx.execute("UPDATE tickets SET used=1 WHERE id=?", [id])
            .map_err(error)?;
        tx.commit().map_err(error)?;
        Ok(binding)
    }
}
fn credit_reserved_grant(
    db: &Connection,
    address: &str,
    amount: u64,
    now: u64,
    kind: &str,
) -> Result<()> {
    db.execute("UPDATE accounts SET balance=balance+?,locked_liquid=locked_liquid+?,grant_unlock=max(grant_unlock,?) WHERE address=?",params![amount,amount,now+GRANT_LOCK_SECONDS,address]).map_err(error)?;
    journal(db, kind, "COMMUNITY_RESERVE", address, amount, now, address)
}
fn distribute_grant(
    db: &Connection,
    address: &str,
    amount: u64,
    now: u64,
    kind: &str,
) -> Result<()> {
    let remaining = get_u(db, "community_remaining")?;
    if amount > remaining {
        return Err("Community reserve exhausted".into());
    }
    set_u(db, "community_remaining", remaining - amount)?;
    credit_reserved_grant(db, address, amount, now, kind)
}

impl Network {
    pub fn accept_proof(
        &self,
        b: &NetworkBinding,
        proof: &Value,
        hash: &str,
        now: u64,
    ) -> Result<()> {
        let mut db = self.db.lock().map_err(error)?;
        let tx = db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(error)?;
        if b.network_id != self.id {
            return Err("Wrong network".into());
        }
        let stored: String = tx
            .query_row(
                "SELECT binding FROM tickets WHERE id=? AND owner=? AND used=1",
                params![b.ticket, b.owner],
                |r| r.get(0),
            )
            .map_err(error)?;
        if stored != serde_json::to_string(b).map_err(error)? {
            return Err("Mining authorization mismatch".into());
        }
        if scalar(
            &tx,
            "SELECT count(*) FROM computations WHERE hash=?",
            [hash],
        )? > 0
        {
            return Ok(());
        }
        let mut statement = tx
            .prepare("SELECT address FROM accounts WHERE active=1 AND stake>=? AND address<>?")
            .map_err(error)?;
        let mut members = statement
            .query_map(params![VALIDATOR_STAKE_ATOMS, b.owner], |r| {
                r.get::<_, String>(0)
            })
            .map_err(error)?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(error)?;
        drop(statement);
        members.sort_by_key(|address| {
            hash_parts(
                b"FlyPoW/committee/v1",
                &[
                    b.previous_hash.as_bytes(),
                    &b.height.to_le_bytes(),
                    address.as_bytes(),
                ],
            )
        });
        members.truncate(MAX_COMMITTEE);
        let status =
            if b.height == get_u(&tx, "height")? + 1 && b.previous_hash == get_s(&tx, "tip")? {
                "pending"
            } else {
                "stale"
            };
        tx.execute("INSERT INTO candidates(hash,owner,ticket,proof,committee,quorum,height,previous_hash,status,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)",params![hash,b.owner,b.ticket,proof.to_string(),serde_json::to_string(&members).map_err(error)?,quorum(members.len()) as u64,b.height,b.previous_hash,status,now]).map_err(error)?;
        tx.execute(
            "INSERT INTO computations(hash,owner,time) VALUES(?,?,?)",
            params![hash, b.owner, now],
        )
        .map_err(error)?;
        let day = now / 86_400;
        let week = week_id(now);
        if scalar(
            &tx,
            "SELECT count(*) FROM points WHERE address=? AND kind='compute' AND day=?",
            params![b.owner, day],
        )? < COMPUTATIONS_PER_DAY
        {
            tx.execute("INSERT INTO points(address,kind,source,week,day,amount,time) VALUES(?,'compute',?,?,?,?,?)",params![b.owner,hash,week,day,POINTS_PER_TASK,now]).map_err(error)?;
        }
        let account = acct(&tx, &b.owner)?.ok_or("Unknown mining wallet")?;
        if !account.qualified {
            tx.execute(
                "UPDATE accounts SET qualified=1 WHERE address=?",
                [&b.owner],
            )
            .map_err(error)?;
            if let Some(parent) = account.referrer {
                let invites = scalar(
                    &tx,
                    "SELECT count(*) FROM points WHERE address=? AND kind='referral' AND week=?",
                    params![parent, week],
                )?;
                if invites < INVITES_PER_WEEK {
                    tx.execute("INSERT OR IGNORE INTO points(address,kind,source,week,day,amount,time) VALUES(?,'referral',?,?,?,?,?)",params![parent,b.owner,week,day,POINTS_PER_TASK,now]).map_err(error)?;
                }
            }
        }
        tx.commit().map_err(error)
    }
    pub fn candidate_proof(&self, hash: &str) -> Result<Value> {
        let db = self.db.lock().map_err(error)?;
        let text: String = db
            .query_row("SELECT proof FROM candidates WHERE hash=?", [hash], |r| {
                r.get(0)
            })
            .map_err(|_| "Candidate not found".to_owned())?;
        serde_json::from_str(&text).map_err(error)
    }
    pub fn attest(&self, a: &SignedAction, recomputed_hash: &str, now: u64) -> Result<Value> {
        let (address, nonce, p) = authenticate(&self.id, a, now)?;
        if a.action != "attest" {
            return Err("Wrong signed action".into());
        }
        allowed_payload(&p, &["candidate", "work_hash"])?;
        let hash = required(&p, "candidate")?;
        if required(&p, "work_hash")? != recomputed_hash || hash != recomputed_hash {
            return Err("Recomputed work hash differs from the signed attestation".into());
        }
        let mut db = self.db.lock().map_err(error)?;
        let tx = db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(error)?;
        let account = acct(&tx, &address)?.ok_or("Register this wallet first")?;
        if account.nonce != nonce {
            return Err("Wallet nonce has changed; retry the action".into());
        }
        if account.stake < VALIDATOR_STAKE_ATOMS {
            return Err("An active 10,000 FLY bond is required".into());
        }
        let (owner, committee, status): (String, String, String) = tx
            .query_row(
                "SELECT owner,committee,status FROM candidates WHERE hash=?",
                [hash],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .map_err(error)?;
        if owner == address {
            return Err("A miner cannot validate their own candidate".into());
        }
        let members: Vec<String> = serde_json::from_str(&committee).map_err(error)?;
        if status != "pending" || !members.contains(&address) {
            return Err("This wallet is not assigned to this pending candidate".into());
        }
        if scalar(
            &tx,
            "SELECT count(*) FROM votes WHERE candidate=? AND address=?",
            params![hash, address],
        )? > 0
        {
            return Err("This validator has already voted".into());
        }
        tx.execute(
            "INSERT INTO votes(candidate,address,signature,time) VALUES(?,?,?,?)",
            params![hash, address, a.signature, now],
        )
        .map_err(error)?;
        tx.execute(
            "UPDATE accounts SET nonce=nonce+1 WHERE address=?",
            [&address],
        )
        .map_err(error)?;
        tx.commit().map_err(error)?;
        Ok(json!({"ok":true,"address":address,"result":{"attested":true,"candidate":hash}}))
    }
    pub fn tick(&self, now: u64) -> Result<()> {
        let mut db = self.db.lock().map_err(error)?;
        let tx = db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(error)?;
        tx.execute(
            "UPDATE accounts SET locked_liquid=0,locked_stake=0 WHERE grant_unlock<=?",
            [now],
        )
        .map_err(error)?;
        settle_rounds(&tx, now)?;
        let last = get_u(&tx, "last_block_time")?;
        if now >= last.saturating_add(TARGET_BLOCK_SECONDS) {
            let height = get_u(&tx, "height")? + 1;
            let tip = get_s(&tx, "tip")?;
            let candidates = {
                let mut st=tx.prepare("SELECT hash,owner,quorum FROM candidates WHERE status='pending' AND height=? AND previous_hash=? ORDER BY created_at,hash").map_err(error)?;
                st.query_map(params![height, tip], |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, u64>(2)?,
                    ))
                })
                .map_err(error)?
                .collect::<rusqlite::Result<Vec<_>>>()
                .map_err(error)?
            };
            for (hash, owner, needed) in candidates {
                if needed == 0 {
                    continue;
                }
                let voters = {
                    let mut st=tx.prepare("SELECT v.address FROM votes v JOIN accounts a ON a.address=v.address WHERE v.candidate=? AND a.stake>=? ORDER BY v.address").map_err(error)?;
                    st.query_map(params![hash, VALIDATOR_STAKE_ATOMS], |r| {
                        r.get::<_, String>(0)
                    })
                    .map_err(error)?
                    .collect::<rusqlite::Result<Vec<_>>>()
                    .map_err(error)?
                };
                if voters.len() < (needed as usize) {
                    continue;
                }
                let mined = get_u(&tx, "mined")?;
                if mined != mined_before_height(height) {
                    return Err("Emission state does not match finalized height".into());
                }
                let reward = capped_subsidy(height, mined);
                let (miner, validator) = split_reward(reward);
                tx.execute(
                    "UPDATE accounts SET balance=balance+? WHERE address=?",
                    params![miner, owner],
                )
                .map_err(error)?;
                journal(
                    &tx,
                    "mining_reward",
                    "MINING_RESERVE",
                    &owner,
                    miner,
                    now,
                    &hash,
                )?;
                let mut allocations = Vec::new();
                for (i, address) in voters.iter().enumerate() {
                    let amount = validator / voters.len() as u64
                        + u64::from((i as u64) < validator % voters.len() as u64);
                    tx.execute(
                        "UPDATE accounts SET balance=balance+? WHERE address=?",
                        params![amount, address],
                    )
                    .map_err(error)?;
                    journal(
                        &tx,
                        "validator_reward",
                        "MINING_RESERVE",
                        address,
                        amount,
                        now,
                        &hash,
                    )?;
                    allocations.push(json!({"address":address,"amount_atoms":amount.to_string()}));
                }
                tx.execute("INSERT INTO chain(height,hash,previous_hash,owner,reward,miner_reward,validator_reward,validators,finalized_at) VALUES(?,?,?,?,?,?,?,?,?)",params![height,hash,tip,owner,reward,miner,validator,serde_json::to_string(&allocations).map_err(error)?,now]).map_err(error)?;
                tx.execute(
                    "UPDATE candidates SET status='stale' WHERE status='pending' AND height<=?",
                    [height],
                )
                .map_err(error)?;
                tx.execute(
                    "UPDATE candidates SET status='finalized' WHERE hash=?",
                    [&hash],
                )
                .map_err(error)?;
                set_u(&tx, "height", height)?;
                set_s(&tx, "tip", &hash)?;
                set_u(&tx, "last_block_time", now)?;
                set_u(&tx, "mined", mined + reward)?;
                break;
            }
        }
        tx.commit().map_err(error)
    }
    pub fn status(&self, now: u64) -> Result<Value> {
        let db = self.db.lock().map_err(error)?;
        let height = get_u(&db, "height")?;
        let mined = get_u(&db, "mined")?;
        let reserve = get_u(&db, "community_remaining")?;
        let next = block_subsidy_atoms(height + 1).min(MINING_RESERVE_ATOMS - mined);
        let (miner, validator) = split_reward(next);
        Ok(
            json!({"network_id":self.id,"mode":"local_testnet_coordinator","server_time":now,"height":height,"tip":get_s(&db,"tip")?,
   "last_block_time":get_u(&db,"last_block_time")?,"next_block_earliest":get_u(&db,"last_block_time")?+TARGET_BLOCK_SECONDS,
   "active_validators":scalar(&db,"SELECT count(*) FROM accounts WHERE active=1 AND stake>=?",[VALIDATOR_STAKE_ATOMS])?,
   "accounts":scalar(&db,"SELECT count(*) FROM accounts",[])?,
   "pending_candidates":scalar(&db,"SELECT count(*) FROM candidates WHERE status='pending'",[])?,
   "mined_atoms":mined.to_string(),"community_remaining_atoms":reserve.to_string(),
   "economics":{"total_supply_atoms":TOTAL_SUPPLY_ATOMS.to_string(),"community_reserve_atoms":COMMUNITY_RESERVE_ATOMS.to_string(),"mining_reserve_atoms":MINING_RESERVE_ATOMS.to_string(),"block_seconds":TARGET_BLOCK_SECONDS,"first_stage_blocks":FIRST_STAGE_BLOCKS,"tranche_atoms":EMISSION_TRANCHE_ATOMS.to_string(),"schedule":emission_schedule(),"current_stage":(mined/EMISSION_TRANCHE_ATOMS+1).min(9),"initial_reward_atoms":INITIAL_SUBSIDY_ATOMS.to_string(),"current_reward_atoms":next.to_string(),"miner_reward_atoms":miner.to_string(),"validator_reward_atoms":validator.to_string(),"stake_atoms":VALIDATOR_STAKE_ATOMS.to_string(),"grant_lock_days":90,"unbonding_days":7,"bootstrap_seats":BOOTSTRAP_SEATS,"weekly_winners":WEEKLY_WINNERS,"campaign_weeks":CAMPAIGN_WEEKS,"bootstrap_budget_atoms":BOOTSTRAP_BUDGET.to_string(),"weekly_budget_atoms":WEEKLY_BUDGET.to_string()}}),
        )
    }
    pub fn account(&self, address: &str, now: u64) -> Result<Value> {
        if !valid_address(address) {
            return Err("Invalid FlyPoW wallet address".into());
        }
        let db = self.db.lock().map_err(error)?;
        let account = acct(&db, address)?;
        let Some(a) = account else {
            return Ok(
                json!({"exists":false,"address":address,"nonce":"0","server_time":now,"network_id":self.id}),
            );
        };
        let locked = if now >= a.grant_unlock {
            0
        } else {
            a.locked_liquid
        };
        let history = {
            let mut st=db.prepare("SELECT kind,sender,recipient,amount,time,reference FROM journal WHERE sender=? OR recipient=? ORDER BY id DESC LIMIT 30").map_err(error)?;
            st.query_map(params![address,address],|r|Ok(json!({"kind":r.get::<_,String>(0)?,"from":r.get::<_,String>(1)?,"to":r.get::<_,String>(2)?,"amount_atoms":r.get::<_,u64>(3)?.to_string(),"time":r.get::<_,u64>(4)?,"reference":r.get::<_,String>(5)?}))).map_err(error)?.collect::<rusqlite::Result<Vec<_>>>().map_err(error)?
        };
        let award=db.query_row("SELECT kind,week,rank,amount,claimed FROM awards WHERE address=?",[address],|r|Ok(json!({"kind":r.get::<_,String>(0)?,"week":r.get::<_,u64>(1)?,"rank":r.get::<_,u64>(2)?,"amount_atoms":r.get::<_,u64>(3)?.to_string(),"claimed":r.get::<_,u64>(4)?==1}))).optional().map_err(error)?;
        let pending = assigned_candidates(&db, address)?;
        Ok(
            json!({"exists":true,"address":a.address,"nonce":a.nonce.to_string(),"balance_atoms":a.balance.to_string(),"spendable_atoms":a.balance.saturating_sub(locked).to_string(),"stake_atoms":a.stake.to_string(),"locked_atoms":locked.to_string(),"grant_unlock":a.grant_unlock,"unbond_at":a.unbond_at,"validator_active":a.active,"qualified":a.qualified,"referrer":a.referrer,"created_at":a.created_at,"history":history,"award":award,"assignments":pending,"network_id":self.id,"server_time":now,
 "week_points":scalar(&db,"SELECT coalesce(sum(amount),0) FROM points WHERE address=? AND week=?",params![address,week_id(now)])?,
 "computations_today":scalar(&db,"SELECT count(*) FROM points WHERE address=? AND kind='compute' AND day=?",params![address,now/86_400])?,
 "qualified_invites_week":scalar(&db,"SELECT count(*) FROM points WHERE address=? AND kind='referral' AND week=?",params![address,week_id(now)])?}),
        )
    }
    pub fn community(&self, now: u64) -> Result<Value> {
        let db = self.db.lock().map_err(error)?;
        let week = week_id(now);
        let start = get_u(&db, "campaign_start")?;
        let ranking = ranked(&db, week, false)?;
        Ok(
            json!({"week":week,"round":week.saturating_sub(start)+1,"ends_at":week_end(week),"server_time":now,
   "active":week<start+CAMPAIGN_WEEKS,"ranking":ranking,
   "bootstrap_claimed":scalar(&db,"SELECT count(*) FROM awards WHERE kind='bootstrap'",[])?,
   "bootstrap_seats":BOOTSTRAP_SEATS,"weekly_winners":WEEKLY_WINNERS,"award_atoms":AIRDROP_ATOMS.to_string(),
   "community_remaining_atoms":get_u(&db,"community_remaining")?.to_string(),"weekly_spent_atoms":get_u(&db,"weekly_spent")?.to_string(),
   "rules":{"points_per_task":POINTS_PER_TASK,"computations_per_day":COMPUTATIONS_PER_DAY,"invites_per_week":INVITES_PER_WEEK,"social_verification":"not_connected","grant_lock_days":90,"one_award_per_wallet":true}}),
        )
    }
    pub fn validators(&self) -> Result<Value> {
        let db = self.db.lock().map_err(error)?;
        let mut st=db.prepare("SELECT address,stake,active,unbond_at,(SELECT count(*) FROM votes WHERE votes.address=accounts.address) FROM accounts WHERE stake>0 ORDER BY created_at").map_err(error)?;
        let validators=st.query_map([],|r|Ok(json!({"address":r.get::<_,String>(0)?,"stake_atoms":r.get::<_,u64>(1)?.to_string(),"active":r.get::<_,u64>(2)?==1,"unbond_at":r.get::<_,u64>(3)?,"attestations":r.get::<_,u64>(4)?}))).map_err(error)?.collect::<rusqlite::Result<Vec<_>>>().map_err(error)?;
        Ok(
            json!({"validators":validators,"stake_atoms":VALIDATOR_STAKE_ATOMS.to_string(),"committee_limit":MAX_COMMITTEE,"quorum":"strictly_more_than_two_thirds","mode":"local_testnet_coordinator"}),
        )
    }
    pub fn chain(&self) -> Result<Value> {
        let db = self.db.lock().map_err(error)?;
        let mut st=db.prepare("SELECT height,hash,owner,reward,miner_reward,validator_reward,validators,finalized_at FROM chain ORDER BY height DESC LIMIT 100").map_err(error)?;
        let blocks=st.query_map([],|r|Ok(json!({"height":r.get::<_,u64>(0)?,"hash":r.get::<_,String>(1)?,"owner":r.get::<_,String>(2)?,"reward_atoms":r.get::<_,u64>(3)?.to_string(),"miner_reward_atoms":r.get::<_,u64>(4)?.to_string(),"validator_reward_atoms":r.get::<_,u64>(5)?.to_string(),"validators":serde_json::from_str::<Value>(&r.get::<_,String>(6)?).unwrap_or(json!([])),"finalized_at":r.get::<_,u64>(7)?}))).map_err(error)?.collect::<rusqlite::Result<Vec<_>>>().map_err(error)?;
        Ok(json!({"blocks":blocks,"height":get_u(&db,"height")?}))
    }
    pub fn candidate_state(&self, hash: &str) -> Result<Value> {
        let db = self.db.lock().map_err(error)?;
        db.query_row("SELECT status,height,owner,committee,quorum,(SELECT count(*) FROM votes WHERE candidate=candidates.hash) FROM candidates WHERE hash=?",[hash],|r|Ok(json!({"status":r.get::<_,String>(0)?,"height":r.get::<_,u64>(1)?,"owner":r.get::<_,String>(2)?,"committee":serde_json::from_str::<Value>(&r.get::<_,String>(3)?).unwrap_or(json!([])),"quorum":r.get::<_,u64>(4)?,"votes":r.get::<_,u64>(5)?}))).optional().map_err(error).map(|v|v.unwrap_or(json!({"status":"legacy","height":0})))
    }
}
fn ranked(db: &Connection, week: u64, eligible_only: bool) -> Result<Vec<Value>> {
    let mut st=db.prepare("SELECT a.address,coalesce(sum(p.amount),0) AS score,coalesce(sum(CASE WHEN p.kind='referral' THEN 1 ELSE 0 END),0) AS invites,min(p.time),a.qualified,(SELECT count(*) FROM awards w WHERE w.address=a.address) FROM accounts a JOIN points p ON p.address=a.address AND p.week=? GROUP BY a.address ORDER BY score DESC,invites DESC,min(p.time),a.address").map_err(error)?;
    let rows = st
        .query_map([week], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, u64>(1)?,
                r.get::<_, u64>(2)?,
                r.get::<_, u64>(3)?,
                r.get::<_, u64>(4)? != 0,
                r.get::<_, u64>(5)? != 0,
            ))
        })
        .map_err(error)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(error)?;
    Ok(rows.into_iter().filter(|row|!eligible_only||(row.4&&!row.5)).take(100).enumerate().map(|(i,(address,points,invites,time,qualified,awarded))|json!({"rank":i+1,"address":address,"points":points,"invites":invites,"first_point_at":time,"eligible":qualified&&!awarded,"previous_winner":awarded})).collect())
}
fn settle_rounds(db: &Connection, now: u64) -> Result<()> {
    let start = get_u(db, "campaign_start")?;
    let last = get_u(db, "last_settled_week")?;
    let end = week_id(now)
        .saturating_sub(1)
        .min(start + CAMPAIGN_WEEKS - 1);
    if end < start || end <= last {
        return Ok(());
    }
    for week in last.max(start.saturating_sub(1)) + 1..=end {
        let winners = ranked(db, week, true)?;
        let mut count = 0;
        for (rank, winner) in winners
            .into_iter()
            .take(WEEKLY_WINNERS as usize)
            .enumerate()
        {
            let remaining = get_u(db, "community_remaining")?;
            let spent = get_u(db, "weekly_spent")?;
            if remaining < AIRDROP_ATOMS || spent + AIRDROP_ATOMS > WEEKLY_BUDGET {
                break;
            }
            let address = winner["address"].as_str().unwrap();
            db.execute("INSERT INTO awards(address,kind,week,rank,amount,claimed,time) VALUES(?,'weekly',?,?,?,0,?)",params![address,week,rank+1,AIRDROP_ATOMS,now]).map_err(error)?;
            set_u(db, "community_remaining", remaining - AIRDROP_ATOMS)?;
            set_u(db, "weekly_spent", spent + AIRDROP_ATOMS)?;
            count += 1;
        }
        db.execute(
            "INSERT OR IGNORE INTO rounds(week,settled_at,winners) VALUES(?,?,?)",
            params![week, now, count],
        )
        .map_err(error)?;
        set_u(db, "last_settled_week", week)?;
    }
    Ok(())
}
fn assigned_candidates(db: &Connection, address: &str) -> Result<Vec<Value>> {
    let mut st=db.prepare("SELECT hash,owner,committee,quorum,height,created_at,(SELECT count(*) FROM votes WHERE candidate=candidates.hash),(SELECT count(*) FROM votes WHERE candidate=candidates.hash AND address=?) FROM candidates WHERE status='pending' ORDER BY created_at DESC LIMIT 200").map_err(error)?;
    let rows = st
        .query_map([address], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, u64>(3)?,
                r.get::<_, u64>(4)?,
                r.get::<_, u64>(5)?,
                r.get::<_, u64>(6)?,
                r.get::<_, u64>(7)? != 0,
            ))
        })
        .map_err(error)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(error)?;
    Ok(rows.into_iter().filter_map(|(hash,owner,committee,quorum,height,time,votes,voted)|{
  let members:Vec<String>=serde_json::from_str(&committee).ok()?;
  if !members.iter().any(|m|m==address){return None;}
  Some(json!({"hash":hash,"owner":owner,"height":height,"created_at":time,"votes":votes,"quorum":quorum,"voted":voted}))
 }).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    const NOW: u64 = 1_789_430_400;
    fn key(n: u8) -> SigningKey {
        SigningKey::from_bytes(&[n; 32])
    }
    fn address(k: &SigningKey) -> String {
        address_from_public_key(&k.verifying_key().to_bytes())
    }
    fn signed(
        net: &Network,
        k: &SigningKey,
        action: &str,
        payload: Value,
        now: u64,
    ) -> SignedAction {
        let nonce = net.account(&address(k), now).unwrap()["nonce"]
            .as_str()
            .unwrap()
            .to_owned();
        let mut a = SignedAction {
            public_key: encode_hex(&k.verifying_key().to_bytes()),
            nonce,
            expires_at: now + 180,
            action: action.into(),
            payload: payload.to_string(),
            signature: String::new(),
        };
        a.signature = encode_hex(&k.sign(&signing_message(&net.id, &a)).to_bytes());
        a
    }
    fn action(net: &Network, k: &SigningKey, kind: &str, p: Value, now: u64) -> Result<Value> {
        net.execute(&signed(net, k, kind, p, now), now)
    }
    fn register(net: &Network, k: &SigningKey, parent: Option<&SigningKey>) {
        action(
            net,
            k,
            "register",
            json!({"referrer":parent.map(address).unwrap_or_default()}),
            NOW,
        )
        .unwrap();
    }
    fn computation(net: &Network, k: &SigningKey, serial: u8, now: u64) -> String {
        let message = format!("fixture {serial}");
        let auth = action(net, k, "mine", json!({"message":message}), now).unwrap();
        let ticket = auth["result"]["ticket"].as_str().unwrap();
        let binding = net.consume_ticket(ticket, &message, now).unwrap();
        let hash = encode_hex(&hash_parts(
            b"test proof fixture",
            &[&[serial], address(k).as_bytes(), &now.to_le_bytes()],
        ));
        net.accept_proof(&binding, &json!({"test_fixture":true}), &hash, now)
            .unwrap();
        hash
    }
    fn audit(net: &Network) {
        let db = net.db.lock().unwrap();
        let wallets = scalar(
            &db,
            "SELECT coalesce(sum(balance+stake),0) FROM accounts",
            [],
        )
        .unwrap();
        let pending = scalar(
            &db,
            "SELECT coalesce(sum(amount),0) FROM awards WHERE claimed=0",
            [],
        )
        .unwrap();
        let all = get_u(&db, "community_remaining").unwrap() + MINING_RESERVE_ATOMS
            - get_u(&db, "mined").unwrap()
            + wallets
            + pending;
        assert_eq!(all, TOTAL_SUPPLY_ATOMS);
    }
    #[test]
    fn signatures_replay_and_referral_are_bound() {
        let dir = tempfile::tempdir().unwrap();
        let net = Network::open(&dir.path().join("network.db"), NOW).unwrap();
        let a = key(1);
        let b = key(2);
        let reg = signed(&net, &a, "register", json!({"referrer":""}), NOW);
        net.execute(&reg, NOW).unwrap();
        assert!(net.execute(&reg, NOW).is_err());
        let mut forged = signed(&net, &b, "register", json!({"referrer":address(&a)}), NOW);
        forged.payload = json!({"referrer":""}).to_string();
        assert!(net.execute(&forged, NOW).is_err());
        register(&net, &b, Some(&a));
        computation(&net, &b, 1, NOW);
        assert_eq!(net.account(&address(&a), NOW).unwrap()["week_points"], 10);
        computation(&net, &b, 2, NOW + 1);
        computation(&net, &b, 3, NOW + 2);
        computation(&net, &b, 4, NOW + 3);
        assert_eq!(
            net.account(&address(&b), NOW + 3).unwrap()["week_points"],
            30
        );
        assert_eq!(
            net.account(&address(&a), NOW + 3).unwrap()["week_points"],
            10
        );
        assert!(action(&net, &b, "twitter_follow", json!({}), NOW).is_err());
        audit(&net);
    }
    #[test]
    fn stake_quorum_clock_and_rewards_conserve_supply() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("network.db");
        let net = Network::open(&path, NOW).unwrap();
        let validator = key(3);
        let miner = key(4);
        register(&net, &validator, None);
        register(&net, &miner, None);
        computation(&net, &validator, 10, NOW);
        action(&net, &validator, "bootstrap", json!({}), NOW).unwrap();
        assert!(action(&net, &validator, "bootstrap", json!({}), NOW).is_err());
        assert!(
            action(
                &net,
                &validator,
                "transfer",
                json!({"to":address(&miner),"amount":"1"}),
                NOW
            )
            .is_err()
        );
        action(&net, &validator, "stake", json!({}), NOW).unwrap();
        let hash = computation(&net, &miner, 11, NOW + 1);
        net.tick(NOW + 59).unwrap();
        assert_eq!(net.status(NOW + 59).unwrap()["height"], 0);
        assert!(action(&net, &validator, "unstake", json!({}), NOW + 2).is_err());
        let vote = signed(
            &net,
            &validator,
            "attest",
            json!({"candidate":hash,"work_hash":hash}),
            NOW + 2,
        );
        assert!(net.attest(&vote, &"00".repeat(32), NOW + 2).is_err());
        net.attest(&vote, &hash, NOW + 2).unwrap();
        assert!(net.attest(&vote, &hash, NOW + 2).is_err());
        net.tick(NOW + 60).unwrap();
        assert_eq!(net.status(NOW + 60).unwrap()["height"], 1);
        let (m, v) = split_reward(block_subsidy_atoms(1));
        assert_eq!(
            net.account(&address(&miner), NOW + 60).unwrap()["balance_atoms"],
            m.to_string()
        );
        assert_eq!(
            net.account(&address(&validator), NOW + 60).unwrap()["balance_atoms"],
            v.to_string()
        );
        net.tick(NOW + 61).unwrap();
        assert_eq!(net.status(NOW + 61).unwrap()["height"], 1);
        action(
            &net,
            &validator,
            "transfer",
            json!({"to":address(&miner),"amount":"1.00000001"}),
            NOW + 62,
        )
        .unwrap();
        action(&net, &validator, "unstake", json!({}), NOW + 63).unwrap();
        assert!(action(&net, &validator, "withdraw_stake", json!({}), NOW + 64).is_err());
        action(
            &net,
            &validator,
            "withdraw_stake",
            json!({}),
            NOW + GRANT_LOCK_SECONDS + 1,
        )
        .unwrap();
        audit(&net);
        drop(net);
        let reopened = Network::open(&path, NOW + 100).unwrap();
        assert_eq!(reopened.status(NOW + 100).unwrap()["height"], 1);
        audit(&reopened);
    }
    #[test]
    fn weekly_ranking_settlement_and_claim_are_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let net = Network::open(&dir.path().join("network.db"), NOW).unwrap();
        let mut keys = Vec::new();
        for n in 20..32 {
            let k = key(n);
            register(&net, &k, None);
            computation(&net, &k, n, NOW);
            keys.push(k);
        }
        let close = week_end(week_id(NOW));
        net.tick(close).unwrap();
        net.tick(close + 1).unwrap();
        let mut winners = 0;
        for k in &keys {
            let account = net.account(&address(k), close).unwrap();
            if !account["award"].is_null() {
                winners += 1;
                action(&net, k, "claim_weekly", json!({}), close).unwrap();
                assert!(action(&net, k, "claim_weekly", json!({}), close + 1).is_err());
                assert_eq!(
                    net.account(&address(k), close).unwrap()["balance_atoms"],
                    AIRDROP_ATOMS.to_string()
                );
            }
        }
        assert_eq!(winners, 10);
        audit(&net);
    }
}
