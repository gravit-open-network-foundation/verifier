//! Rust port of `gravit_verifier/kernel.py` (Python is the reference).
//!
//! STATUS: `cargo test` reproduces all vectors in
//! `../tests/golden/vectors.json` (33/33 checked 2026-10-06, rustc 1.99.0); it
//! conforms only while that keeps passing. Known intentional divergence: an unknown
//! `required_verification_state` sorts last here (Python raises ValueError).

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Epistemic {
    Raw,
    Validated,
    Speculative,
    Probabilistic,
    Fact,
}

impl Epistemic {
    pub fn name(self) -> &'static str {
        match self {
            Epistemic::Raw => "RAW",
            Epistemic::Validated => "VALIDATED",
            Epistemic::Speculative => "Speculative Claim",
            Epistemic::Probabilistic => "Probabilistic Assessment",
            Epistemic::Fact => "Verified Fact",
        }
    }
    pub fn from_name(s: &str) -> Option<Epistemic> {
        [
            Epistemic::Raw,
            Epistemic::Validated,
            Epistemic::Speculative,
            Epistemic::Probabilistic,
            Epistemic::Fact,
        ]
        .into_iter()
        .find(|e| e.name() == s)
    }
    pub fn order(self) -> u8 {
        match self {
            Epistemic::Raw => 0,
            Epistemic::Validated => 1,
            Epistemic::Speculative => 2,
            Epistemic::Probabilistic => 3,
            Epistemic::Fact => 4,
        }
    }
    /// One step down the ladder; RAW demotes to nothing (mirrors Python).
    fn demoted(self) -> Option<Epistemic> {
        match self {
            Epistemic::Fact => Some(Epistemic::Probabilistic),
            Epistemic::Probabilistic => Some(Epistemic::Speculative),
            Epistemic::Speculative => Some(Epistemic::Validated),
            Epistemic::Validated => Some(Epistemic::Raw),
            Epistemic::Raw => None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct Evidence {
    pub record_id: String,
    pub theta: f64,
    /// false if `theta` was not a JSON number (Python: MalformedRecord).
    pub theta_is_number: bool,
    pub result: Value,
    pub verifier_id: String,
    pub timestamp: String,
    pub provenance: String,
    pub integrity_hash: String,
    pub key_id: String,
    pub signature: String,
}

impl Evidence {
    pub fn from_value(v: &Value) -> Evidence {
        let s = |k: &str| v[k].as_str().unwrap_or("").to_string();
        Evidence {
            record_id: s("record_id"),
            theta: v["theta"].as_f64().unwrap_or(0.0),
            theta_is_number: v["theta"].is_number(),
            result: v["result"].clone(),
            verifier_id: s("verifier_id"),
            timestamp: s("timestamp"),
            provenance: s("provenance"),
            integrity_hash: s("integrity_hash"),
            key_id: s("key_id"),
            signature: s("signature"),
        }
    }
}

fn tier(state: &str) -> i32 {
    match state {
        "RAW" => 0,
        "VALIDATED" => 1,
        "VERIFIED" => 2,
        "COMMITTED" => 3,
        _ => -1,
    }
}

fn kind_of(b: &Value) -> String {
    b["kind"].as_str().unwrap_or("state_gate").to_string()
}

fn rid(b: &Value) -> String {
    b["requirement_id"].as_str().unwrap_or("").to_string()
}

// ---------------------------------------------------------------------------
// Verifier registry and signed evidence (CANON-SIG-011); mirrors registry.py
// ---------------------------------------------------------------------------

struct RegisteredKey {
    public_key: [u8; 32],
    operator: String,
    revoked: bool,
}

pub struct Registry {
    keys: HashMap<String, RegisteredKey>,
    /// SHA-256 hex of the registry file bytes.
    pub digest: String,
}

fn sha256_hex(data: &[u8]) -> String {
    Sha256::digest(data).iter().map(|b| format!("{:02x}", b)).collect()
}

/// Standard base64 with padding; None unless `s` is its canonical encoding.
fn b64decode_strict(s: &str) -> Option<Vec<u8>> {
    let raw = B64.decode(s).ok()?;
    if B64.encode(&raw) == s { Some(raw) } else { None }
}

impl Registry {
    pub fn from_bytes(data: &[u8]) -> Result<Registry, String> {
        let doc: Value = serde_json::from_slice(data).map_err(|e| format!("registry is not valid JSON: {}", e))?;
        if doc["registry_version"].as_i64() != Some(1) {
            return Err("registry_version must be 1".into());
        }
        let entries = doc["verifiers"].as_array().ok_or("'verifiers' must be a list")?;
        let mut keys = HashMap::new();
        let mut seen_public: HashSet<[u8; 32]> = HashSet::new();
        for (i, v) in entries.iter().enumerate() {
            let pk: [u8; 32] = v["public_key"]
                .as_str()
                .and_then(b64decode_strict)
                .and_then(|raw| raw.try_into().ok())
                .ok_or(format!("verifiers[{}].public_key must be base64 of 32 bytes", i))?;
            let kid = sha256_hex(&pk)[..16].to_string();
            if v["key_id"].as_str() != Some(kid.as_str()) {
                return Err(format!("verifiers[{}].key_id does not match its public_key", i));
            }
            let operator = v["operator"].as_str().filter(|s| !s.is_empty())
                .ok_or(format!("verifiers[{}].operator must be a non-empty string", i))?;
            let revoked = match &v["revoked"] {
                Value::Null => false,
                Value::Bool(b) => *b,
                _ => return Err(format!("verifiers[{}].revoked must be true or false", i)),
            };
            if keys.contains_key(&kid) || !seen_public.insert(pk) {
                return Err(format!("verifiers[{}] duplicates an earlier key", i));
            }
            keys.insert(kid, RegisteredKey { public_key: pk, operator: operator.to_string(), revoked });
        }
        Ok(Registry { keys, digest: sha256_hex(data) })
    }
}

/// The exact bytes a verifier signs; None if the Record is malformed.
pub fn signing_message(artifact_id: &str, e: &Evidence) -> Option<Vec<u8>> {
    let text = [artifact_id, &e.record_id, &e.timestamp, &e.provenance, &e.integrity_hash];
    if text.iter().any(|s| s.contains('\n') || s.contains('\r')) {
        return None;
    }
    if !e.theta_is_number || !e.theta.is_finite() {
        return None;
    }
    let theta = format!("{:.6}", e.theta);
    if theta.parse::<f64>().ok()? != e.theta {
        return None;
    }
    let result = match &e.result {
        Value::Bool(true) => "true",
        Value::Bool(false) => "false",
        Value::Null => "null",
        _ => return None,
    };
    let lines = [
        "gravit-evidence-v1", artifact_id, &e.record_id, &theta, result,
        &e.timestamp, &e.provenance, &e.integrity_hash,
    ];
    Some(lines.join("\n").into_bytes())
}

fn exclusion_reason(registry: &Registry, artifact_id: &str, e: &Evidence) -> Option<&'static str> {
    if e.key_id.is_empty() || e.signature.is_empty() {
        return Some("unsigned");
    }
    let key = match registry.keys.get(&e.key_id) {
        None => return Some("unknown_key"),
        Some(k) => k,
    };
    if key.revoked {
        return Some("revoked_key");
    }
    let message = match signing_message(artifact_id, e) {
        None => return Some("malformed"),
        Some(m) => m,
    };
    let sig: [u8; 64] = match b64decode_strict(&e.signature).and_then(|raw| raw.try_into().ok()) {
        None => return Some("bad_signature"),
        Some(s) => s,
    };
    // Like Python, a key that is not a valid curve point loads fine but
    // never verifies.
    let ok = VerifyingKey::from_bytes(&key.public_key)
        .map(|vk| vk.verify(&message, &Signature::from_bytes(&sig)).is_ok())
        .unwrap_or(false);
    if ok { None } else { Some("bad_signature") }
}

struct Screening<'a> {
    admissible: Vec<(&'a Evidence, &'a str)>,
    excluded: Vec<Value>,
}

fn screen<'a>(registry: &'a Registry, artifact_id: &str, evidence: &'a [Evidence]) -> Screening<'a> {
    let mut s = Screening { admissible: Vec::new(), excluded: Vec::new() };
    for e in evidence {
        match exclusion_reason(registry, artifact_id, e) {
            None => s.admissible.push((e, registry.keys[&e.key_id].operator.as_str())),
            Some(reason) => s.excluded.push(json!({ "record_id": e.record_id, "reason": reason })),
        }
    }
    s
}

/// GEVP §10.3 over source representatives: (h > 0.7 && f < 0.3, h, f).
fn convergence(reps: &[&Evidence]) -> (bool, f64, f64) {
    let n = reps.len() as f64;
    let h = reps.iter().filter(|e| e.theta >= 0.7).count() as f64 / n;
    let f = reps.iter().filter(|e| e.theta < 0.5).count() as f64 / n;
    (h > 0.7 && f < 0.3, h, f)
}

fn independent_by_verifier(evidence: &[Evidence]) -> Vec<&Evidence> {
    let refs: Vec<&Evidence> = evidence.iter().collect();
    let ids: Vec<&str> = evidence.iter().map(|e| e.verifier_id.as_str()).collect();
    independent_subset(&refs, &ids)
}

/// One representative Record per independent source (CANON-IND-004).
/// Records sharing an identity (verifier_id, or the registry operator for
/// CANON-SIG-011) or a provenance, directly or through a chain, form one
/// source; each source is represented by its lowest-theta Record.
/// Mirrors `GEVPEvaluator.independent_subset` in kernel.py.
fn independent_subset<'a>(evidence: &[&'a Evidence], identities: &[&str]) -> Vec<&'a Evidence> {
    fn find(parent: &mut [usize], mut i: usize) -> usize {
        while parent[i] != i {
            parent[i] = parent[parent[i]];
            i = parent[i];
        }
        i
    }
    let mut parent: Vec<usize> = (0..evidence.len()).collect();
    let mut first_by_key: HashMap<(&str, &str), usize> = HashMap::new();
    for (i, e) in evidence.iter().enumerate() {
        for key in [("identity", identities[i]), ("provenance", e.provenance.as_str())] {
            let j = *first_by_key.entry(key).or_insert(i);
            let (ri, rj) = (find(&mut parent, i), find(&mut parent, j));
            parent[ri] = rj;
        }
    }
    let mut rep: HashMap<usize, usize> = HashMap::new();
    for (i, e) in evidence.iter().enumerate() {
        let root = find(&mut parent, i);
        match rep.get(&root) {
            Some(&r) if evidence[r].theta <= e.theta => {}
            _ => {
                rep.insert(root, i);
            }
        }
    }
    let mut idx: Vec<usize> = rep.into_values().collect();
    idx.sort_unstable();
    idx.into_iter().map(|i| evidence[i]).collect()
}

/// GEVP evaluator: returns (ok, metrics).
fn gevp_evaluate(binding: &Value, evidence: &[Evidence]) -> (bool, Value) {
    let required = binding["verification_condition"]["required_verification_state"]
        .as_str()
        .unwrap_or("");
    match required {
        "COMMITTED" => {
            let ind = independent_by_verifier(evidence);
            if ind.len() < 2 {
                return (false, json!({ "independent_records": ind.len() }));
            }
            let (ok, h, f) = convergence(&ind);
            (ok, json!({ "h": h, "f": f, "independent_records": ind.len() }))
        }
        "VERIFIED" | "VALIDATED" => (
            !evidence.is_empty(),
            json!({ "record_count": evidence.len() }),
        ),
        "RAW" => (true, json!({ "record_count": evidence.len() })),
        _ => (false, json!({})),
    }
}

/// VEDS classifier: first state in priority order that the binding allows.
fn classify(binding: &Value, gevp_ok: bool) -> Option<Epistemic> {
    if !gevp_ok {
        return None;
    }
    let allowed: Vec<&str> = binding["policy_obligation"]["allowed_epistemic_states"]
        .as_array()
        .map(|a| a.iter().filter_map(|x| x.as_str()).collect())
        .unwrap_or_default();
    [
        Epistemic::Fact,
        Epistemic::Probabilistic,
        Epistemic::Speculative,
        Epistemic::Validated,
        Epistemic::Raw,
    ]
    .into_iter()
    .find(|s| allowed.contains(&s.name()))
}

struct ConstraintResult {
    ok: bool,
    reason: String,
    informative: bool,
    /// Cap the state here instead of stepping one rung down (CANON-SIG-011).
    cap: Option<Epistemic>,
    metrics: Map<String, Value>,
}

impl ConstraintResult {
    fn check(ok: bool, reason: &str) -> ConstraintResult {
        ConstraintResult {
            ok,
            reason: if ok { String::new() } else { reason.into() },
            informative: false,
            cap: None,
            metrics: Map::new(),
        }
    }
}

/// CANON-SIG-011; mirrors ConstraintEvaluator._signed_evidence.
fn signed_evidence(tentative: Option<Epistemic>, screening: Option<&Screening>) -> ConstraintResult {
    if tentative != Some(Epistemic::Fact) {
        return ConstraintResult::check(true, "");
    }
    let mut metrics = Map::new();
    let s = match screening {
        None => {
            metrics.insert("registry".into(), json!(false));
            return ConstraintResult {
                cap: Some(Epistemic::Probabilistic),
                metrics,
                ..ConstraintResult::check(false, "no verifier registry loaded; Verified Fact requires signed evidence")
            };
        }
        Some(s) => s,
    };
    let records: Vec<&Evidence> = s.admissible.iter().map(|(e, _)| *e).collect();
    let operators: Vec<&str> = s.admissible.iter().map(|(_, op)| *op).collect();
    let sources = independent_subset(&records, &operators);
    metrics.insert("registry".into(), json!(true));
    metrics.insert("admissible_records".into(), json!(records.len()));
    metrics.insert("independent_sources".into(), json!(sources.len()));
    let mut ok = false;
    if sources.len() >= 2 {
        let (conv, h, f) = convergence(&sources);
        ok = conv;
        metrics.insert("h".into(), json!(h));
        metrics.insert("f".into(), json!(f));
    }
    ConstraintResult {
        cap: Some(Epistemic::Probabilistic),
        metrics,
        ..ConstraintResult::check(ok, "signed evidence from independent operators does not converge")
    }
}

fn constraint_evaluate(
    id: &str,
    evidence: &[Evidence],
    high_impact: bool,
    tentative: Option<Epistemic>,
    screening: Option<&Screening>,
) -> ConstraintResult {
    let pass = ConstraintResult::check(true, "");
    match id {
        "CANON-IND-004" => {
            let ok = tentative != Some(Epistemic::Fact) || independent_by_verifier(evidence).len() >= 2;
            ConstraintResult::check(ok, "records not independently produced")
        }
        "CANON-FRS-005" => {
            let ok = evidence.iter().all(|e| !e.timestamp.is_empty());
            ConstraintResult::check(ok, "evidence missing Freshness Bound timestamp")
        }
        "CANON-PRV-006" => {
            if !high_impact {
                return pass;
            }
            let ok = evidence
                .iter()
                .all(|e| !e.integrity_hash.is_empty() && !e.provenance.is_empty());
            ConstraintResult::check(ok, "high-impact decision lacks strong provenance binding")
        }
        "CANON-SIG-011" => signed_evidence(tentative, screening),
        "CANON-NSD-007" => ConstraintResult { informative: true, ..pass },
        _ => pass,
    }
}

/// Full verify pipeline. `bindings` is the array from tests/golden/bindings.json.
/// Returns the DecisionRecord as JSON WITHOUT `decision_id` (non-deterministic in Python).
pub fn verify(
    bindings: &[Value],
    artifact_id: &str,
    claimed: Option<Epistemic>,
    evidence: &[Evidence],
    high_impact: bool,
    registry: Option<&Registry>,
) -> Value {
    let screening = registry.map(|r| screen(r, artifact_id, evidence));
    let normative: Vec<&Value> = bindings
        .iter()
        .filter(|b| b["status"].as_str() == Some("normative"))
        .collect();
    let gates: Vec<&Value> = normative.iter().copied().filter(|b| kind_of(b) == "state_gate").collect();
    let constraints: Vec<&Value> = normative.iter().copied().filter(|b| kind_of(b) == "constraint").collect();

    let mut gevp_metrics: Vec<(String, Value)> = Vec::new();
    let mut classifications: HashMap<String, Epistemic> = HashMap::new();
    for b in &gates {
        let (ok, metrics) = gevp_evaluate(b, evidence);
        gevp_metrics.push((rid(b), metrics));
        if let Some(s) = classify(b, ok) {
            classifications.insert(rid(b), s);
        }
    }

    // Highest tier first; sort_by is stable (matches Python's sorted(reverse=True)).
    let mut ranked = gates.clone();
    ranked.sort_by(|a, b| {
        let ta = tier(a["verification_condition"]["required_verification_state"].as_str().unwrap_or(""));
        let tb = tier(b["verification_condition"]["required_verification_state"].as_str().unwrap_or(""));
        tb.cmp(&ta)
    });
    let mut achieved: Option<Epistemic> = None;
    let mut winning: Option<String> = None;
    for b in &ranked {
        if let Some(s) = classifications.get(&rid(b)) {
            achieved = Some(*s);
            winning = Some(rid(b));
            break;
        }
    }
    let tentative = achieved;

    let mut constraint_results: Vec<(String, ConstraintResult)> = Vec::new();
    for c in &constraints {
        let id = rid(c);
        let r = constraint_evaluate(&id, evidence, high_impact, tentative, screening.as_ref());
        let mut m = r.metrics.clone();
        m.insert("constraint_ok".into(), json!(r.ok));
        gevp_metrics.push((id.clone(), Value::Object(m)));
        constraint_results.push((id, r));
    }

    let mut reasons: Vec<String> = Vec::new();
    if achieved.is_none() {
        reasons.push("no state_gate Binding's verification condition was satisfied".to_string());
    }
    let mut demoted = false;
    for (id, r) in &constraint_results {
        if r.informative {
            continue;
        }
        if !r.ok && achieved.is_some() {
            if let Some(cap) = r.cap {
                if achieved.map_or(false, |a| a.order() > cap.order()) {
                    demoted = true;
                    reasons.push(format!("{}: {}", id, r.reason));
                    achieved = Some(cap);
                }
                continue;
            }
            demoted = true;
            reasons.push(format!("{}: {}", id, r.reason));
            achieved = achieved.and_then(|s| s.demoted());
        }
    }

    let status = match (achieved, claimed) {
        (None, _) => "REJECTED",
        (Some(_), None) => "SUCCESS",
        (Some(a), Some(c)) if a == c => if demoted { "DEGRADED" } else { "SUCCESS" },
        (Some(a), Some(c)) if a.order() < c.order() => {
            reasons.push(format!(
                "claimed '{}' not justified by evidence; capped at '{}'",
                c.name(),
                a.name()
            ));
            "DEGRADED"
        }
        (Some(_), Some(_)) => "SUCCESS",
    };

    let all: Vec<&Value> = gates.iter().chain(constraints.iter()).copied().collect();

    let mut reverse_trace: Vec<Value> = Vec::new();
    for b in &all {
        let id = rid(b);
        let achieved_name = classifications.get(&id).map(|s| s.name()).unwrap_or("None");
        let desc = b["policy_obligation"]["description"].as_str().unwrap_or("").trim().to_string();
        let obligation = if desc.is_empty() {
            String::new()
        } else {
            format!("{}...", desc.chars().take(120).collect::<String>())
        };
        let cref = b["canonical_reference"][0].as_str().unwrap_or("unknown").to_string();
        let is_win = if winning.as_deref() == Some(id.as_str()) { "True" } else { "False" };
        for ev in evidence {
            reverse_trace.push(json!({
                "evidence_id": ev.record_id,
                "binding_id": id,
                "canon_reference": cref,
                "policy_obligation": obligation,
                "achieved_state": achieved_name,
                "is_winning_gate": is_win,
            }));
        }
    }

    let canon_trace: Vec<Value> = all
        .iter()
        .filter_map(|b| b["canonical_reference"][0].as_str().map(|s| json!(s)))
        .collect();

    let mut metrics = Map::new();
    for (k, v) in gevp_metrics {
        metrics.insert(k, v);
    }

    let reason = if reasons.is_empty() {
        "All applicable Bindings satisfied".to_string()
    } else {
        reasons.join("; ")
    };
    let requirement_ids: Vec<String> = all.iter().map(|b| rid(b)).collect();
    let evidence_ids: Vec<String> = evidence.iter().map(|e| e.record_id.clone()).collect();
    let final_state: Option<&str> = achieved.map(|s| s.name());

    json!({
        "requirement_ids": requirement_ids,
        "final_epistemic_state": final_state,
        "status": status,
        "evidence_ids": evidence_ids,
        "convergence_metrics": Value::Object(metrics),
        "canon_trace": canon_trace,
        "reverse_trace": reverse_trace,
        "reason": reason,
        "c_down": achieved.is_some() && status != "REJECTED",
        "c_up": winning.is_some(),
        "excluded_evidence": screening.map(|s| s.excluded).unwrap_or_default(),
        "registry_digest": registry.map(|r| r.digest.clone()),
    })
}
