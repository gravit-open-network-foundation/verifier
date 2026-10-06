//! Rust port of `gravit_verifier/kernel.py` (Python is the reference).
//!
//! STATUS: `cargo test` reproduces all vectors in
//! `../tests/golden/vectors.json` (23/23 checked 2026-10-06, rustc 1.99.0); it
//! conforms only while that keeps passing. Known intentional divergence: an unknown
//! `required_verification_state` sorts last here (Python raises ValueError).

use serde_json::{json, Map, Value};
use std::collections::HashMap;

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
    pub verifier_id: String,
    pub timestamp: String,
    pub provenance: String,
    pub integrity_hash: String,
}

impl Evidence {
    pub fn from_value(v: &Value) -> Evidence {
        let s = |k: &str| v[k].as_str().unwrap_or("").to_string();
        Evidence {
            record_id: s("record_id"),
            theta: v["theta"].as_f64().unwrap_or(0.0),
            verifier_id: s("verifier_id"),
            timestamp: s("timestamp"),
            provenance: s("provenance"),
            integrity_hash: s("integrity_hash"),
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

/// One representative Record per independent source (CANON-IND-004).
/// Records sharing a verifier_id or a provenance, directly or through a chain,
/// form one source; each source is represented by its lowest-theta Record.
/// Mirrors `GEVPEvaluator.independent_subset` in kernel.py.
fn independent_subset(evidence: &[Evidence]) -> Vec<&Evidence> {
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
        for key in [("verifier_id", e.verifier_id.as_str()), ("provenance", e.provenance.as_str())] {
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
    idx.into_iter().map(|i| &evidence[i]).collect()
}

/// GEVP evaluator: returns (ok, metrics).
fn gevp_evaluate(binding: &Value, evidence: &[Evidence]) -> (bool, Value) {
    let required = binding["verification_condition"]["required_verification_state"]
        .as_str()
        .unwrap_or("");
    match required {
        "COMMITTED" => {
            let ind = independent_subset(evidence);
            if ind.len() < 2 {
                return (false, json!({ "independent_records": ind.len() }));
            }
            let n = ind.len() as f64;
            let h = ind.iter().filter(|e| e.theta >= 0.7).count() as f64 / n;
            let f = ind.iter().filter(|e| e.theta < 0.5).count() as f64 / n;
            let ok = h > 0.7 && f < 0.3;
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
}

fn constraint_evaluate(
    id: &str,
    evidence: &[Evidence],
    high_impact: bool,
    tentative: Option<Epistemic>,
) -> ConstraintResult {
    let pass = ConstraintResult { ok: true, reason: String::new(), informative: false };
    match id {
        "CANON-IND-004" => {
            let ok = if tentative == Some(Epistemic::Fact) {
                independent_subset(evidence).len() >= 2
            } else {
                true
            };
            ConstraintResult {
                ok,
                reason: if ok { String::new() } else { "records not independently produced".into() },
                informative: false,
            }
        }
        "CANON-FRS-005" => {
            let ok = evidence.iter().all(|e| !e.timestamp.is_empty());
            ConstraintResult {
                ok,
                reason: if ok { String::new() } else { "evidence missing Freshness Bound timestamp".into() },
                informative: false,
            }
        }
        "CANON-PRV-006" => {
            if !high_impact {
                return pass;
            }
            let ok = evidence
                .iter()
                .all(|e| !e.integrity_hash.is_empty() && !e.provenance.is_empty());
            ConstraintResult {
                ok,
                reason: if ok { String::new() } else { "high-impact decision lacks strong provenance binding".into() },
                informative: false,
            }
        }
        "CANON-NSD-007" => ConstraintResult { ok: true, reason: String::new(), informative: true },
        _ => pass,
    }
}

/// Full verify pipeline. `bindings` is the array from tests/golden/bindings.json.
/// Returns the DecisionRecord as JSON WITHOUT `decision_id` (non-deterministic in Python).
pub fn verify(
    bindings: &[Value],
    claimed: Option<Epistemic>,
    evidence: &[Evidence],
    high_impact: bool,
) -> Value {
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
        let r = constraint_evaluate(&id, evidence, high_impact, tentative);
        gevp_metrics.push((id.clone(), json!({ "constraint_ok": r.ok })));
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
    })
}
