"""Generate language-neutral golden vectors from the Python reference kernel.

Output: tests/golden/vectors.json  (inputs + expected DecisionRecord, minus the
non-deterministic decision_id) and tests/golden/bindings.json (the YAML
bindings as JSON, so a port needs only a JSON parser).
Any port (Rust, etc.) must reproduce `expected` exactly for every case.
"""
import json, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from gravit_verifier.kernel import VerifierKernel, VerificationRequest, EvidenceRecord, EpistemicState
from gravit_verifier.loader import load_bindings_from_dir

TS = "2026-09-06T12:00:00Z"
def ev(i, theta, v, p, h="h", ts=TS):
    return dict(record_id=f"r{i}", theta=theta, result=True, verifier_id=v,
                timestamp=ts, provenance=p, integrity_hash=h)

CASES = [
 ("committed_two_strong", "Verified Fact", {}, [ev(1,.88,"v1","A"), ev(2,.85,"v2","B")]),
 ("weak_aggregation_three", "Verified Fact", {}, [ev(1,.61,"v1","A"), ev(2,.58,"v2","B"), ev(3,.55,"v3","C")]),
 ("single_high_theta", "Verified Fact", {}, [ev(1,.94,"v1","A")]),
 ("no_evidence_no_claim", None, {}, []),
 ("no_evidence_claims_fact", "Verified Fact", {}, []),
 ("no_claim_strong_evidence", None, {}, [ev(1,.9,"v1","A"), ev(2,.9,"v2","B")]),
 ("claims_lower_than_achieved", "Speculative Claim", {}, [ev(1,.9,"v1","A"), ev(2,.9,"v2","B")]),
 ("duplicate_verifier_provenance", "Verified Fact", {}, [ev(1,.9,"v1","A"), ev(2,.9,"v1","A")]),
 ("same_verifier_diff_provenance", "Verified Fact", {}, [ev(1,.9,"v1","A"), ev(2,.9,"v1","B")]),
 # CANON-IND-004: sharing a verifier-id OR a provenance root (even via a chain) = one source
 ("same_provenance_diff_verifier", "Verified Fact", {}, [ev(1,.9,"v1","A"), ev(2,.9,"v2","A")]),
 ("chain_shared_keys_one_source", "Verified Fact", {},
    [ev(1,.9,"v1","A"), ev(2,.9,"v2","A"), ev(3,.9,"v2","B"), ev(4,.9,"v3","B")]),
 ("two_sources_with_duplicates", "Verified Fact", {}, [ev(1,.9,"v1","A"), ev(2,.9,"v1","A"), ev(3,.9,"v2","B")]),
 ("weak_record_drags_source_down", "Verified Fact", {},
    [ev(1,.9,"v1","A"), ev(2,.4,"v1","B"), ev(3,.9,"v2","C"), ev(4,.9,"v3","D")]),
 ("weak_record_drags_source_down_reversed", "Verified Fact", {},
    [ev(4,.9,"v3","D"), ev(3,.9,"v2","C"), ev(2,.4,"v1","B"), ev(1,.9,"v1","A")]),
 ("boundary_h_075_f_025_passes", "Verified Fact", {}, [ev(1,.7,"v1","A"), ev(2,.8,"v2","B"), ev(3,.9,"v3","C"), ev(4,.4,"v4","D")]),
 ("boundary_h_exactly_070_fails", "Verified Fact", {},
    [ev(i,t,f"v{i}",f"P{i}") for i,t in enumerate([.7,.7,.7,.7,.7,.7,.7,.6,.6,.6],1)]),
 ("boundary_h_070_f_030_fails", "Verified Fact", {},
    [ev(i,t,f"v{i}",f"P{i}") for i,t in enumerate([.9]*7+[.4]*3,1)]),
 ("theta_exactly_07_counts_honest", "Verified Fact", {}, [ev(1,.7,"v1","A"), ev(2,.7,"v2","B")]),
 ("missing_timestamp_demotes", "Verified Fact", {}, [ev(1,.9,"v1","A",ts=""), ev(2,.9,"v2","B")]),
 ("high_impact_missing_hash", "Verified Fact", {"high_impact": True}, [ev(1,.9,"v1","A",h=""), ev(2,.9,"v2","B")]),
 ("high_impact_ok", "Verified Fact", {"high_impact": True}, [ev(1,.9,"v1","A"), ev(2,.9,"v2","B")]),
 ("not_high_impact_missing_hash_ok", "Verified Fact", {}, [ev(1,.9,"v1","A",h=""), ev(2,.9,"v2","B")]),
 ("two_records_low_theta_claims_prob", "Probabilistic Assessment", {}, [ev(1,.3,"v1","A"), ev(2,.2,"v2","B")]),
]

def build_kernel():
    k = VerifierKernel()
    for b in load_bindings_from_dir(ROOT / "bindings"):
        k.load_binding(b)
    return k

def main():
    k = build_kernel()
    vectors = []
    for name, claim, ctx, evidence in CASES:
        req = VerificationRequest(
            artifact_id=name,
            claimed_state=EpistemicState(claim) if claim else None,
            evidence=[EvidenceRecord(**e) for e in evidence],
            context=ctx)
        d = k.verify(req).to_dict(); d.pop("decision_id")
        # determinism check: second run must be identical
        d2 = k.verify(req).to_dict(); d2.pop("decision_id")
        assert d == d2, f"non-deterministic: {name}"
        vectors.append(dict(name=name, claimed_state=claim, context=ctx,
                            evidence=evidence, expected=d))
    out = ROOT / "tests" / "golden"
    (out / "vectors.json").write_text(json.dumps(vectors, indent=1, ensure_ascii=False, sort_keys=True), encoding="utf-8")
    (out / "bindings.json").write_text(json.dumps(load_bindings_from_dir(ROOT / "bindings"), indent=1, ensure_ascii=False, sort_keys=True, default=str), encoding="utf-8")
    print(f"wrote {len(vectors)} vectors")
    for v in vectors:
        e = v["expected"]
        print(f"  {v['name']:38s} -> {str(e['final_epistemic_state']):26s} {e['status']}")
main()
