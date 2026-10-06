"""Generate language-neutral golden vectors from the Python reference kernel.

Output: tests/golden/vectors.json  (inputs + expected DecisionRecord, minus the
content-addressed decision_id), tests/golden/bindings.json (the YAML
bindings as JSON, so a port needs only a JSON parser), tests/golden/registry.json
(a verifier registry of TEST keys) with its root signatures registry.json.sig,
tests/golden/trust_root.json (5 TEST root keys, threshold 3) and
examples/artifact_signed.json.
Any port (Rust, etc.) must reproduce `expected` exactly for every case.

Test keys are derived from fixed public seeds below. They are not secret and
must never be used outside tests. Ed25519 signatures are deterministic, so the
output is byte-stable.
"""
import base64, hashlib, json, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from gravit_verifier.kernel import VerifierKernel, VerificationRequest, EvidenceRecord, EpistemicState
from gravit_verifier.loader import load_bindings_from_dir
from gravit_verifier.registry import (
    TrustRoot, VerifierRegistry, key_id_for, registry_signing_message, signing_message,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

TS = "2026-09-06T12:00:00Z"
AUTO = object()  # sign with the key named like the verifier_id

def ev(i, theta, v, p, h="h", ts=TS, key=AUTO, sign_for=None, tamper=None, sig=None):
    """key: key name, AUTO (= v) or None (unsigned). sign_for: artifact_id to
    sign for (default: the case name). tamper: fields changed AFTER signing.
    sig: literal signature instead of a real one."""
    rec = dict(record_id=f"r{i}", theta=theta, result=True, verifier_id=v,
               timestamp=ts, provenance=p, integrity_hash=h)
    rec["_sign"] = dict(key=v if key is AUTO else key, sign_for=sign_for, tamper=tamper or {}, sig=sig)
    return rec

# --- test keys and registry -------------------------------------------------
def test_key(name):
    return Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b"gravit-test-key:" + name.encode()).digest())

def raw_public(sk):
    return sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

# key name -> (operator, revoked). v1b shares operator op-v1 with v1.
REGISTERED = {**{f"v{n}": (f"op-v{n}", False) for n in range(1, 11)},
              "v1b": ("op-v1", False),
              "vR": ("op-revoked", True)}
KEYS = {name: test_key(name) for name in [*REGISTERED, "ghost"]}  # ghost: not registered

def registry_bytes():
    entries = [dict(key_id=key_id_for(raw_public(KEYS[n])),
                    public_key=base64.b64encode(raw_public(KEYS[n])).decode(),
                    operator=op, revoked=rev) for n, (op, rev) in REGISTERED.items()]
    doc = dict(registry_version=1, verifiers=entries)
    return (json.dumps(doc, indent=1, sort_keys=True) + "\n").encode("utf-8")

def finish_record(artifact_id, rec):
    """Turn an ev() spec into a plain (possibly signed) record dict."""
    spec = rec.pop("_sign")
    if spec["key"] is not None:
        sk = KEYS[spec["key"]]
        rec["key_id"] = key_id_for(raw_public(sk))
        if spec["sig"] is not None:
            rec["signature"] = spec["sig"]
        else:
            msg = signing_message(spec["sign_for"] or artifact_id, EvidenceRecord(**rec))
            rec["signature"] = base64.b64encode(sk.sign(msg)).decode()
    rec.update(spec["tamper"])
    return rec

DUMMY_SIG = base64.b64encode(bytes(64)).decode()

# --- test trust root: 5 root keys, threshold 3; roots 1, 3, 5 sign ----------
ROOTS = {f"root-{n}": test_key(f"root-{n}") for n in range(1, 6)}
ROOT_SIGNERS = ["root-1", "root-3", "root-5"]

def trust_root_bytes():
    entries = [dict(key_id=key_id_for(raw_public(sk)), public_key=base64.b64encode(raw_public(sk)).decode())
               for sk in ROOTS.values()]
    doc = dict(trust_root_version=1, threshold=3, root_keys=entries)
    return (json.dumps(doc, indent=1, sort_keys=True) + "\n").encode("utf-8")

def registry_signatures(reg_bytes):
    msg = registry_signing_message(reg_bytes)
    return "".join(f"{key_id_for(raw_public(ROOTS[n]))} {base64.b64encode(ROOTS[n].sign(msg)).decode()}\n"
                   for n in ROOT_SIGNERS)

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
# All cases above run WITH the test registry (their meaning is unchanged).
# CANON-SIG-011 cases: (name, claim, ctx, evidence, use_registry)
SIG_CASES = [
 ("no_registry_caps_at_prob", "Verified Fact", {}, [ev(1,.9,"v1","A"), ev(2,.9,"v2","B")], False),
 # FRS-005 already steps VF down to PA; the SIG-011 cap must not demote it again
 ("no_registry_missing_timestamp_not_stacked", "Verified Fact", {}, [ev(1,.9,"v1","A",ts=""), ev(2,.9,"v2","B")], False),
 ("unsigned_record_excluded", "Verified Fact", {}, [ev(1,.9,"v1","A"), ev(2,.9,"v2","B",key=None)], True),
 ("unknown_key_excluded", "Verified Fact", {}, [ev(1,.9,"v1","A"), ev(2,.9,"v2","B",key="ghost")], True),
 ("revoked_key_excluded", "Verified Fact", {}, [ev(1,.9,"v1","A"), ev(2,.9,"vR","B")], True),
 ("tampered_theta_bad_signature", "Verified Fact", {}, [ev(1,.9,"v1","A"), ev(2,.9,"v2","B",tamper={"theta":.95})], True),
 ("replayed_from_other_artifact", "Verified Fact", {},
    [ev(1,.9,"v1","A"), ev(2,.9,"v2","B",sign_for="committed_two_strong")], True),
 ("malformed_theta_precision", "Verified Fact", {}, [ev(1,.9,"v1","A"), ev(2,.9000001,"v2","B",sig=DUMMY_SIG)], True),
 ("two_keys_one_operator", "Verified Fact", {}, [ev(1,.9,"v1","A"), ev(2,.9,"v1b","B")], True),
 ("one_bad_record_others_converge", "Verified Fact", {},
    [ev(1,.9,"v1","A"), ev(2,.9,"v2","B"), ev(3,.9,"v3","C",tamper={"provenance":"Z"})], True),
]
# CANON-FRS-005 with a Freshness Bound policy in the context (v0.5.0)
FRESH = {"evaluation_time": "2026-09-06T13:00:00Z", "freshness_max_age_seconds": 3600}
FRESH_CASES = [
 ("fresh_age_equals_bound_passes", "Verified Fact", FRESH, [ev(1,.9,"v1","A"), ev(2,.9,"v2","B")], True),
 ("stale_by_one_second_demotes", "Verified Fact", FRESH,
    [ev(1,.9,"v1","A",ts="2026-09-06T11:59:59Z"), ev(2,.9,"v2","B")], True),
 ("future_timestamp_demotes", "Verified Fact", FRESH,
    [ev(1,.9,"v1","A",ts="2026-09-06T13:00:01Z"), ev(2,.9,"v2","B")], True),
 ("timestamp_wrong_format_demotes", "Verified Fact", FRESH,
    [ev(1,.9,"v1","A",ts="2026-09-06 12:00:00Z"), ev(2,.9,"v2","B")], True),
 ("timestamp_impossible_date_demotes", "Verified Fact", FRESH,
    [ev(1,.9,"v1","A",ts="2026-02-29T12:00:00Z"), ev(2,.9,"v2","B")], True),
 ("leap_day_across_month_passes", "Verified Fact",
    {"evaluation_time": "2028-03-01T11:00:00Z", "freshness_max_age_seconds": 86400},
    [ev(1,.9,"v1","A",ts="2028-02-29T12:00:00Z"), ev(2,.9,"v2","B",ts="2028-03-01T10:00:00Z")], True),
 ("freshness_policy_incomplete_demotes", "Verified Fact", {"evaluation_time": "2026-09-06T13:00:00Z"},
    [ev(1,.9,"v1","A"), ev(2,.9,"v2","B")], True),
]

def build_kernel(registry=None):
    k = VerifierKernel(registry)
    for b in load_bindings_from_dir(ROOT / "bindings"):
        k.load_binding(b)
    return k

def main():
    out = ROOT / "tests" / "golden"
    reg_bytes, root_bytes = registry_bytes(), trust_root_bytes()
    reg_sigs = registry_signatures(reg_bytes)
    (out / "registry.json").write_bytes(reg_bytes)
    (out / "registry.json.sig").write_text(reg_sigs, encoding="utf-8")
    (out / "trust_root.json").write_bytes(root_bytes)
    registry = VerifierRegistry.from_bytes(reg_bytes, reg_sigs, TrustRoot.from_bytes(root_bytes))
    kernels = {True: build_kernel(registry), False: build_kernel()}
    vectors = []
    for name, claim, ctx, evidence, use_registry in [(*c, True) for c in CASES] + SIG_CASES + FRESH_CASES:
        evidence = [finish_record(name, dict(e)) for e in evidence]
        req = VerificationRequest(
            artifact_id=name,
            claimed_state=EpistemicState(claim) if claim else None,
            evidence=[EvidenceRecord(**e) for e in evidence],
            context=ctx)
        k = kernels[use_registry]
        d = k.verify(req).to_dict()
        # determinism check: second run must be identical, decision_id included
        d2 = k.verify(req).to_dict()
        assert d == d2, f"non-deterministic: {name}"
        vectors.append(dict(name=name, claimed_state=claim, context=ctx, use_registry=use_registry,
                            evidence=evidence, expected=d))
    example = dict(artifact_id="agent-knowledge-signed", claimed_state="Verified Fact",
                   evidence=[finish_record("agent-knowledge-signed", ev(1,.87,"v1","agent-A",h="6f1ed002ab5595859014ebf0951522d9")),
                             finish_record("agent-knowledge-signed", ev(2,.84,"v2","agent-B",h="a3c9e1f07b2d4458c6e9f1a2b3c4d5e6"))])
    (ROOT / "examples" / "artifact_signed.json").write_text(json.dumps(example, indent=2) + "\n", encoding="utf-8")
    (out / "vectors.json").write_text(json.dumps(vectors, indent=1, ensure_ascii=False, sort_keys=True), encoding="utf-8")
    (out / "bindings.json").write_text(json.dumps(load_bindings_from_dir(ROOT / "bindings"), indent=1, ensure_ascii=False, sort_keys=True, default=str), encoding="utf-8")
    print(f"wrote {len(vectors)} vectors")
    for v in vectors:
        e = v["expected"]
        print(f"  {v['name']:40s} -> {str(e['final_epistemic_state']):26s} {e['status']}")
main()
