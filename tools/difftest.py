"""Differential test: random mutations of the 56 golden vectors, run through
the Python reference kernel and the Rust port, DecisionRecords compared.

usage: python difftest.py <repo> <n> <seed> <outdir>
Deterministic for a given seed. Writes cases.json, rust.jsonl, report.json,
and mismatches.json (inputs + both outputs) for every difference."""
import copy, json, math, random, subprocess, sys, time
from pathlib import Path

REPO, N, SEED, OUT = Path(sys.argv[1]).resolve(), int(sys.argv[2]), int(sys.argv[3]), Path(sys.argv[4])
sys.path.insert(0, str(REPO))
from gravit_verifier.kernel import VerifierKernel, VerificationRequest, EvidenceRecord, EpistemicState
from gravit_verifier.loader import load_bindings_from_dir
from gravit_verifier.registry import TrustRoot, VerifierRegistry

G = REPO / "tests/golden"
root = TrustRoot.from_file(G / "trust_root.json")
registry = VerifierRegistry.from_file(G / "registry.json", root)
kernels = {True: VerifierKernel(registry), False: VerifierKernel()}
for k in kernels.values():
    for b in load_bindings_from_dir(REPO / "bindings"):
        k.load_binding(b)
golden = json.loads((G / "vectors.json").read_text(encoding="utf-8"))
STATES = sorted({v["claimed_state"] for v in golden if v["claimed_state"]}) + [None]
CONTEXTS = [json.loads(s) for s in sorted({json.dumps(v["context"], sort_keys=True) for v in golden})]
VIDS = sorted({e["verifier_id"] for v in golden for e in v["evidence"]}) + ["v_unknown"]
PROVS = sorted({e["provenance"] for v in golden for e in v["evidence"]}) + ["Z", ""]
TS = sorted({e["timestamp"] for v in golden for e in v["evidence"]})
EDGE = [0.0, 1.0, 0.7, 0.3, 0.6999999999999999, 0.7000000000000001, 0.3000000000000001, 0.5, 1e-9, 1 - 1e-9, 0.1 + 0.2, 2/3]

rng = random.Random(SEED)

def theta():
    r = rng.random()
    if r < 0.4: return rng.choice(EDGE)
    if r < 0.8: return round(rng.random(), rng.choice([1, 2, 3, 6, 15]))
    return rng.random()

def flip_b64(s):
    if not isinstance(s, str) or not s: return s
    i = rng.randrange(len(s) - 2) if len(s) > 2 else 0
    c = "A" if s[i] != "A" else "B"
    return s[:i] + c + s[i + 1:]

def shift_ts(ts):
    choices = TS + ["2026-09-06T12:00:00+00:00", "2026-09-06 12:00:00Z", "2026-02-30T12:00:00Z", "2024-02-29T00:00:00Z",
                    "2026-09-06T12:00:00.5Z", "2026-09-06T23:59:60Z", "not-a-date", ""]
    return rng.choice(choices)

def mutate(v):
    v = copy.deepcopy(v)
    v.pop("expected", None)
    ops = rng.randint(1, 4)
    for _ in range(ops):
        ev = v["evidence"]
        op = rng.choice(["theta", "theta", "result", "vid", "prov", "ts", "sig", "hash", "dup", "drop", "claim", "ctx", "reg", "swap", "rid"])
        if op in ("theta", "result", "vid", "prov", "ts", "sig", "hash", "rid") and not ev:
            op = "claim"
        if op == "theta": rng.choice(ev)["theta"] = theta()
        elif op == "result": e = rng.choice(ev); e["result"] = not e.get("result", True)
        elif op == "vid": rng.choice(ev)["verifier_id"] = rng.choice(VIDS)
        elif op == "prov": rng.choice(ev)["provenance"] = rng.choice(PROVS)
        elif op == "ts": rng.choice(ev)["timestamp"] = shift_ts(None)
        elif op == "sig": e = rng.choice(ev); e["signature"] = flip_b64(e.get("signature"))
        elif op == "hash": rng.choice(ev)["integrity_hash"] = rng.choice(["h", "h2", "6f1ed002ab5595859014ebf0951522d9", ""])
        elif op == "rid": rng.choice(ev)["record_id"] = rng.choice(["r1", "r2", "r3", "r9"])
        elif op == "dup" and ev: ev.append(copy.deepcopy(rng.choice(ev)))
        elif op == "drop" and ev: ev.pop(rng.randrange(len(ev)))
        elif op == "swap" and len(ev) > 1: rng.shuffle(ev)
        elif op == "claim": v["claimed_state"] = rng.choice(STATES)
        elif op == "ctx": v["context"] = copy.deepcopy(rng.choice(CONTEXTS))
        elif op == "reg": v["use_registry"] = not v["use_registry"]
    return v

def py_run(v):
    req = VerificationRequest(v["name"], EpistemicState(v["claimed_state"]) if v["claimed_state"] else None,
                              [EvidenceRecord(**e) for e in v["evidence"]], v["context"])
    return kernels[v["use_registry"]].verify(req).to_dict()

OUT.mkdir(parents=True, exist_ok=True)
t0 = time.time()
cases, py_out, py_err = [], [], 0
while len(cases) < N:
    v = mutate(rng.choice(golden))
    try:
        d = py_run(v)
    except Exception as e:
        py_err += 1
        d = {"python_exception": type(e).__name__ + ": " + str(e)[:200]}
    cases.append(v); py_out.append(d)
t_py = time.time() - t0
(OUT / "cases.json").write_text(json.dumps(cases, ensure_ascii=False), encoding="utf-8")
t1 = time.time()
rust = subprocess.run([str(REPO / "rust/target/release/examples/replay"), str(OUT / "cases.json")], capture_output=True, text=True, check=True)
t_rs = time.time() - t1
(OUT / "rust.jsonl").write_text(rust.stdout, encoding="utf-8")
rs_out = [json.loads(l) for l in rust.stdout.splitlines()]
assert len(rs_out) == N

def norm(x):  # same JSON value model on both sides
    return json.loads(json.dumps(x, sort_keys=True))

mism, kinds, states = [], {}, {}
for i, (c, p, r) in enumerate(zip(cases, py_out, rs_out)):
    if "python_exception" in p:
        k = "python_exception+rust_panic" if "panic" in r else "python_exception_only"
    elif "panic" in r:
        k = "rust_panic_only"
    elif norm(p) != norm(r["got"]):
        k = "different_decision_record"
    else:
        k = "identical"
        s = (p.get("final_epistemic_state"), p.get("status")); states[str(s)] = states.get(str(s), 0) + 1
    kinds[k] = kinds.get(k, 0) + 1
    if k != "identical":
        mism.append({"i": i, "kind": k, "case": c, "python": p, "rust": r})
report = {"seed": SEED, "cases": N, "outcomes": kinds, "identical_by_state_status": states,
          "python_seconds": round(t_py, 2), "rust_seconds": round(t_rs, 2)}
(OUT / "report.json").write_text(json.dumps(report, indent=1, sort_keys=True), encoding="utf-8")
(OUT / "mismatches.json").write_text(json.dumps(mism[:500], indent=1, ensure_ascii=False, sort_keys=True), encoding="utf-8")
print(json.dumps(report, indent=1, sort_keys=True))
