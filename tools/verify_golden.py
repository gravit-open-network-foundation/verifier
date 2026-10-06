"""Replay every golden vector through the Python kernel and compare to the
stored expected output (decision_id excluded). Exit 1 on any mismatch."""
import json, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from gravit_verifier.kernel import VerifierKernel, VerificationRequest, EvidenceRecord, EpistemicState
from gravit_verifier.loader import load_bindings_from_dir
from gravit_verifier.registry import VerifierRegistry

registry = VerifierRegistry.from_file(ROOT / "tests/golden/registry.json")
kernels = {True: VerifierKernel(registry), False: VerifierKernel()}
for k in kernels.values():
    for b in load_bindings_from_dir(ROOT / "bindings"): k.load_binding(b)
vectors = json.loads((ROOT / "tests/golden/vectors.json").read_text(encoding="utf-8"))
bad = 0
for v in vectors:
    req = VerificationRequest(v["name"], EpistemicState(v["claimed_state"]) if v["claimed_state"] else None,
                              [EvidenceRecord(**e) for e in v["evidence"]], v["context"])
    got = kernels[v["use_registry"]].verify(req).to_dict(); got.pop("decision_id")
    ok = got == v["expected"]
    bad += (not ok)
    print(("PASS " if ok else "FAIL ") + v["name"])
print(f"\n{len(vectors)-bad}/{len(vectors)} vectors reproduced")
sys.exit(1 if bad else 0)
