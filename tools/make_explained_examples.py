#!/usr/bin/env python3
"""
Worked example for decision explanations (docs/decision-explanation.md).

Builds a TEST registry in which two operators reference evidence for their
independence (a signed statement, here an illustrative text file) and one does
not, then explains four decisions:

  1. two evidenced operators          -> Verified Fact, independence evidenced
  2. one evidenced, one not           -> Verified Fact, independence partly ASSUMED
  3. two keys of one operator         -> degraded, one source only
  4. no verifier registry             -> NOT EVALUABLE (not an evaluated denial)

All keys derive from public seeds: test fixtures, never for real use.
Writes examples/explained/ ; deterministic, so CI can compare byte for byte.
"""

import base64
import hashlib
import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from gravit_verifier.explain import explain  # noqa: E402
from gravit_verifier.kernel import EpistemicState, EvidenceRecord, VerificationRequest, VerifierKernel  # noqa: E402
from gravit_verifier.loader import load_bindings_from_dir  # noqa: E402
from gravit_verifier.registry import (TrustRoot, VerifierRegistry, key_id_for,  # noqa: E402
                                      registry_signing_message, signing_message)

OUT = ROOT / "examples" / "explained"
TS = "2026-10-12T12:00:00Z"
OPERATORS = {  # key name -> (operator, has evidence)
    "a1": ("Example Operator A AG", True),
    "a2": ("Example Operator A AG", True),
    "b1": ("Example Operator B Ltd", True),
    "c1": ("Example Operator C GmbH", False),
}


def key(name):
    return Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b"gravit-explain-example:" + name.encode()).digest())


def pub(name):
    return key(name).public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def doc(o):
    return (json.dumps(o, indent=1, sort_keys=True) + "\n").encode()


def statement(operator):
    text = (f"TEST FIXTURE - illustrative independence statement\n"
            f"Operator: {operator}\nWe declare that we are not under common control with any other operator "
            f"listed in the registry (ownership, management, or shared signing infrastructure).\n")
    return text.encode()


def build_registry():
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "statements").mkdir(exist_ok=True)
    entries = []
    for name, (op, has_ev) in OPERATORS.items():
        e = {"key_id": key_id_for(pub(name)), "public_key": base64.b64encode(pub(name)).decode(),
             "operator": op, "revoked": False}
        if has_ev:
            fname = "statements/" + op.lower().replace(" ", "-") + ".txt"
            body = statement(op)
            (OUT / fname).write_bytes(body)
            e["independence_evidence"] = [{"type": "independence-statement", "sha256": hashlib.sha256(body).hexdigest(),
                                           "ref": fname}]
        entries.append(e)
    roots = [f"root-{i}" for i in range(1, 6)]
    tr = doc({"trust_root_version": 1, "threshold": 3, "root_keys": [
        {"key_id": key_id_for(pub(r)), "public_key": base64.b64encode(pub(r)).decode()} for r in roots]})
    reg = doc({"registry_version": 1, "verifiers": entries})
    msg = registry_signing_message(reg)
    sigs = "".join(f"{key_id_for(pub(r))} {base64.b64encode(key(r).sign(msg)).decode()}\n" for r in roots[:3])
    (OUT / "trust_root.json").write_bytes(tr)
    (OUT / "registry.json").write_bytes(reg)
    (OUT / "registry.json.sig").write_text(sigs)
    return VerifierRegistry.from_bytes(reg, sigs, TrustRoot.from_bytes(tr))


def record(artifact, name, n, theta):
    op = OPERATORS[name][0]
    r = EvidenceRecord(record_id=f"r{n}", theta=theta, result=True, verifier_id=name, timestamp=TS,
                       provenance=op, integrity_hash="sha3-256-of-the-claim", key_id=key_id_for(pub(name)))
    r.signature = base64.b64encode(key(name).sign(signing_message(artifact, r))).decode()
    return r


def kernel(registry):
    k = VerifierKernel(registry)
    for b in load_bindings_from_dir(ROOT / "bindings"):
        k.load_binding(b)
    return k


def main() -> int:
    reg = build_registry()
    cases = [
        ("case-1-two-evidenced-operators", ["a1", "b1"], True),
        ("case-2-one-operator-assumed", ["a1", "c1"], True),
        ("case-3-two-keys-one-operator", ["a1", "a2"], True),
        ("case-4-no-registry", ["a1", "b1"], False),
    ]
    for name, signers, with_registry in cases:
        req = VerificationRequest(artifact_id=name, claimed_state=EpistemicState.VERIFIED_FACT,
                                  evidence=[record(name, s, i + 1, 0.9 - 0.02 * i) for i, s in enumerate(signers)])
        k = kernel(reg if with_registry else None)
        d = k.verify(req)
        out = {"request": {"artifact_id": req.artifact_id, "claimed_state": req.claimed_state.value,
                           "evidence": [e.__dict__ for e in req.evidence]},
               "decision": d.to_dict(), "explanation": explain(req, d, k)}
        (OUT / f"{name}.json").write_text(json.dumps(out, indent=1, sort_keys=True, ensure_ascii=False) + "\n")
        x = out["explanation"]
        print(f"{name:34} {d.status.value:9} {x['evaluation']['result']:14} {x['independence']['conclusion']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
