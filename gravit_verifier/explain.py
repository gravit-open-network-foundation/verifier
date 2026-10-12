"""
Decision explanation: what a reader needs in order to judge a DecisionRecord.

The kernel's DecisionRecord (and its content-addressed decision_id) is left
unchanged; this module adds an explanation next to it. It answers three
questions a third-party auditor asks:

1. Was the claim actually evaluated, or could the check not be completed?
   ("evaluated" versus "not_evaluable" - an evaluated denial is a different
   fact from a check that was impossible, e.g. without a verifier registry.)
2. Which rules, in which revision, were applied?
3. What does "independent" rest on? Two valid signatures are not proof of two
   independent organisations. The verifier groups records by registry operator
   and by provenance, but the registry is trusted input: signature checks
   cannot detect misrepresented common control or collusion. The explanation
   therefore names the registry and trust-root digests, the grouping rule, the
   independence claim that was evaluated, and for every operator either the
   evidence behind its registry entry (e.g. its signed independence statement)
   or an explicit "assumed, not evidenced" marker.

See docs/decision-explanation.md.
"""

import hashlib
import json
from typing import Any, Dict, List, Optional

from .kernel import DecisionRecord, VerificationRequest, VerifierKernel
from .registry import screen_evidence

EXPLANATION_VERSION = "1"

GROUPING_RULE = (
    "Records count towards independence only if admissible (signed by a registered, non-revoked key "
    "over this artifact). All keys of one registry operator count as one source (CANON-SIG-011), and "
    "at most one record counts per (verifier identity, provenance) (CANON-IND-004)."
)

LIMITS = (
    "The verifier registry is trusted input. Signature checks and grouping by operator cannot detect "
    "misrepresented common control or collusion between registered operators; that requires the "
    "evidence referenced below, evaluated outside the signature check (docs/sybil-design.md)."
)


def _not_evaluable_reasons(request: VerificationRequest, decision: DecisionRecord,
                           kernel: VerifierKernel) -> List[str]:
    reasons = []
    if kernel.verifier_registry is None:
        reasons.append("no verifier registry loaded: independent signed evidence (CANON-SIG-011) cannot be evaluated")
    frs = (decision.convergence_metrics or {}).get("CANON-FRS-005", {})
    if isinstance(frs, dict) and "policy" in str(frs.get("reason", "")).lower():
        reasons.append("the freshness policy in the request is invalid or incomplete")
    return reasons


def explain(request: VerificationRequest, decision: DecisionRecord, kernel: VerifierKernel) -> Dict[str, Any]:
    reg = kernel.verifier_registry
    reasons = _not_evaluable_reasons(request, decision, kernel)

    rules = []
    for rid in decision.requirement_ids:
        b = kernel.registry.get(rid) or {}
        rules.append({"requirement_id": rid, "revision": str(b.get("version", "")),
                      "kind": b.get("kind", "state_gate"), "title": b.get("title", "")})

    independence: Dict[str, Any] = {"grouping_rule": GROUPING_RULE, "limits": LIMITS,
                                    "registry_digest": decision.registry_digest,
                                    "trust_root_digest": decision.trust_root_digest}
    if reg is None:
        independence.update({"claim_evaluated": None, "operators": [],
                             "conclusion": "not evaluated: no verifier registry"})
    else:
        admissible, _ = screen_evidence(reg, request.artifact_id, request.evidence)
        by_op: Dict[str, Dict[str, Any]] = {}
        for record, operator in admissible:
            entry = by_op.setdefault(operator, {"operator": operator, "records": [], "keys": [], "evidence": []})
            entry["records"].append(record.record_id)
            if record.key_id not in entry["keys"]:
                entry["keys"].append(record.key_id)
        for operator, entry in by_op.items():
            seen = set()
            for key in reg.keys.values():
                if key.operator == operator:
                    for ev in key.independence_evidence:
                        if ev["sha256"] not in seen:
                            seen.add(ev["sha256"])
                            entry["evidence"].append(dict(ev))
            entry["status"] = "evidenced" if entry["evidence"] else "assumed, not evidenced"
        operators = sorted(by_op.values(), key=lambda e: e["operator"])
        evidenced = [o["operator"] for o in operators if o["status"] == "evidenced"]
        assumed = [o["operator"] for o in operators if o["status"] != "evidenced"]
        claim = (f"the admissible records come from {len(operators)} distinct registered operator(s): "
                 + (", ".join(o["operator"] for o in operators) or "none"))
        if not operators:
            conclusion = "no admissible records: independence not established"
        elif len(operators) == 1:
            conclusion = (f"one operator only ({operators[0]['operator']}): its records count as one source, "
                          "so there is no independent corroboration")
        elif assumed:
            conclusion = (f"independence of {', '.join(assumed)} is assumed from the registry, not evidenced"
                          + (f"; evidence is referenced for {', '.join(evidenced)}" if evidenced else ""))
        else:
            conclusion = "an evidence reference is recorded for every operator involved (to be checked outside the signature check)"
        independence.update({"claim_evaluated": claim, "operators": operators, "conclusion": conclusion})

    body = {
        "explanation_version": EXPLANATION_VERSION,
        "decision_id": decision.decision_id,
        "artifact_id": decision.artifact_id,
        "outcome": {"claimed_state": request.claimed_state.value if request.claimed_state else None,
                    "final_epistemic_state": decision.final_epistemic_state.value if decision.final_epistemic_state else None,
                    "status": decision.status.value, "reason": decision.reason},
        "evaluation": {"result": "not_evaluable" if reasons else "evaluated", "reasons": reasons},
        "rules_applied": rules,
        "evidence": {"referenced": list(decision.evidence_ids), "excluded": list(decision.excluded_evidence)},
        "independence": independence,
    }
    body["explanation_id"] = hashlib.sha256(
        json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()[:16]
    return body
