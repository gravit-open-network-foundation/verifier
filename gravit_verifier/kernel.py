"""
Gravit Verifier Kernel — Reference Implementation (v0.2, consolidated & fixed)

Deterministic executable semantics for Canonical Verification Binding.

Purpose: prevent epistemic elevation of knowledge (e.g. among many
autonomous agents in a decentralized environment) via mere aggregation,
absent independent, canonically-grounded verification evidence.

Design notes (fixing the earlier draft's inconsistency)
--------------------------------------------------------
Earlier drafts evaluated every normative Binding and then took the *most
conservative* epistemic state across ALL of them. That silently collapsed
strong COMMITTED-level convergence down to "Speculative Claim", because a
low-tier Binding (VAL-002) always trivially succeeds once any evidence
exists. It also defined `status = SUCCESS` whenever *any* Binding passed,
so aggregation attempts that should have been blocked still reported
SUCCESS. Both defects are fixed here:

1. Bindings are split into two kinds:
   - "state_gate": each corresponds to one rung of the verification-state
     ladder (RAW < VALIDATED < VERIFIED < COMMITTED) and licenses one
     epistemic state if its GEVP condition holds. The kernel walks the
     ladder top-down and the achieved epistemic state is the classification
     of the *highest* rung whose gate actually passes — not the lowest.
   - "constraint": cross-cutting requirements (independence, freshness,
     provenance strength for high-impact decisions) that can only ever
     demote an already-achieved state, never grant one on their own.

2. `DecisionRecord.status` is evaluated against `request.claimed_state`:
   - SUCCESS   — evidence justifies the claimed state (or no claim was made
                 and some state was justified).
   - DEGRADED  — evidence justifies a *lower* state than claimed (this is
                 the direct, testable expression of "no aggregation
                 laundering": claim Verified Fact on weak evidence, get
                 DEGRADED with final_epistemic_state capped below it).
   - REJECTED  — no state gate passes at all.

Pipeline:
    Binding Registry -> Obligation Resolver -> GEVP Evaluator
        -> VEDS Classifier -> Constraint Evaluator -> Decision Composer
"""

from __future__ import annotations

import decimal
import hashlib
import json
import math
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from .registry import VerifierRegistry, screen_evidence


# ---------------------------------------------------------------------------
# Core vocabulary
# ---------------------------------------------------------------------------

class EpistemicState(str, Enum):
    RAW = "RAW"
    VALIDATED = "VALIDATED"
    SPECULATIVE_CLAIM = "Speculative Claim"
    PROBABILISTIC_ASSESSMENT = "Probabilistic Assessment"
    VERIFIED_FACT = "Verified Fact"


_EPISTEMIC_ORDER = {
    EpistemicState.RAW: 0,
    EpistemicState.VALIDATED: 1,
    EpistemicState.SPECULATIVE_CLAIM: 2,
    EpistemicState.PROBABILISTIC_ASSESSMENT: 3,
    EpistemicState.VERIFIED_FACT: 4,
}


class VerificationState(str, Enum):
    RAW = "RAW"
    VALIDATED = "VALIDATED"
    VERIFIED = "VERIFIED"
    COMMITTED = "COMMITTED"


_VERIFICATION_TIER = {
    VerificationState.RAW: 0,
    VerificationState.VALIDATED: 1,
    VerificationState.VERIFIED: 2,
    VerificationState.COMMITTED: 3,
}


class DecisionStatus(str, Enum):
    SUCCESS = "SUCCESS"
    REJECTED = "REJECTED"
    DEGRADED = "DEGRADED"
    PENDING = "PENDING"


class BindingKind(str, Enum):
    STATE_GATE = "state_gate"
    CONSTRAINT = "constraint"
    INFORMATIVE = "informative"


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class EvidenceRecord:
    record_id: str
    theta: float
    result: Any
    verifier_id: str
    timestamp: str
    provenance: str
    integrity_hash: str  # expected: SHA3-256
    key_id: str = ""     # registry key that signed this Record (CANON-SIG-011)
    signature: str = ""  # base64 Ed25519 signature over registry.signing_message()


@dataclass
class VerificationRequest:
    artifact_id: str
    claimed_state: Optional[EpistemicState]
    evidence: List[EvidenceRecord]
    context: Dict[str, Any] = field(default_factory=dict)  # e.g. {"high_impact": True}


@dataclass
class DecisionRecord:
    requirement_ids: List[str]
    final_epistemic_state: Optional[EpistemicState]
    status: DecisionStatus
    evidence_ids: List[str]
    convergence_metrics: Dict[str, Any]
    canon_trace: List[str]                       # forward trace (C_down)
    reverse_trace: List[Dict[str, str]]           # C_up: Evidence -> Binding -> Canon
    reason: str
    c_down: bool
    c_up: bool
    artifact_id: str = ""
    # Content address: first 16 hex chars of SHA3-256 over canonical_json()
    # of every other field. Same inputs -> same id, on any machine.
    decision_id: str = ""
    excluded_evidence: List[Dict[str, str]] = field(default_factory=list)  # CANON-SIG-011
    registry_digest: Optional[str] = None  # SHA-256 of the verifier registry used, if any
    trust_root_digest: Optional[str] = None  # SHA-256 of the trust root that accepted it

    def __post_init__(self) -> None:
        if not self.decision_id:
            self.decision_id = self.content_id()

    def content_id(self) -> str:
        body = self.to_dict()
        body.pop("decision_id")
        return hashlib.sha3_256(canonical_json(body).encode("utf-8")).hexdigest()[:16]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "decision_id": self.decision_id,
            "artifact_id": self.artifact_id,
            "requirement_ids": self.requirement_ids,
            "final_epistemic_state": (
                self.final_epistemic_state.value if self.final_epistemic_state else None
            ),
            "status": self.status.value,
            "evidence_ids": self.evidence_ids,
            "convergence_metrics": self.convergence_metrics,
            "canon_trace": self.canon_trace,
            "reverse_trace": self.reverse_trace,
            "reason": self.reason,
            "c_down": self.c_down,
            "c_up": self.c_up,
            "excluded_evidence": self.excluded_evidence,
            "registry_digest": self.registry_digest,
            "trust_root_digest": self.trust_root_digest,
        }

    def to_json(self, indent: Optional[int] = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)


def canonical_json(value: Any) -> str:
    """JSON Canonicalization Scheme, RFC 8785: keys sorted by UTF-16 code
    units, no whitespace, numbers as ECMAScript formats them, strings with
    the minimal JSON escapes. The Rust port implements the same rules."""
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, (int, float)):
        return _jcs_number(value)
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(canonical_json(v) for v in value) + "]"
    if isinstance(value, dict):
        keys = sorted(value, key=lambda k: k.encode("utf-16-be"))
        return "{" + ",".join(json.dumps(k, ensure_ascii=False) + ":" + canonical_json(value[k]) for k in keys) + "}"
    raise TypeError(f"not JSON: {type(value).__name__}")


def _jcs_number(x: Any) -> str:
    """ECMAScript Number::toString (RFC 8785, Section 3.2.2.3)."""
    if isinstance(x, float) and not math.isfinite(x):
        raise ValueError("NaN and Infinity are not JSON")
    if x == 0:
        return "0"
    if isinstance(x, int):
        if abs(x) > 2**53:
            raise ValueError("integer outside the IEEE 754 exact range")
        return str(x)
    sign = "-" if x < 0 else ""
    _, digit_tuple, exp = decimal.Decimal(repr(abs(x))).as_tuple()
    digits = "".join(map(str, digit_tuple)).rstrip("0")
    exp += len("".join(map(str, digit_tuple))) - len(digits)
    k = len(digits)
    n = k + exp  # value = 0.<digits> * 10**n
    if k <= n <= 21:
        return sign + digits + "0" * (n - k)
    if 0 < n <= 21:
        return sign + digits[:n] + "." + digits[n:]
    if -6 < n <= 0:
        return sign + "0." + "0" * (-n) + digits
    e = n - 1
    mantissa = digits if k == 1 else digits[0] + "." + digits[1:]
    return sign + mantissa + "e" + ("+" if e > 0 else "-") + str(abs(e))


def theta_is_well_formed(theta: Any) -> bool:
    """theta must be a finite JSON number; strings and booleans are never coerced."""
    return not isinstance(theta, bool) and isinstance(theta, (int, float)) and math.isfinite(theta)


def counted_evidence(
    evidence: List["EvidenceRecord"],
    screening: Optional[Tuple[List[Tuple["EvidenceRecord", str]], List[Dict[str, str]]]],
) -> Tuple[List["EvidenceRecord"], List[Dict[str, str]]]:
    """The Records every rule counts, and the excluded ones with reasons.
    With a registry, only admissible Records count (GEVP Section 6);
    without one, every Record with a well-formed theta counts."""
    if screening is not None:
        return [e for e, _ in screening[0]], screening[1]
    counted = [e for e in evidence if theta_is_well_formed(e.theta)]
    excluded = [{"record_id": e.record_id, "reason": "malformed"}
                for e in evidence if not theta_is_well_formed(e.theta)]
    return counted, excluded


# ---------------------------------------------------------------------------
# Freshness Bound (CANON-FRS-005)
# ---------------------------------------------------------------------------

def parse_utc_timestamp(ts: Any) -> Optional[int]:
    """Seconds since 1970-01-01 for exactly 'YYYY-MM-DDTHH:MM:SSZ', else None.
    Deliberately strict and hand-rolled so the Rust port matches exactly."""
    if not isinstance(ts, str) or len(ts) != 20:
        return None
    if (ts[4], ts[7], ts[10], ts[13], ts[16], ts[19]) != ("-", "-", "T", ":", ":", "Z"):
        return None
    digits = ts[0:4] + ts[5:7] + ts[8:10] + ts[11:13] + ts[14:16] + ts[17:19]
    if any(c not in "0123456789" for c in digits):
        return None
    y, mo, d = int(ts[0:4]), int(ts[5:7]), int(ts[8:10])
    h, mi, s = int(ts[11:13]), int(ts[14:16]), int(ts[17:19])
    leap = y % 4 == 0 and (y % 100 != 0 or y % 400 == 0)
    month_days = [31, 29 if leap else 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    if not (1 <= mo <= 12 and 1 <= d <= month_days[mo - 1] and h <= 23 and mi <= 59 and s <= 59):
        return None
    # days_from_civil (H. Hinnant); y >= 0 here, so // and Rust's / agree.
    yy = y - 1 if mo <= 2 else y
    era = (yy if yy >= 0 else yy - 399) // 400
    yoe = yy - era * 400
    doy = (153 * (mo - 3 if mo > 2 else mo + 9) + 2) // 5 + d - 1
    doe = yoe * 365 + yoe // 4 - yoe // 100 + doy
    days = era * 146097 + doe - 719468
    return days * 86400 + h * 3600 + mi * 60 + s


def freshness_check(evidence: List["EvidenceRecord"], context: Dict[str, Any]) -> Dict[str, Any]:
    """Without a policy in `context`, only presence of a timestamp is checked.
    With `evaluation_time` and/or `freshness_max_age_seconds`, both must be
    valid and every Record must satisfy 0 <= evaluation_time - timestamp <= max."""
    if "evaluation_time" not in context and "freshness_max_age_seconds" not in context:
        ok = all(bool(e.timestamp) for e in evidence)
        return {"ok": ok, "reason": "" if ok else "evidence missing Freshness Bound timestamp"}
    now = parse_utc_timestamp(context.get("evaluation_time"))
    max_age = context.get("freshness_max_age_seconds")
    if now is None or isinstance(max_age, bool) or not isinstance(max_age, int) or max_age < 0:
        return {"ok": False, "reason": "invalid Freshness Bound policy in context"}
    for e in evidence:
        t = parse_utc_timestamp(e.timestamp)
        if t is None:
            return {"ok": False, "reason": "evidence timestamp missing or not YYYY-MM-DDTHH:MM:SSZ"}
        if t > now:
            return {"ok": False, "reason": "evidence timestamp after evaluation_time"}
        if now - t > max_age:
            return {"ok": False, "reason": "evidence older than Freshness Bound"}
    return {"ok": True, "reason": ""}


# ---------------------------------------------------------------------------
# Binding Registry
# ---------------------------------------------------------------------------

class BindingRegistry:
    def __init__(self) -> None:
        self.bindings: Dict[str, Dict[str, Any]] = {}

    def load(self, binding: Dict[str, Any]) -> None:
        rid = binding["requirement_id"]
        self.bindings[rid] = binding

    def get(self, requirement_id: str) -> Optional[Dict[str, Any]]:
        return self.bindings.get(requirement_id)

    def all(self) -> List[Dict[str, Any]]:
        return list(self.bindings.values())


# ---------------------------------------------------------------------------
# Obligation Resolver
# ---------------------------------------------------------------------------

class ObligationResolver:
    """Finds which Binding records apply to a given VerificationRequest.

    v0.2: all normative Bindings apply uniformly; a context-aware filter
    (e.g. only applying PRV-006 when request.context["high_impact"] is set)
    happens later, inside the relevant evaluator, not here.
    """

    def __init__(self, registry: BindingRegistry) -> None:
        self.registry = registry

    def resolve(self, request: VerificationRequest) -> List[Dict[str, Any]]:
        return [b for b in self.registry.all() if b.get("status") == "normative"]


# ---------------------------------------------------------------------------
# GEVP Evaluator (HOW: verification-state machine + convergence)
# ---------------------------------------------------------------------------

class GEVPEvaluator:
    def evaluate(self, binding: Dict[str, Any], evidence: List[EvidenceRecord]) -> Dict[str, Any]:
        cond = binding["verification_condition"]
        required_state = cond["required_verification_state"]

        if required_state == VerificationState.COMMITTED.value:
            return self._check_convergence(evidence)
        elif required_state in (VerificationState.VERIFIED.value, VerificationState.VALIDATED.value):
            return {"ok": len(evidence) >= 1, "metrics": {"record_count": len(evidence)}}
        elif required_state == VerificationState.RAW.value:
            return {"ok": True, "metrics": {"record_count": len(evidence)}}
        return {"ok": False, "metrics": {}}

    def _check_convergence(self, evidence: List[EvidenceRecord]) -> Dict[str, Any]:
        """Convergence per GEVP §10.3-10.4: h > 0.7, f < 0.3, >= 2
        independent Records. Independence per CANON-IND-004 (VEDS §4.6.2):
        see independent_subset()."""
        independent = self.independent_subset(evidence)

        if len(independent) < 2:
            return {"ok": False, "metrics": {"independent_records": len(independent)}}
        ok, h, f = self.convergence(independent)
        return {
            "ok": ok,
            "metrics": {"h": h, "f": f, "independent_records": len(independent)},
        }

    @staticmethod
    def convergence(representatives: List[EvidenceRecord]) -> Tuple[bool, float, float]:
        """GEVP §10.3: (h > 0.7 and f < 0.3, h, f) over source representatives."""
        thetas = [e.theta for e in representatives]
        h = sum(1 for t in thetas if t >= 0.7) / len(thetas)
        f = sum(1 for t in thetas if t < 0.5) / len(thetas)
        return h > 0.7 and f < 0.3, h, f

    @staticmethod
    def independent_subset(
        evidence: List[EvidenceRecord], identities: Optional[List[str]] = None
    ) -> List[EvidenceRecord]:
        """One representative Record per independent source.

        CANON-IND-004 requires distinct verifier-id AND distinct provenance
        roots. Records sharing either one -- directly or through a chain of
        other Records -- are treated as a single source (connected
        components). Each source is represented by its lowest-theta Record,
        so a source cannot outvote itself. The result does not depend on
        the order of `evidence`, except for the order of the returned list.

        `identities` replaces verifier_id as the identity of each Record
        (CANON-SIG-011 passes the registry operator).
        """
        if identities is None:
            identities = [e.verifier_id for e in evidence]
        parent = list(range(len(evidence)))

        def find(i: int) -> int:
            while parent[i] != i:
                parent[i] = parent[parent[i]]
                i = parent[i]
            return i

        first_by_key: Dict[tuple, int] = {}
        for i, e in enumerate(evidence):
            for key in (("identity", identities[i]), ("provenance", e.provenance)):
                j = first_by_key.setdefault(key, i)
                parent[find(i)] = find(j)

        rep: Dict[int, int] = {}
        for i, e in enumerate(evidence):
            root = find(i)
            if root not in rep or e.theta < evidence[rep[root]].theta:
                rep[root] = i
        return [evidence[i] for i in sorted(rep.values())]


# ---------------------------------------------------------------------------
# VEDS Classifier (WHAT: taxonomy + anti-elevation policy)
# ---------------------------------------------------------------------------

class VEDSClassifier:
    _PRIORITY = [
        EpistemicState.VERIFIED_FACT,
        EpistemicState.PROBABILISTIC_ASSESSMENT,
        EpistemicState.SPECULATIVE_CLAIM,
        EpistemicState.VALIDATED,
        EpistemicState.RAW,
    ]

    def classify(self, binding: Dict[str, Any], gevp_result: Dict[str, Any]) -> Optional[EpistemicState]:
        if not gevp_result.get("ok"):
            return None
        allowed = binding["policy_obligation"].get("allowed_epistemic_states", [])
        for state in self._PRIORITY:
            if state.value in allowed:
                return state
        return None


# ---------------------------------------------------------------------------
# Constraint Evaluator (cross-cutting checks that can only demote a state)
# ---------------------------------------------------------------------------

class ConstraintEvaluator:
    """Evaluates 'constraint' Bindings. These never grant a state on their
    own; they can only cap/demote a state already achieved by a state_gate.
    """

    def evaluate(
        self,
        binding: Dict[str, Any],
        request: VerificationRequest,
        achieved_state: Optional[EpistemicState],
        gate_gevp_metrics: Dict[str, Any],
        screening: Optional[Tuple[List[Tuple[EvidenceRecord, str]], List[Dict[str, str]]]] = None,
    ) -> Dict[str, Any]:
        rid = binding["requirement_id"]
        counted, _ = counted_evidence(request.evidence, screening)

        if rid == "CANON-IND-004":
            independent = GEVPEvaluator.independent_subset(counted)
            ok = len(independent) >= 2 if achieved_state == EpistemicState.VERIFIED_FACT else True
            return {"ok": ok, "reason": "" if ok else "records not independently produced"}

        if rid == "CANON-FRS-005":
            return freshness_check(counted, request.context)

        if rid == "CANON-PRV-006":
            if not request.context.get("high_impact"):
                return {"ok": True, "reason": ""}  # binding not applicable
            ok = all(e.integrity_hash and e.provenance for e in counted)
            return {"ok": ok, "reason": "" if ok else "high-impact decision lacks strong provenance binding"}

        if rid == "CANON-SIG-011":
            return self._signed_evidence(achieved_state, screening)

        if rid == "CANON-RES-012":
            return self._signed_result(achieved_state, counted, screening)

        if rid == "CANON-NSD-007":
            # Meta-rule about re-verification over time; not evaluable
            # within a single stateless verify() call. Recorded as
            # informative only.
            return {"ok": True, "reason": "", "informative": True}

        return {"ok": True, "reason": ""}

    @staticmethod
    def _signed_evidence(
        achieved_state: Optional[EpistemicState],
        screening: Optional[Tuple[List[Tuple[EvidenceRecord, str]], List[Dict[str, str]]]],
    ) -> Dict[str, Any]:
        """CANON-SIG-011: Verified Fact must converge on signed Records from
        independent operators. Caps (never steps) the state at Probabilistic
        Assessment, so it does not stack with CANON-IND-004."""
        if achieved_state != EpistemicState.VERIFIED_FACT:
            return {"ok": True, "reason": ""}
        cap = EpistemicState.PROBABILISTIC_ASSESSMENT
        if screening is None:
            return {
                "ok": False,
                "cap": cap,
                "reason": "no verifier registry loaded; Verified Fact requires signed evidence",
                "metrics": {"registry": False},
            }
        admissible, _excluded = screening
        records = [e for e, _ in admissible]
        sources = GEVPEvaluator.independent_subset(records, [op for _, op in admissible])
        metrics: Dict[str, Any] = {
            "registry": True,
            "admissible_records": len(records),
            "independent_sources": len(sources),
        }
        hashes = sorted({e.integrity_hash for e in records})
        metrics["integrity_hashes"] = len(hashes)
        if len(hashes) > 1:
            return {
                "ok": False,
                "cap": cap,
                "reason": f"counted records refer to different content ({len(hashes)} distinct integrity_hash values)",
                "metrics": metrics,
            }
        ok = False
        if len(sources) >= 2:
            ok, metrics["h"], metrics["f"] = GEVPEvaluator.convergence(sources)
        return {
            "ok": ok,
            "cap": cap,
            "reason": "" if ok else "signed evidence from independent operators does not converge",
            "metrics": metrics,
        }


    @staticmethod
    def _signed_result(
        achieved_state: Optional[EpistemicState],
        counted_records: List[EvidenceRecord],
        screening: Optional[Tuple[List[Tuple[EvidenceRecord, str]], List[Dict[str, str]]]],
    ) -> Dict[str, Any]:
        """CANON-RES-012: a Verified Fact needs 2 independent sources whose
        records report result=true and no counted record reporting false.
        Counted records are the admissible ones when a registry is loaded,
        otherwise all. Too few sources without any false/null record is left
        to CANON-SIG-011 / CANON-IND-004, so the reason names the real cause. Caps at Probabilistic Assessment, like CANON-SIG-011."""
        if achieved_state != EpistemicState.VERIFIED_FACT:
            return {"ok": True, "reason": ""}
        if screening is not None:
            counted = [(e, op) for e, op in screening[0]]
        else:
            counted = [(e, e.verifier_id) for e in counted_records]
        supporting = [(e, op) for e, op in counted if e.result is True]
        contradicting = [e.record_id for e, _ in counted if e.result is False]
        no_verdict = [e.record_id for e, _ in counted if e.result is not True and e.result is not False]
        sources = GEVPEvaluator.independent_subset([e for e, _ in supporting], [op for _, op in supporting])
        metrics: Dict[str, Any] = {
            "supporting_sources": len(sources),
            "contradicting_records": contradicting,
            "no_verdict_records": no_verdict,
        }
        if contradicting:
            reason = f"{len(contradicting)} record(s) report result=false: the claim is contradicted"
        elif no_verdict and len(sources) < 2:
            reason = (f"only {len(sources)} independent source(s) report result=true"
                      f" ({len(no_verdict)} record(s) report no verdict)")
        else:
            reason = ""
        return {"ok": not reason, "cap": EpistemicState.PROBABILISTIC_ASSESSMENT, "reason": reason,
                "metrics": metrics}


# ---------------------------------------------------------------------------
# Decision Composer
# ---------------------------------------------------------------------------

class DecisionComposer:
    def compose(
        self,
        state_gates: List[Dict[str, Any]],
        constraints: List[Dict[str, Any]],
        request: VerificationRequest,
        gevp_results: Dict[str, Dict[str, Any]],
        classifications: Dict[str, Optional[EpistemicState]],
        constraint_results: Dict[str, Dict[str, Any]],
        excluded_evidence: Optional[List[Dict[str, str]]] = None,
        registry_digest: Optional[str] = None,
        trust_root_digest: Optional[str] = None,
    ) -> DecisionRecord:
        ranked_gates = sorted(
            state_gates,
            key=lambda b: _VERIFICATION_TIER.get(
                VerificationState(b["verification_condition"]["required_verification_state"]), -1
            ),
            reverse=True,
        )

        achieved_state: Optional[EpistemicState] = None
        winning_gate_id: Optional[str] = None
        for b in ranked_gates:
            rid = b["requirement_id"]
            state = classifications.get(rid)
            if state is not None:
                achieved_state = state
                winning_gate_id = rid
                break

        reasons: List[str] = []
        if achieved_state is None:
            reasons.append("no state_gate Binding's verification condition was satisfied")

        demoted = False
        for c in constraints:
            rid = c["requirement_id"]
            result = constraint_results.get(rid, {"ok": True})
            if result.get("informative"):
                continue
            if not result.get("ok", True) and achieved_state is not None:
                cap = result.get("cap")
                if cap is not None:
                    if _EPISTEMIC_ORDER[achieved_state] > _EPISTEMIC_ORDER[cap]:
                        demoted = True
                        reasons.append(f"{rid}: {result.get('reason', 'constraint failed')}")
                        achieved_state = cap
                    continue
                demoted = True
                reasons.append(f"{rid}: {result.get('reason', 'constraint failed')}")
                order = _EPISTEMIC_ORDER[achieved_state]
                lower = [s for s, o in _EPISTEMIC_ORDER.items() if o == max(order - 1, 0)]
                achieved_state = lower[0] if order > 0 else None

        claimed = request.claimed_state
        if achieved_state is None:
            status = DecisionStatus.REJECTED
        elif claimed is None:
            status = DecisionStatus.SUCCESS
        elif achieved_state == claimed:
            status = DecisionStatus.DEGRADED if demoted else DecisionStatus.SUCCESS
        elif _EPISTEMIC_ORDER[achieved_state] < _EPISTEMIC_ORDER[claimed]:
            status = DecisionStatus.DEGRADED
            reasons.append(
                f"claimed '{claimed.value}' not justified by evidence; "
                f"capped at '{achieved_state.value}'"
            )
        else:
            status = DecisionStatus.SUCCESS

        all_bindings = state_gates + constraints
        reverse_trace = self._build_reverse_trace(all_bindings, request, classifications, winning_gate_id)
        c_down = status in (DecisionStatus.SUCCESS, DecisionStatus.DEGRADED) and achieved_state is not None
        c_up = winning_gate_id is not None

        metrics = {rid: gevp_results[rid].get("metrics", {}) for rid in gevp_results}

        return DecisionRecord(
            artifact_id=request.artifact_id,
            requirement_ids=[b["requirement_id"] for b in all_bindings],
            final_epistemic_state=achieved_state,
            status=status,
            evidence_ids=[e.record_id for e in request.evidence],
            convergence_metrics=metrics,
            canon_trace=[b["canonical_reference"][0] for b in all_bindings if b.get("canonical_reference")],
            reverse_trace=reverse_trace,
            reason="; ".join(reasons) if reasons else "All applicable Bindings satisfied",
            c_down=c_down,
            c_up=c_up,
            excluded_evidence=excluded_evidence or [],
            registry_digest=registry_digest,
            trust_root_digest=trust_root_digest,
        )

    @staticmethod
    def _build_reverse_trace(
        bindings: List[Dict[str, Any]],
        request: VerificationRequest,
        classifications: Dict[str, Optional[EpistemicState]],
        winning_gate_id: Optional[str],
    ) -> List[Dict[str, str]]:
        trace = []
        for b in bindings:
            rid = b["requirement_id"]
            achieved = classifications.get(rid)
            description = b.get("policy_obligation", {}).get("description", "").strip()
            for ev in request.evidence:
                trace.append(
                    {
                        "evidence_id": ev.record_id,
                        "binding_id": rid,
                        "canon_reference": (b.get("canonical_reference") or ["unknown"])[0],
                        "policy_obligation": (description[:120] + "...") if description else "",
                        "achieved_state": achieved.value if achieved else "None",
                        "is_winning_gate": str(rid == winning_gate_id),
                    }
                )
        return trace


# ---------------------------------------------------------------------------
# Verifier Kernel
# ---------------------------------------------------------------------------

class VerifierKernel:
    def __init__(self, verifier_registry: Optional[VerifierRegistry] = None) -> None:
        self.verifier_registry = verifier_registry
        self.registry = BindingRegistry()
        self.resolver = ObligationResolver(self.registry)
        self.gevp = GEVPEvaluator()
        self.veds = VEDSClassifier()
        self.constraints_eval = ConstraintEvaluator()
        self.composer = DecisionComposer()

    def load_binding(self, binding: Dict[str, Any]) -> None:
        self.registry.load(binding)

    def load_verifier_registry(self, registry: VerifierRegistry) -> None:
        self.verifier_registry = registry

    def verify(self, request: VerificationRequest) -> DecisionRecord:
        bindings = self.resolver.resolve(request)
        screening = None
        if self.verifier_registry is not None:
            screening = screen_evidence(self.verifier_registry, request.artifact_id, request.evidence)
        state_gates = [b for b in bindings if b.get("kind", "state_gate") == BindingKind.STATE_GATE.value]
        constraints = [b for b in bindings if b.get("kind") == BindingKind.CONSTRAINT.value]

        counted, excluded = counted_evidence(request.evidence, screening)
        gevp_results: Dict[str, Dict[str, Any]] = {}
        classifications: Dict[str, Optional[EpistemicState]] = {}

        for b in state_gates:
            rid = b["requirement_id"]
            result = self.gevp.evaluate(b, counted)
            gevp_results[rid] = result
            classifications[rid] = self.veds.classify(b, result)

        tentative = None
        for b in sorted(
            state_gates,
            key=lambda b: _VERIFICATION_TIER.get(
                VerificationState(b["verification_condition"]["required_verification_state"]), -1
            ),
            reverse=True,
        ):
            state = classifications.get(b["requirement_id"])
            if state is not None:
                tentative = state
                break

        constraint_results: Dict[str, Dict[str, Any]] = {}
        for c in constraints:
            rid = c["requirement_id"]
            result = self.constraints_eval.evaluate(c, request, tentative, gevp_results, screening)
            constraint_results[rid] = result
            gevp_results[rid] = {"metrics": {"constraint_ok": result.get("ok"), **result.get("metrics", {})}}

        return self.composer.compose(
            state_gates, constraints, request, gevp_results, classifications, constraint_results,
            excluded_evidence=excluded,
            registry_digest=self.verifier_registry.digest if self.verifier_registry else None,
            trust_root_digest=self.verifier_registry.trust_root_digest if self.verifier_registry else None,
        )
