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

import hashlib
import json
import time
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
    decision_id: str = field(
        default_factory=lambda: hashlib.sha3_256(str(time.time()).encode()).hexdigest()[:16]
    )
    excluded_evidence: List[Dict[str, str]] = field(default_factory=list)  # CANON-SIG-011
    registry_digest: Optional[str] = None  # SHA-256 of the verifier registry used, if any

    def to_dict(self) -> Dict[str, Any]:
        return {
            "decision_id": self.decision_id,
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
        }

    def to_json(self, indent: Optional[int] = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)


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

        if rid == "CANON-IND-004":
            independent = GEVPEvaluator.independent_subset(request.evidence)
            ok = len(independent) >= 2 if achieved_state == EpistemicState.VERIFIED_FACT else True
            return {"ok": ok, "reason": "" if ok else "records not independently produced"}

        if rid == "CANON-FRS-005":
            ok = all(bool(e.timestamp) for e in request.evidence)
            return {"ok": ok, "reason": "" if ok else "evidence missing Freshness Bound timestamp"}

        if rid == "CANON-PRV-006":
            if not request.context.get("high_impact"):
                return {"ok": True, "reason": ""}  # binding not applicable
            ok = all(e.integrity_hash and e.provenance for e in request.evidence)
            return {"ok": ok, "reason": "" if ok else "high-impact decision lacks strong provenance binding"}

        if rid == "CANON-SIG-011":
            return self._signed_evidence(achieved_state, screening)

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
        ok = False
        if len(sources) >= 2:
            ok, metrics["h"], metrics["f"] = GEVPEvaluator.convergence(sources)
        return {
            "ok": ok,
            "cap": cap,
            "reason": "" if ok else "signed evidence from independent operators does not converge",
            "metrics": metrics,
        }


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

        gevp_results: Dict[str, Dict[str, Any]] = {}
        classifications: Dict[str, Optional[EpistemicState]] = {}

        for b in state_gates:
            rid = b["requirement_id"]
            result = self.gevp.evaluate(b, request.evidence)
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
            excluded_evidence=screening[1] if screening else [],
            registry_digest=self.verifier_registry.digest if self.verifier_registry else None,
        )
