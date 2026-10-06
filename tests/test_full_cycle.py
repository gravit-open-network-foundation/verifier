"""
Full-cycle integration test.

Verifies that the complete pipeline
(Binding load -> Obligation resolve -> GEVP -> VEDS -> Constraints
 -> Decision + C_up)
correctly blocks epistemic elevation via aggregation, while still allowing
genuine COMMITTED-level convergence to reach Verified Fact.
"""

from pathlib import Path

import pytest

from gravit_verifier.loader import load_bindings_from_dir
from gravit_verifier.kernel import (
    VerifierKernel,
    VerificationRequest,
    EvidenceRecord,
    EpistemicState,
    DecisionStatus,
)

BINDINGS_DIR = Path(__file__).parent.parent / "bindings"


@pytest.fixture
def kernel_with_all_bindings():
    kernel = VerifierKernel()
    for binding in load_bindings_from_dir(BINDINGS_DIR):
        kernel.load_binding(binding)
    return kernel


@pytest.fixture
def signed_kernel(kernel_with_all_bindings, signer):
    kernel_with_all_bindings.load_verifier_registry(signer.registry)
    return kernel_with_all_bindings


def test_full_cycle_blocks_aggregation_laundering(kernel_with_all_bindings):
    """Claiming Verified Fact from several weak/low-theta records must be
    DEGRADED to whatever the evidence actually supports — never SUCCESS
    at Verified Fact."""
    req = VerificationRequest(
        artifact_id="agg-test-001",
        claimed_state=EpistemicState.VERIFIED_FACT,
        evidence=[
            EvidenceRecord("r1", 0.61, True, "v-01", "2026-09-03T12:00:00Z", "agent-A", "hash1"),
            EvidenceRecord("r2", 0.58, True, "v-02", "2026-09-03T12:00:30Z", "agent-B", "hash2"),
            EvidenceRecord("r3", 0.55, True, "v-03", "2026-09-03T12:01:00Z", "agent-C", "hash3"),
        ],
    )
    decision = kernel_with_all_bindings.verify(req)

    assert decision.final_epistemic_state != EpistemicState.VERIFIED_FACT
    assert decision.status == DecisionStatus.DEGRADED
    assert len(decision.reverse_trace) > 0


def test_full_cycle_single_record_max_probabilistic(kernel_with_all_bindings):
    """A single high-theta record can never justify Verified Fact — at most
    a Probabilistic Assessment."""
    req = VerificationRequest(
        artifact_id="single-high-theta",
        claimed_state=EpistemicState.VERIFIED_FACT,
        evidence=[
            EvidenceRecord("r1", 0.94, True, "v-01", "2026-09-03T12:00:00Z", "agent-A", "hash1"),
        ],
    )
    decision = kernel_with_all_bindings.verify(req)

    assert decision.final_epistemic_state == EpistemicState.PROBABILISTIC_ASSESSMENT
    assert decision.status == DecisionStatus.DEGRADED


def _two_strong_records():
    return [
        EvidenceRecord("r1", 0.88, True, "v-01", "2026-09-03T12:00:00Z", "agent-A", "hash1"),
        EvidenceRecord("r2", 0.85, True, "v-02", "2026-09-03T12:00:45Z", "agent-B", "hash2"),
    ]


def test_full_cycle_committed_success(signed_kernel, signer):
    """Two strong, independently-produced, signed records with good h/f DO
    reach Verified Fact — genuine convergence is not penalized."""
    evidence = [signer.sign("committed-ok", e, e.verifier_id) for e in _two_strong_records()]
    req = VerificationRequest(
        artifact_id="committed-ok", claimed_state=EpistemicState.VERIFIED_FACT, evidence=evidence
    )
    decision = signed_kernel.verify(req)

    assert decision.final_epistemic_state == EpistemicState.VERIFIED_FACT
    assert decision.status == DecisionStatus.SUCCESS
    assert decision.c_up is True
    assert decision.c_down is True
    assert decision.excluded_evidence == []
    assert decision.registry_digest == signer.registry.digest


def test_without_registry_verified_fact_is_capped(kernel_with_all_bindings):
    """CANON-SIG-011: no registry, no Verified Fact — however strong the records."""
    req = VerificationRequest(
        artifact_id="no-registry", claimed_state=EpistemicState.VERIFIED_FACT,
        evidence=_two_strong_records(),
    )
    decision = kernel_with_all_bindings.verify(req)

    assert decision.final_epistemic_state == EpistemicState.PROBABILISTIC_ASSESSMENT
    assert decision.status == DecisionStatus.DEGRADED
    assert "CANON-SIG-011" in decision.reason
    assert decision.registry_digest is None


def test_invented_verifier_ids_do_not_count(signed_kernel, signer):
    """The Sybil case from v0.3.1: one key, two invented verifier_ids."""
    evidence = [signer.sign("sybil", e, "v-01") for e in _two_strong_records()]
    decision = signed_kernel.verify(VerificationRequest(
        artifact_id="sybil", claimed_state=EpistemicState.VERIFIED_FACT, evidence=evidence
    ))
    assert decision.final_epistemic_state == EpistemicState.PROBABILISTIC_ASSESSMENT
    assert decision.convergence_metrics["CANON-SIG-011"]["independent_sources"] == 1


def test_bad_signature_excludes_record_but_not_artifact(signed_kernel, signer):
    records = _two_strong_records() + [
        EvidenceRecord("r3", 0.9, True, "v-03", "2026-09-03T12:01:00Z", "agent-C", "hash3")
    ]
    evidence = [signer.sign("partial", e, e.verifier_id) for e in records]
    evidence[2].theta = 0.99  # changed after signing
    decision = signed_kernel.verify(VerificationRequest(
        artifact_id="partial", claimed_state=EpistemicState.VERIFIED_FACT, evidence=evidence
    ))
    assert decision.excluded_evidence == [{"record_id": "r3", "reason": "bad_signature"}]
    assert decision.final_epistemic_state == EpistemicState.VERIFIED_FACT


def test_full_cycle_no_evidence_is_rejected(kernel_with_all_bindings):
    req = VerificationRequest(artifact_id="empty", claimed_state=None, evidence=[])
    decision = kernel_with_all_bindings.verify(req)
    assert decision.final_epistemic_state is None
    assert decision.status == DecisionStatus.REJECTED


def test_high_impact_context_demotes_without_provenance(signed_kernel, signer):
    """CANON-PRV-006 only bites when context['high_impact'] is set."""
    evidence = [
        EvidenceRecord("r1", 0.88, True, "v-01", "2026-09-03T12:00:00Z", "agent-A", ""),
        EvidenceRecord("r2", 0.85, True, "v-02", "2026-09-03T12:00:45Z", "agent-B", "hash2"),
    ]
    evidence = [signer.sign("hi", e, e.verifier_id) for e in evidence]
    req_normal = VerificationRequest(
        artifact_id="hi", claimed_state=EpistemicState.VERIFIED_FACT, evidence=evidence
    )
    req_high_impact = VerificationRequest(
        artifact_id="hi",
        claimed_state=EpistemicState.VERIFIED_FACT,
        evidence=evidence,
        context={"high_impact": True},
    )

    normal_decision = signed_kernel.verify(req_normal)
    high_impact_decision = signed_kernel.verify(req_high_impact)

    assert normal_decision.final_epistemic_state == EpistemicState.VERIFIED_FACT
    assert high_impact_decision.final_epistemic_state != EpistemicState.VERIFIED_FACT
    assert high_impact_decision.status == DecisionStatus.DEGRADED


def test_decision_record_serializes_to_json(kernel_with_all_bindings):
    req = VerificationRequest(
        artifact_id="serialize-test",
        claimed_state=None,
        evidence=[
            EvidenceRecord("r1", 0.9, True, "v-01", "2026-09-03T12:00:00Z", "agent-A", "hash1"),
        ],
    )
    decision = kernel_with_all_bindings.verify(req)
    payload = decision.to_dict()
    assert payload["decision_id"]
    assert isinstance(decision.to_json(), str)


@pytest.mark.parametrize(
    "evidence",
    [
        # one verifier, two provenance strings
        [("v-01", "agent-A"), ("v-01", "agent-B")],
        # two verifiers, one provenance root
        [("v-01", "agent-A"), ("v-02", "agent-A")],
        # chain: v-01~A~v-02~B~v-03 is one source
        [("v-01", "agent-A"), ("v-02", "agent-A"), ("v-02", "agent-B"), ("v-03", "agent-B")],
    ],
    ids=["same-verifier", "same-provenance", "chain"],
)
def test_shared_verifier_or_provenance_is_not_independent(kernel_with_all_bindings, evidence):
    """CANON-IND-004: distinct verifier-id AND distinct provenance are both required."""
    req = VerificationRequest(
        artifact_id="ind-004",
        claimed_state=EpistemicState.VERIFIED_FACT,
        evidence=[
            EvidenceRecord(f"r{i}", 0.9, True, v, "2026-09-03T12:00:00Z", p, f"hash{i}")
            for i, (v, p) in enumerate(evidence, 1)
        ],
    )
    decision = kernel_with_all_bindings.verify(req)
    assert decision.final_epistemic_state != EpistemicState.VERIFIED_FACT
    assert decision.status == DecisionStatus.DEGRADED


def test_independent_subset_is_order_independent_and_takes_weakest():
    from gravit_verifier.kernel import GEVPEvaluator

    evidence = [
        EvidenceRecord("r1", 0.9, True, "v-01", "t", "agent-A", "h"),
        EvidenceRecord("r2", 0.4, True, "v-01", "t", "agent-B", "h"),
        EvidenceRecord("r3", 0.9, True, "v-02", "t", "agent-C", "h"),
    ]
    forward = GEVPEvaluator.independent_subset(evidence)
    backward = GEVPEvaluator.independent_subset(list(reversed(evidence)))
    assert sorted(e.record_id for e in forward) == sorted(e.record_id for e in backward) == ["r2", "r3"]
