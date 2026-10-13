"""
Gravit Verifier — reference implementation of Canonical Verification Binding.

Prevents epistemic elevation of knowledge (e.g. among many autonomous agents)
through mere aggregation, absent independent, canonically-grounded evidence.
"""

from .kernel import (
    EpistemicState,
    VerificationState,
    DecisionStatus,
    EvidenceRecord,
    VerificationRequest,
    DecisionRecord,
    BindingRegistry,
    ObligationResolver,
    GEVPEvaluator,
    VEDSClassifier,
    DecisionComposer,
    VerifierKernel,
)

__all__ = [
    "EpistemicState",
    "VerificationState",
    "DecisionStatus",
    "EvidenceRecord",
    "VerificationRequest",
    "DecisionRecord",
    "BindingRegistry",
    "ObligationResolver",
    "GEVPEvaluator",
    "VEDSClassifier",
    "DecisionComposer",
    "VerifierKernel",
]

__version__ = "0.6.0"
