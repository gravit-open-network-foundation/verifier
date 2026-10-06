# Gravit Verifier — Canonical Verification Binding + Verifier Kernel

Reference implementation of the executable layer discussed across the
Gravit Canon / VEDS / GEVP design conversation:

```
GRAVIT CANON (stable normative layer)
        │
   ┌────┴────┐
   │         │
  VEDS      GEVP
  WHAT      HOW
   │         │
   └────┬────┘
        │
CANONICAL VERIFICATION BINDING
        │
        ▼
   VERIFIER KERNEL
        │
        ▼
EXECUTION TRACE → EVIDENCE → DECISION RECORD → BACK TO CANON
```

Core invariant enforced end-to-end:

```
Aggregate(V1, ..., Vn)  ⇏  VerifiedFact
```

in the absence of independent verification evidence satisfying `COMMITTED`
convergence (`h > 0.7 ∧ f < 0.3`, ≥2 independently-produced Records).

## What changed during finalization

The design conversation this repo consolidates had drifted into an
inconsistent state by the end: the reference kernel evaluated every Binding
and kept the *most conservative* epistemic state across all of them. That
silently capped even genuine `COMMITTED`-level convergence down to
`Speculative Claim`, and `status` was reported as `SUCCESS` whenever *any*
Binding passed — which meant blocked aggregation attempts still looked
successful. Both were fixed here (see `gravit_verifier/kernel.py` module
docstring for the full rationale):

- Bindings are now typed `state_gate` (one rung of `RAW < VALIDATED <
  VERIFIED < COMMITTED`) or `constraint` (can only demote, never grant).
- `DecisionRecord.status` is evaluated against the *claimed* epistemic
  state: `SUCCESS` if justified, `DEGRADED` if the evidence only supports
  something weaker (this is the actual, testable meaning of "no
  aggregation laundering"), `REJECTED` if nothing is justified at all.

## Layout

```
bindings/            7 normative Canonical Verification Binding records (YAML)
gravit_verifier/     Python package: loader, kernel, CLI
schemas/             JSON Schema for Binding records (draft 2020-12)
tests/               unit + full-cycle integration tests (pytest)
examples/            sample artifact.json inputs for the CLI
```

## Binding records

| ID              | Kind       | Licenses / constrains                                  |
|-----------------|------------|----------------------------------------------------------|
| CANON-NAL-001   | state_gate | `Verified Fact` via `COMMITTED` convergence only          |
| CANON-VAL-002   | state_gate | `Speculative Claim` at most, from `VALIDATED` admissibility |
| CANON-VER-003   | state_gate | `Probabilistic Assessment` at most, from a single Record  |
| CANON-IND-004   | constraint | Records must be independently produced                    |
| CANON-FRS-005   | constraint | Evidence must carry a Freshness Bound timestamp           |
| CANON-PRV-006   | constraint | High-impact decisions need strong provenance (context-scoped) |
| CANON-NSD-007   | constraint | No silent degradation (informative in this stateless kernel) |

## Install & test

```bash
pip install -e .
pip install pytest jsonschema   # for the schema-validation test
pytest -v
```

## CLI

```bash
gravit-verify examples/artifact_committed.json --bindings-dir bindings --pretty
gravit-verify examples/artifact_weak_aggregation.json --bindings-dir bindings --pretty
```

Exit code is `0` for `SUCCESS`/`DEGRADED`, `1` for `REJECTED`.

## Library usage

```python
from gravit_verifier import VerifierKernel, VerificationRequest, EvidenceRecord, EpistemicState
from gravit_verifier.loader import load_bindings_from_dir

kernel = VerifierKernel()
for binding in load_bindings_from_dir("bindings"):
    kernel.load_binding(binding)

decision = kernel.verify(VerificationRequest(
    artifact_id="agent-knowledge-42",
    claimed_state=EpistemicState.VERIFIED_FACT,
    evidence=[
        EvidenceRecord("r1", 0.88, True, "v-01", "2026-09-06T12:00:00Z", "agent-A", "hash1"),
        EvidenceRecord("r2", 0.85, True, "v-02", "2026-09-06T12:00:45Z", "agent-B", "hash2"),
    ],
))

print(decision.final_epistemic_state, decision.status)
```

## Known open work (not finalized here)

- `CANON-NSD-007` is a re-verification-over-time invariant; this kernel is
  stateless per call and only records it as informative. A production
  deployment needs a scheduler that re-runs `verify()` per `artifact_id`
  and emits an explicit transition when evidence expires.
- `CANON-FRS-005` only checks *presence* of a timestamp, not an actual
  Freshness Bound duration — a real duration needs a domain-specific
  policy value.

## v0.3 additions

- `tests/golden/` + `tools/` — language-neutral golden vectors generated from this Python kernel (`python tools/make_golden.py`, replay with `python tools/verify_golden.py`).
- `rust/` — Rust port; `cd rust && cargo test` reproduces all golden vectors. Python remains the reference; see `CONFORMANCE.md`.
- `CONFORMANCE.md` — what was and was not verified, plus observed weaknesses of the reference kernel.
