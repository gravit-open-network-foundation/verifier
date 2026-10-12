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
bindings/            8 normative Canonical Verification Binding records (YAML)
gravit_verifier/     Python package: loader, kernel, verifier registry + signatures, CLI
docs/                design documents (signed evidence, root key custody)
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
| CANON-SIG-011   | constraint | `Verified Fact` needs signed Records from independent registry operators |

## Install & test

```bash
pip install -e .
pip install pytest jsonschema   # for the schema-validation test
pytest -v
```

## CLI

```bash
gravit-verify examples/artifact_signed.json --bindings-dir bindings \
    --registry tests/golden/registry.json --trust-root tests/golden/trust_root.json --pretty
gravit-verify examples/artifact_weak_aggregation.json --bindings-dir bindings --pretty
```

Without `--registry`, no artifact can reach `Verified Fact` (CANON-SIG-011);
the result is capped at `Probabilistic Assessment`. The registry is only
loaded if enough root keys from `--trust-root` signed it (`<registry>.sig`,
3 of 5 for the test files). `tests/golden/registry.json`, its `.sig` and
`tests/golden/trust_root.json` contain **test keys only** (derived from
public seeds in `tools/make_golden.py`) and must never be used outside tests.

Exit code: `0` = `SUCCESS`, `3` = `DEGRADED` (claim downgraded), `1` = `REJECTED`, `2` = usage or input error.

Freshness (CANON-FRS-005): put `"evaluation_time": "YYYY-MM-DDTHH:MM:SSZ"` and
`"freshness_max_age_seconds": N` in the artifact's `context` to require every
timestamp to be at most N seconds old at that time. Without them only a
non-empty timestamp is required.

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
- `CANON-FRS-005` checks a real Freshness Bound only when the caller puts
  `evaluation_time` and `freshness_max_age_seconds` in the context; the
  right maximum age is domain-specific, so there is no built-in default.

## Decision explanations (unreleased)

`gravit-verify artifact.json … --explain` outputs the decision together with an explanation: whether
the claim was **evaluated** or **not evaluable** (e.g. no registry), the **revision** of every rule
applied, and what **independence** rests on — registry and trust-root digests, the grouping rule,
the operators involved and, for each, the evidence behind its registry entry or an explicit
"assumed, not evidenced". Two valid signatures are not proof of two independent organisations.
The kernel's decisions and golden vectors are unchanged. Details and a worked example:
[docs/decision-explanation.md](docs/decision-explanation.md), `examples/explained/`.

## v0.5 additions

- The verifier registry must be signed by at least `threshold` root keys of a pinned trust root (`TrustRoot`, `--trust-root`); the trust root itself must require more than half of its keys. Procedure: `docs/root-key-custody.md`; holders: `registry/ROOT_KEYS.md`.
- DecisionRecord gains `trust_root_digest` and `artifact_id`; `decision_id` is now a content hash (same inputs → same id), not time-based.
- Freshness Bound policy for CANON-FRS-005 via `context.evaluation_time` + `context.freshness_max_age_seconds`.
- CLI exit code `3` for `DEGRADED` (was `0`).
- 40 golden vectors (7 new for freshness).

## v0.4 additions

- `CANON-SIG-011` + `gravit_verifier/registry.py` — Records carry `key_id` and an Ed25519 `signature`; only Records signed by registered, non-revoked keys count toward `Verified Fact`, and keys of one operator count as one source. Design: `docs/sybil-design.md`; registry key custody: `docs/root-key-custody.md`.
- DecisionRecord gains `excluded_evidence` (record + reason) and `registry_digest`.
- 33 golden vectors (10 new for signed evidence), reproduced by Python and Rust.

## v0.3 additions

- `tests/golden/` + `tools/` — language-neutral golden vectors generated from this Python kernel (`python tools/make_golden.py`, replay with `python tools/verify_golden.py`).
- `rust/` — Rust port; `cd rust && cargo test` reproduces all golden vectors. Python remains the reference; see `CONFORMANCE.md`.
- `CONFORMANCE.md` — what was and was not verified, plus observed weaknesses of the reference kernel.
