# CONFORMANCE.md — what is actually verified (v0.3)

This file records evidence, not intent. Every line says how it was checked.
First pass: 2026-10-06, in a sandbox with Python 3.12, no Rust toolchain, no network.
Second pass: 2026-10-06, macOS, Python 3.9.6 + pytest/pyyaml/jsonschema, rustc/cargo 1.99.0.
CI (`.github/workflows/ci.yml`) repeats these checks on Python 3.10–3.12 and stable Rust.

## 1. Verified by execution

| Claim | How checked | Result |
|---|---|---|
| 7 Bindings load; 3 `state_gate` + 4 `constraint` | ran loader + tests | pass |
| Existing test suite, incl. JSON-Schema validation of all Bindings | `pytest` with `jsonschema` installed (second pass) | 14/14 pass (third pass, after the CANON-IND-004 fix) |
| Anti-laundering: weak aggregation claiming *Verified Fact* → *Probabilistic Assessment*, `DEGRADED` | CLI on `examples/artifact_weak_aggregation.json` | as claimed |
| Genuine convergence (2 independent records, θ≥0.7) → *Verified Fact*, `SUCCESS` | CLI on `examples/artifact_committed.json` | as claimed |
| Golden vectors: 23 cases incl. threshold boundaries, empty evidence, duplicates, shared verifier/provenance, high-impact | `tools/make_golden.py` → `tools/verify_golden.py` | 23/23 reproduce; regenerating gives byte-identical files (deterministic apart from `decision_id`) |
| Rust port (`rust/`) reproduces every golden vector | `cd rust && cargo test` (second pass) | builds with `-D warnings`; 23/23 vectors match |
| Rust golden test is not vacuous | changed one `expected` field in a copy of `vectors.json`, reran `cargo test` | fails with `1 vector(s) differ`, as it should |

## 2. NOT verified

- **Rust port beyond the golden vectors** — conformance means only "reproduces these 23 cases". Inputs outside them are untested; see the known divergence noted in `rust/src/lib.rs`.
- **`pip install -e .` and Python ≥ 3.10** — not run locally (only Python 3.9 available, network unavailable for build deps). CI is the first place this is exercised.
- **Conformance to `draft-gravit-gevp` / `draft-gravit-verifiable-epistemic-decision`** — *no claim is made.* The Binding texts were not compared against the drafts in this check, so §5.2-style conformance statements cannot be made from this repository.

## 3. Observed properties of the reference kernel (from the golden vectors)

These are real behaviours, listed so nobody discovers them later and assumes they were hidden.

1. **Independence is declared, not proven.** Since v0.3.1, Records that share a `verifier_id` *or* a `provenance` — directly or through a chain of other Records — count as one source, represented by its lowest-θ Record (CANON-IND-004: distinct verifier-id **and** distinct provenance root). This closes the v0.3.0 hole where one verifier with two `provenance` strings, or two verifiers with one `provenance`, reached *Verified Fact* (vectors `same_verifier_diff_provenance`, `same_provenance_diff_verifier`, `chain_shared_keys_one_source`). It is still **not Sybil resistance**: both fields are self-declared strings, so an actor who invents new `verifier_id`s and `provenance`s per record is counted as independent. Real resistance needs identities bound to keys/attestation, which this kernel does not have.
2. **`f < 0.3` is redundant.** Because the θ≥0.7 and θ<0.5 sets are disjoint, `h > 0.7` already forces `f < 0.3`. The second condition never binds.
3. **θ is self-reported input.** The kernel counts how many submitted θ values are ≥0.7; it does not compute or check them. `result` is ignored.
4. **`integrity_hash` is checked only for presence** (non-empty, and only under `high_impact`). It is never recomputed or validated as SHA3-256. Freshness checks only that a timestamp is non-empty, not that it is recent.
5. **Claiming less than the evidence supports yields `SUCCESS` with a higher final state** (`claims_lower_than_achieved`: claim *Speculative Claim*, result *Verified Fact*). Whether that is desired is a policy question.
6. **`decision_id` is time-derived**, so records are not byte-reproducible; comparisons must exclude it.
7. **`CANON-NSD-007` is informative only** (stateless kernel; no re-verification over time).
8. **The CLI exits 0 for both `SUCCESS` and `DEGRADED`.** A script that uses the exit code as "claim accepted" will accept a downgraded claim; check `status` / `final_epistemic_state` in the JSON instead.

## 4. What this repository is, and is not

It is a small, deterministic reference implementation of one specific rule — *aggregation of weak records does not by itself yield a Verified Fact* — with reproducible test vectors. It checks the **structure of submitted evidence**; it does not establish that any claim is true, does not constrain what an AI model does, and has no independent review.
