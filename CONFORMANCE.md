# CONFORMANCE.md — what is actually verified (v0.4)

This file records evidence, not intent. Every line says how it was checked.
First pass: 2026-10-06, in a sandbox with Python 3.12, no Rust toolchain, no network.
Second pass: 2026-10-06, macOS, Python 3.9.6 + pytest/pyyaml/jsonschema, rustc/cargo 1.99.0.
Fourth pass (v0.4.0, signed evidence): 2026-10-06, same machine, plus `cryptography` 50.0.2, `ed25519-dalek` 2.
CI (`.github/workflows/ci.yml`) repeats these checks on Python 3.10–3.12 and stable Rust.

## 1. Verified by execution

| Claim | How checked | Result |
|---|---|---|
| 8 Bindings load; 3 `state_gate` + 5 `constraint` | ran loader + tests | pass |
| Existing test suite, incl. JSON-Schema validation of all Bindings | `pytest` with `jsonschema` installed (second pass) | 27/27 pass (fourth pass) |
| Anti-laundering: weak aggregation claiming *Verified Fact* → *Probabilistic Assessment*, `DEGRADED` | CLI on `examples/artifact_weak_aggregation.json` | as claimed |
| Genuine convergence (2 signed records from independent operators, θ≥0.7) → *Verified Fact*, `SUCCESS` | CLI on `examples/artifact_signed.json --registry tests/golden/registry.json` | as claimed |
| Same artifact without a registry → *Probabilistic Assessment*, `DEGRADED` | CLI on `examples/artifact_signed.json` | as claimed |
| Records with no signature, unknown or revoked key, bad signature (tampered θ, replay from another artifact), or malformed θ are excluded with that reason and do not reject the artifact | golden vectors `unsigned_record_excluded` … `one_bad_record_others_converge` | as claimed |
| Golden vectors: 33 cases incl. threshold boundaries, empty evidence, duplicates, shared verifier/provenance, high-impact, signed evidence | `tools/make_golden.py` → `tools/verify_golden.py` | 33/33 reproduce; regenerating gives byte-identical files (deterministic apart from `decision_id`) |
| Rust port (`rust/`) reproduces every golden vector | `cd rust && cargo test` (second pass) | builds with `-D warnings`; 33/33 vectors match |
| Rust golden test is not vacuous | changed one `expected` field in a copy of `vectors.json`, reran `cargo test` | fails with `1 vector(s) differ`, as it should |
| Rust really verifies signatures | in a copy, undid the θ tampering of `tampered_theta_bad_signature` (signature valid again), reran `cargo test` | fails with `1 vector(s) differ`, as it should |

## 2. NOT verified

- **Rust port beyond the golden vectors** — conformance means only "reproduces these 33 cases". Inputs outside them are untested; see the known divergence noted in `rust/src/lib.rs`.
- **Ed25519 edge cases** — Python (OpenSSL via `cryptography`) and Rust (`ed25519-dalek` `verify`) agree on all vectors, but no vector covers adversarial encodings (small-order keys, non-canonical points). They may disagree there.
- **Sybil resistance in practice** — the registry in this repository holds test keys only; the governance in `docs/sybil-design.md` §10 is a recommendation, not yet in place.
- **`pip install -e .` and Python ≥ 3.10** — not run locally (only Python 3.9 available, network unavailable for build deps). CI is the first place this is exercised.
- **Conformance to `draft-gravit-gevp` / `draft-gravit-verifiable-epistemic-decision`** — *no claim is made.* The Binding texts were not compared against the drafts in this check, so §5.2-style conformance statements cannot be made from this repository.

## 3. Observed properties of the reference kernel (from the golden vectors)

These are real behaviours, listed so nobody discovers them later and assumes they were hidden.

1. **Independence is declared, not proven.** Since v0.3.1, Records that share a `verifier_id` *or* a `provenance` — directly or through a chain of other Records — count as one source, represented by its lowest-θ Record (CANON-IND-004: distinct verifier-id **and** distinct provenance root). This closes the v0.3.0 hole where one verifier with two `provenance` strings, or two verifiers with one `provenance`, reached *Verified Fact* (vectors `same_verifier_diff_provenance`, `same_provenance_diff_verifier`, `chain_shared_keys_one_source`). These fields are self-declared strings, so on their own they are **not Sybil resistance**. Since v0.4.0, `CANON-SIG-011` adds that layer for *Verified Fact*: only Records signed by registered, non-revoked keys count, grouped by registry `operator`. Invented `verifier_id`s no longer help. What remains: the registry is trusted input — an operator listed twice under different names, or colluding registered operators, are not detected (see `docs/sybil-design.md` §7).
2. **`f < 0.3` is redundant.** Because the θ≥0.7 and θ<0.5 sets are disjoint, `h > 0.7` already forces `f < 0.3`. The second condition never binds.
3. **θ is self-reported input.** The kernel counts how many submitted θ values are ≥0.7; it does not compute or check them. `result` is ignored.
4. **`integrity_hash` is checked only for presence** (non-empty, and only under `high_impact`). It is never recomputed or validated as SHA3-256. Freshness checks only that a timestamp is non-empty, not that it is recent.
5. **Claiming less than the evidence supports yields `SUCCESS` with a higher final state** (`claims_lower_than_achieved`: claim *Speculative Claim*, result *Verified Fact*). Whether that is desired is a policy question.
6. **`decision_id` is time-derived**, so records are not byte-reproducible; comparisons must exclude it.
7. **`CANON-NSD-007` is informative only** (stateless kernel; no re-verification over time).
8. **The CLI exits 0 for both `SUCCESS` and `DEGRADED`.** A script that uses the exit code as "claim accepted" will accept a downgraded claim; check `status` / `final_epistemic_state` in the JSON instead.

## 4. What this repository is, and is not

It is a small, deterministic reference implementation of one specific rule — *aggregation of weak records does not by itself yield a Verified Fact* — with reproducible test vectors. It checks the **structure of submitted evidence**; it does not establish that any claim is true, does not constrain what an AI model does, and has no independent review.
