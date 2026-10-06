# Design: signed evidence and a verifier registry (Sybil resistance)

Status: **implemented in 0.4.0** (Python reference + Rust port, 33 golden vectors).
Scope: new Binding `CANON-SIG-011` (signed evidence), which tightens how
`CANON-IND-004` (independent production of Records) is evaluated.
Decisions taken on 2026-10-06 are recorded in §9.

## 1. Problem

Since v0.3.1 the kernel treats Records that share a `verifier_id` or a
`provenance` as one source. But both fields are self-declared strings. A
single actor who writes `verifier_id: "v-01"` on one Record and `"v-02"` on
another is counted as two independent sources and can reach *Verified Fact*
alone. Nothing ties a Record to who actually produced it.

## 2. Goal and non-goals

Goal: a Record counts toward independence only if

1. it was signed by a key the kernel knows, and
2. its key belongs to an operator different from the operators of the other
   counted Records.

Non-goals for 0.4.0:

- Deciding who may be in the registry, or proving that two operators are
  really different organisations. The registry is trusted input (§7).
- Key rotation schedules, expiry by time, or online revocation checks.
- Proving that θ or `result` is true. A valid signature proves only who
  produced the Record, not that its content is correct.

## 3. Verifier registry

A JSON file, loaded alongside the Bindings (JSON so the Rust port needs no
YAML parser):

```json
{
  "registry_version": 1,
  "verifiers": [
    {
      "key_id": "k-7f3a…",
      "public_key": "base64 of the 32-byte Ed25519 public key",
      "operator": "operator-A",
      "revoked": false
    }
  ]
}
```

- `key_id` = first 16 hex chars of SHA-256 over the raw public key. The
  loader recomputes it and rejects the file if it does not match, so a
  `key_id` cannot be chosen freely.
- `operator` names the control plane. All keys with the same `operator` are
  one source.
- Duplicate `key_id`s, or a public key listed twice, make the file invalid.
- The DecisionRecord gets a new field `registry_digest` (SHA-256 of the
  registry file bytes), so an auditor can see which registry a decision used.

## 4. Signed Records

`EvidenceRecord` gets two new fields: `key_id` and `signature` (base64,
Ed25519). `verifier_id` remains as a human-readable label but no longer
counts toward independence.

Signed message: a fixed UTF-8 byte string, one field per line, with no
JSON canonicalisation (so Python and Rust cannot disagree on float or key
formatting):

```
gravit-evidence-v1
<artifact_id>
<record_id>
<theta formatted with exactly 6 decimals>
<result as "true" | "false" | "null">
<timestamp>
<provenance>
<integrity_hash>
```

- `artifact_id` is included so a Record cannot be replayed into another
  artifact.
- θ is signed as a 6-decimal string. A Record whose θ has more than 6
  decimals is rejected, so the signed and the evaluated value are equal.
- No field may contain a newline; such a Record is rejected.
- Ed25519 signatures are deterministic, so golden vectors stay stable.

## 5. Independence rule (replaces §3.1 behaviour of v0.3.1)

1. **Filter.** A Record is *admissible* only if its `key_id` is in the
   registry, the key is not revoked, and the signature verifies. All other
   Records are excluded from the convergence count and listed in the
   DecisionRecord with a reason, checked in this order: `unsigned` (no
   `key_id` or no `signature`), `unknown_key`, `revoked_key`, `malformed`,
   `bad_signature`.
2. **Group.** Among admissible Records, Records sharing an `operator` or a
   `provenance` (directly or via a chain) are one source. This is the v0.3.1
   rule with `operator` in place of `verifier_id`.
3. **Represent.** Each source counts once, with its lowest-θ Record
   (unchanged from v0.3.1).
4. Convergence (`h > 0.7`, `f < 0.3`, ≥ 2 sources) is computed on the
   representatives, unchanged.

Excluded Records never raise the state; they can only fail to help. An
artifact whose Records are all excluded behaves like an artifact with no
evidence. A bad signature does **not** reject the whole artifact (decision
3 in §9): the remaining admissible Records are still evaluated.

## 6. Rollout

Default (decision 1 in §9): **a registry is required to reach *Verified Fact*.**

- With a registry: rules of §5 apply.
- Without a registry: the kernel caps the result at *Probabilistic
  Assessment* and says so in `reason`. Unsigned Records can still support
  the lower states, as today.

Consequence: every existing golden vector that reaches *Verified Fact*
(currently 8 of 23) would need a registry and signatures. The plan is to
regenerate them with deterministic test keys (seeds fixed in
`tools/make_golden.py`, never used outside tests), and to add vectors for
each exclusion reason, for two keys of one operator, and for a Record
replayed from another artifact.

The rejected alternative (opt-in: enforce signatures only when a registry
is loaded) would keep all existing vectors unchanged but leave the current
hole open by default.

## 7. What this does and does not protect against

| Attack | Protected? |
|---|---|
| Invent new `verifier_id` strings to look like several sources | Yes — strings no longer count; only registered keys do |
| Forge a Record in the name of a registered verifier | Yes — needs that verifier's private key |
| Copy a valid Record into another artifact | Yes — `artifact_id` is signed |
| Change θ or other fields of a signed Record | Yes — signature fails |
| One operator using several registered keys | Yes — grouped by `operator` |
| Registry lists the same real organisation under two operator names | **No** — the registry is trusted |
| A verifier's private key is stolen | Only after it is marked `revoked` |
| Registered verifiers collude and sign false Records | **No** — signatures prove origin, not truth |

In short, trust moves from "whatever the submitter writes" to "whoever
maintains the registry". That is a real improvement, but the registry's
governance becomes the security boundary and must be described before any
regulator-facing claim of Sybil resistance.

## 8. Implementation plan (after this document is accepted)

1. New Binding `bindings/CANON-SIG-011.yaml` (`kind: constraint`).
   Python: registry loader, signature check, new independence rule.
   New dependency: `cryptography` (Ed25519).
2. Golden vectors regenerated with test keys; new vectors per §6.
3. Rust: same rules. New dependencies: `ed25519-dalek`, `sha2`, `base64`.
   Must reproduce all vectors.
4. JSON Schema and `examples/` updated; `CONFORMANCE.md` §3.1 rewritten.
5. One PR, CI green, then tag `v0.4.0`.

## 9. Decisions

1. **Default:** a registry is required to reach *Verified Fact*. Without
   one, the result is capped at *Probabilistic Assessment*.
2. **Binding:** a new Binding, `CANON-SIG-011` "Evidence must be signed by a
   registered key". IDs 008–010 are left free because other drafts use
   `CANON-CNF-008`, `CANON-SYB-009` and `CANON-PII-010`. `CANON-IND-004`
   is unchanged (it still groups by `verifier_id`/`provenance`);
   `CANON-SIG-011` adds the stricter check on signed Records grouped by
   `operator`. SIG-011 *caps* the state at Probabilistic Assessment instead
   of stepping it down, so it never double-penalises a Record set that
   another constraint already demoted.
3. **Excluded Records:** dropped from the count and listed with a reason;
   the artifact itself is not rejected.
4. **Registry governance:** see §10 (recommendation, to be confirmed by the
   Foundation before any external claim of Sybil resistance).

## 10. Registry governance (recommendation)

Who maintains it:

- The **Gravit Open Network Foundation** is the registry operator. The
  registry lives in this repository as `registry/verifiers.json`, so its
  full history is the git log.
- Changes (adding an operator or key, revoking a key) only via pull request,
  approved by **at least two maintainers**, with branch protection on `main`
  so nobody can push around review. The PR states who the operator is and
  how their identity was checked.
- **Operators generate their own keys** and submit only the public key. The
  Foundation never holds a verifier's private key.
- Admission criteria for operators (for example: identifiable legal entity,
  named contact, statement of no common control with existing operators)
  are written down in `registry/POLICY.md` before the first real operator
  is added.
- Revocation can be requested by the operator itself or decided by the
  maintainers; it is a normal PR, merged with priority.

Whether to sign the registry itself — yes, in two steps:

- **0.4.0:** no registry signature. Every DecisionRecord carries
  `registry_digest`, so it is always provable which registry a decision
  used, and the git history shows who approved that registry.
- **0.5.0:** the registry gets detached Ed25519 signatures
  (`registry/verifiers.json.sig`) from Foundation **root keys** kept
  offline — 3 of 5 holders, see `root-key-custody.md`. The kernel accepts a
  registry only if enough signatures verify against root public keys pinned
  in its configuration. This protects
  deployments that receive the registry outside this repository (mirrors,
  devices, xApps). It is deferred because the hard part is not the code but
  the custody of the root key: who holds it, where, and what happens if it
  is lost. That procedure should exist before the code depends on it.

Until §10 is confirmed and `registry/POLICY.md` exists, the registry in this
repository contains **test keys only**, and documentation must not claim
Sybil resistance — only "signed, registry-bound evidence".
