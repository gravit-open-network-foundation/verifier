# The signed `result` of an Evidence Record (CANON-RES-012)

## Meaning

Every Evidence Record carries `result`, and the value is bound into the record's Ed25519
signature (`signing_message`, `registry.py`). Since v0.6.0 its meaning is explicit:

| `result` | Meaning | Effect on a *Verified Fact* |
|---|---|---|
| `true` | the producer's check **supports** the asserted claim | counts as support |
| `false` | the producer's check **contradicts** the claim | blocks: capped at *Probabilistic Assessment* |
| `null` | the producer's check gave **no verdict** (e.g. could not run) | supports nothing, contradicts nothing |

A *Verified Fact* needs at least 2 independent sources (CANON-IND-004 grouping, by registry
operator when a registry is loaded) whose records report `true`, and **no** counted record
reporting `false`, even if supporting records outnumber it. One contradicting producer is a
fact the decision must not hide. Counted records are the admissible ones when a verifier
registry is loaded (an unsigned or unregistered `false` cannot block a decision), otherwise all.

The decision keeps the values: `convergence_metrics["CANON-RES-012"]` lists
`contradicting_records`, `no_verdict_records` and `supporting_sources`, and the reason names
the cause. A contradicted claim and a claim without a verdict therefore produce different
decisions and different `decision_id`s.

## Correction

Up to v0.5.0 the kernel ignored `result`, and `CONFORMANCE.md` listed this as a property.
It was a defect: records signed with `result=false` or `null` counted towards a *Verified
Fact* exactly like `true`, with identical decision ids. The earlier text is kept in the
history of `CONFORMANCE.md`; the v0.5.0 tag is unchanged.

Reported on 12 October 2026 by Iman Schrock, with a reproduction against the SAFR v1.1
reference adapter (`gravit-safr-adapter` at `75bd115`, verifier at `3fc7004`, public test keys,
no payment executed):

| signed `result` | v0.5.0: second submission | v0.6.0: second submission |
|---|---|---|
| `true` | Auto-Execute, *Verified Fact* | Auto-Execute, *Verified Fact* |
| `false` | **Auto-Execute**, *Verified Fact* | Escalate, *Probabilistic Assessment* (contradicted) |
| `null` | **Auto-Execute**, *Verified Fact* | Escalate, *Probabilistic Assessment* (no verdict) |

## Golden vectors

Seven vectors cover the rule (`result_*` in `tests/golden/vectors.json`): a contradicting
record, two verdict-less records, one supporting and one verdict-less, a contradiction
outvoted 3 to 1 (still blocks), an unsigned `false` (not counted), a `false` without a
registry, and a modest claim. The outcomes and reasons of the 40 earlier vectors are
unchanged; their `decision_id`s change because every decision now lists CANON-RES-012.

## Limits

- `result` is the producer's own verdict. The kernel does not re-run the producer's check.
- A producer that signs `true` for a claim it never checked is not detected here; that is the
  independence question of `docs/decision-explanation.md` and `docs/sybil-design.md`.
- The rule only guards *Verified Fact*. Below that the state already says "not established".
