# Decision explanations

A `DecisionRecord` says *what* was decided. A reader who trusts neither the agent nor its operator
also needs to know *on what basis*. `gravit_verifier.explain` (CLI: `gravit-verify … --explain`)
adds an explanation next to the record; the record itself and its content-addressed `decision_id`
are unchanged, and all golden vectors are reproduced as before.

The explanation answers three questions.

## 1. Was the claim evaluated?

`evaluation.result` is `evaluated` or `not_evaluable`. An evaluated denial ("the evidence does not
justify a Verified Fact") is a different fact from a check that could not be completed — for
example when no verifier registry is available, so independent signed evidence (CANON-SIG-011)
cannot be assessed at all, or when the request carries an invalid freshness policy. The reasons
are listed.

## 2. Which rules, in which revision?

`rules_applied` lists every binding with its `revision`, kind and title.

## 3. What does "independent" rest on?

Two valid signatures are not proof of two independent organisations. The verifier groups admissible
records by registry operator and by provenance, but the registry is trusted input: signature checks
cannot detect misrepresented common control or collusion (see `sybil-design.md`). The `independence`
section therefore states:

- the `registry_digest` and `trust_root_digest` the decision relied on;
- the `grouping_rule` applied;
- the `claim_evaluated` — which operators the admissible records come from;
- for each operator, the `evidence` behind its registry entry (for example the signed independence
  statement required by `registry/POLICY.md` §3, referenced by SHA-256), or the explicit status
  **`assumed, not evidenced`** when the registry entry carries none;
- a `conclusion` and the `limits` of what the signature check can establish.

Registry entries may carry the optional field
`independence_evidence: [{"type": "...", "sha256": "<64 hex>", "ref": "..."}]`. It is covered by the
root-key signatures over the registry file and does not influence the kernel's decision.

## Worked example

`python tools/make_explained_examples.py` writes `examples/explained/`: a test registry in which
two operators reference an independence statement and one does not, and four explained decisions —
two evidenced operators; one operator only assumed; two keys of one operator (one source); no
registry (not evaluable). CI regenerates the folder and fails on any byte difference.

This responds to review on the IETF AUDIT discussion: a decision record is useful input alongside
interaction records when it is bound to the action, the rule revision, the evidence references and
the outcome, and keeps an evaluated denial distinct from a check that could not be completed.
