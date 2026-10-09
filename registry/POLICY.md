# Verifier registry policy

Status: **approved by the Gravit Open Network Foundation on 2026-10-06.**
Until at least one operator has been admitted under it and the real root
keys exist (`ROOT_KEYS.md`), the only registry in use is the test registry
in `tests/golden/registry.json`, and no document may claim Sybil resistance
(see `docs/sybil-design.md` §10).

## 1. Scope

This policy governs `registry/verifiers.json`: which operators and keys may
be listed, how they are added and revoked, and who decides. The registry is
what `CANON-SIG-011` uses to decide which signed Records count toward
*Verified Fact*.

## 2. Roles

- **Registry operator:** the Gravit Open Network Foundation. It maintains
  the file in this repository, owned by the GitHub organisation
  `gravit-open-network-foundation` (GitHub Enterprise).
- **Organisation owners:** the shared Foundation account `@GravitOpenNetwork`
  and the President of the Foundation. Owners can change repository
  rules; every such change is visible in the organisation audit log.
- **Maintainers:** team `@gravit-open-network-foundation/maintainers`, role
  *Maintain* on this repository, the only code owners. Its members are
  designated by the Foundation.
  Every registry change involves **two different maintainers**: one opens
  the pull request, the other approves it (GitHub does not count an
  author's approval of their own pull request).
- **One person, one maintainer account.** Only the accounts above are code
  owners. Further accounts of the same people are in team
  `@gravit-open-network-foundation/contributors` with role *Triage*: they
  can manage issues and pull requests but cannot push or merge.
  They also cannot open pull requests from branches of this repository, so
  "approving your own pull request from a second account" is largely
  prevented technically. The rule still applies to any other route (for
  example a fork): **a maintainer must never approve a pull request opened
  from another account of their own.**
- The shared account `@GravitOpenNetwork` is not a code owner; its
  approval does not satisfy the review requirement.
- **Root key holders:** the five holders listed by role in `ROOT_KEYS.md`. From v0.5.0 a
  registry is only valid when at least three of them have signed it.
- **Operators:** organisations that run verifiers and submit Records.

## 3. Admission criteria for an operator

An operator is admitted only if all of the following are documented in the
pull request that adds it:

1. **Identifiable legal entity:** registered name, registration number,
   country.
2. **Named contact:** a person responsible for the operator's keys, with an
   address for security notices.
3. **Independence statement:** a signed statement that the operator is not
   under common control with any operator already listed (ownership,
   management, or shared infrastructure that could sign on its behalf). The
   maintainers check this against the existing list.
4. **Own key generation:** the operator generated its key pair itself; the
   Foundation never sees or holds the private key.
5. **Proof of possession:** a signature with the new key over the text
   `gravit-operator-v1 <operator name> <date>`, verified by a maintainer.
6. **Acceptance of this policy**, including the revocation rules (§5).

The `operator` field in the registry is the legal entity name from point 1.
One legal entity = one operator, however many keys it has.

## 4. Adding or changing a key

1. The operator (or a maintainer on its behalf) opens a pull request that
   edits `registry/verifiers.json` and attaches the evidence for §3.
2. CI must pass; the registry loader rejects mismatched `key_id`s and
   duplicates automatically.
3. A second maintainer, not the author, approves (enforced by branch
   protection and `.github/CODEOWNERS`). Neither maintainer may be employed
   by the operator being added.
4. After merge (from v0.5.0): root key holders sign the new file (§5 of
   `docs/root-key-custody.md`).

## 5. Revocation

A key is revoked (set `"revoked": true`, never deleted, so old decisions
stay explainable) when:

- the operator asks for it;
- the key may be compromised;
- the operator no longer meets §3 (for example, it came under common control
  with another operator);
- the operator does not respond to a security notice within 30 days.

Revocations follow §4 but are merged with priority (target: 24 hours for a
suspected compromise). An operator may appeal a revocation it did not request;
the key stays revoked during the appeal.

## 6. Record keeping

- The git history of `registry/` is the audit log. Evidence for §3 that
  cannot be public (for example contracts) is kept by the Foundation and
  referenced in the pull request by an internal reference.
- Every DecisionRecord carries `registry_digest`, so any decision can be
  traced to the exact registry version it used.

## 7. Open points before approval

1. Done 2026-10-06: repository moved to the organisation; teams
   `maintainers` (Maintain) and `contributors` (Triage) created; members
   invited.
2. Done 2026-10-06: ruleset "main protection" on the default branch — pull
   request with 1 approval from a code owner, approval after the last push,
   stale approvals dismissed, CI checks `python (3.10/3.11/3.12)` and `rust`
   required, no force push, no deletion, **no bypass for anyone**.
3. Where non-public admission evidence is stored.
4. Some maintainers are also root key holders. This is allowed (no holder is
   the *only* person able to merge), but for registry changes a reviewer who
   is not a key holder should be preferred.
5. Require two-factor authentication for the organisation once every
   member has enabled it.
