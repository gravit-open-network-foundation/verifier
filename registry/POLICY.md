# Verifier registry policy

Status: **draft for Foundation approval.** Until this policy is approved and
at least one operator has been admitted under it, the only registry in use
is the test registry in `tests/golden/registry.json`, and no document may
claim Sybil resistance (see `docs/sybil-design.md` §10).

## 1. Scope

This policy governs `registry/verifiers.json`: which operators and keys may
be listed, how they are added and revoked, and who decides. The registry is
what `CANON-SIG-011` uses to decide which signed Records count toward
*Verified Fact*.

## 2. Roles

- **Registry operator:** the Gravit Open Network Foundation. It maintains
  the file in this repository.
- **Maintainers:** people with merge rights on this repository, designated by
  the Foundation.
  Every registry change involves **two different maintainers**: one opens
  the pull request, the other approves it (GitHub does not count an
  author's approval of their own pull request).
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

1. Both maintainers must be added as collaborators with write access.
2. Branch protection for `main` (1 required approval from a code owner, no
   direct pushes, CI must pass). `GravitOpenNetwork` is a personal account,
   not an organisation: this needs either GitHub Pro on that account, or
   converting it into an organisation on GitHub Team.
3. Where non-public admission evidence is stored.
4. With two maintainers, one of them unavailable blocks all changes. A third
   maintainer is advisable.
