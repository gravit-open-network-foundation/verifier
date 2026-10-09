# Root key custody for the verifier registry

Status: **proposal.** Needed before 0.5.0 (registry signature, see
`sybil-design.md` §10). Names of key holders are decided by the Gravit Open
Network Foundation and are not part of this document.

## 1. What the root key protects

The registry (`registry/verifiers.json`) decides which keys count as
independent verifiers. Whoever can sign a registry that kernels accept can
add fake operators and so defeat `CANON-SIG-011` and `CANON-IND-004`. The
root key is therefore the single most valuable secret in the system.

## 2. Recommended shape: 3-of-5 root keys, not one key

Instead of one root key, the Foundation creates **five independent Ed25519
root keys**, each held by a different person. A registry is accepted only
if it carries valid signatures from **at least three** of them.

Why this and not one key split into shares (Shamir):

- No moment ever exists where the full secret is reassembled on one
  machine; each holder signs separately.
- Losing up to two keys does not stop the system; stealing up to two keys
  does not let anyone sign.
- Every signature is visible: the registry file shows *which* holders
  approved it.

The 3-of-5 numbers are a starting point; the rule is "more than half must
sign, and losing a minority must not lock us out".

Effect on 0.5.0 code: the kernel pins **five** root public keys and a
threshold of three, not one key. This is the only part of this document that
changes code.

## 3. Holders

- Five people, chosen by the Foundation. At most two from the same
  organisation, ideally in at least two jurisdictions.
- No holder may also be the sole maintainer able to merge registry PRs
  (separates "approve the change" from "sign the result").
- Each holder signs a short written acceptance of these rules.
- The list of holders and their root public keys is published in
  `registry/ROOT_KEYS.md`.

## 4. Key generation (one-time ceremony)

Before the ceremony, run the dry run in `ceremony-dry-run.md` with one
device; `tools/ceremony.py` checks proofs (step 3) and prints the entries
for `trust_root.json` and `ROOT_KEYS.md` (step 4).

1. Each holder generates their key **on their own device**, preferably a
   hardware security key that supports Ed25519 and does not allow export of
   the private key. Fallback: an air-gapped computer that never connects to
   a network, with the key in an encrypted file.
2. The private key never leaves that device. If an encrypted backup is made,
   it is stored in a different physical place from the device.
3. Each holder sends only the public key, plus a signature over the text
   `gravit-root-key-v1 <holder name> <date>` to prove they hold the key.
4. Two other holders verify the proofs; the result is recorded in
   `registry/ROOT_KEYS.md` via a reviewed PR.

## 5. Signing a new registry

1. A registry change is merged on `main` through the normal PR process
   (≥ 2 maintainer approvals, see `sybil-design.md` §10).
2. Holders independently check the merged diff, then sign the exact file
   bytes (SHA-256 shown and compared out-of-band, e.g. by phone).
3. Signatures are collected into `registry/verifiers.json.sig` (one line per
   holder: key id + signature). When three are present, the registry is
   released.
4. Target time for a routine change: a few days. Emergency revocations:
   same process, holders contacted directly, target within 24 hours.

## 6. Loss, compromise, rotation

| Event | Response |
|---|---|
| One holder loses their key | Not an emergency (still ≥ 3 of 4). Holder generates a new key; the other holders sign a registry/root-key update replacing the old public key. |
| One holder's key may be stolen | Same as loss, but urgent; the old key is listed as revoked in `ROOT_KEYS.md`. Two stolen keys are still below the threshold. |
| Three or more keys lost | Signing is impossible; deployments must be updated with a new pinned root set. Prevented by keeping backups and checking §7 regularly. |
| Three or more keys stolen | Registry trust is broken. Publish an incident notice, generate a new root set, and update every deployment. |
| Holder leaves the Foundation | Handled like a planned loss: new holder, new key, old key removed. |
| Scheduled rotation | Every 2 years, one or two keys at a time, so the set is never replaced all at once. |

Changing the pinned root set requires a new kernel configuration, so it is
announced in the release notes.

## 7. Regular checks

- Once a year, each holder signs a test message to prove the key still works
  and the backup is readable. Result recorded in `ROOT_KEYS.md`.
- Any holder who cannot prove access within 30 days is treated as a lost key
  (§6).

## 8. Open points for the Foundation

Decided on 2026-10-06: threshold **3 of 5**; the five holders are named in
`registry/ROOT_KEYS.md`.

Still open:

1. Confirm that the holders satisfy §3 (organisations, jurisdictions,
   separation from registry maintainers).
2. Choose the hardware (must support Ed25519 signing without exporting the
   key).
3. Decide where encrypted backups are stored.
4. Schedule the key generation ceremony (§4).
