"""
Verifier registry and signed evidence (CANON-SIG-011).

See docs/sybil-design.md. A Record counts toward Verified Fact only if it is
signed by a key listed in the registry, the key is not revoked, and the
signature verifies over the exact message produced by `signing_message()`.

Since v0.5.0 the registry itself is only accepted if at least `threshold`
root keys of a pinned TrustRoot have signed it (docs/root-key-custody.md).
"""

from __future__ import annotations

import base64
import hashlib
import json
import math
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

SIGNING_DOMAIN = "gravit-evidence-v1"
REGISTRY_SIGNING_DOMAIN = b"gravit-registry-v1\n"


class RegistryError(ValueError):
    """The registry file is invalid; the kernel must not use it."""


class MalformedRecord(ValueError):
    """The Record cannot be turned into a signing message."""


@dataclass(frozen=True)
class RegisteredKey:
    key_id: str
    public_key: bytes
    operator: str
    revoked: bool
    # Optional references to the evidence behind this operator assignment (e.g. the signed
    # independence statement under registry/POLICY.md section 3). Informative only: the kernel's
    # decisions do not depend on it; gravit_verifier.explain reports it.
    independence_evidence: Tuple[Dict[str, str], ...] = ()


def key_id_for(public_key: bytes) -> str:
    """First 16 hex chars of SHA-256 over the raw 32-byte public key."""
    return hashlib.sha256(public_key).hexdigest()[:16]


def b64decode_strict(s: Any) -> Optional[bytes]:
    """Standard base64 with padding; None unless `s` is its canonical encoding."""
    if not isinstance(s, str):
        return None
    try:
        raw = base64.b64decode(s, validate=True)
    except ValueError:
        return None
    return raw if base64.b64encode(raw).decode("ascii") == s else None


def _is_exact_int(value: Any, expected: int) -> bool:
    """JSON integer equal to `expected`; rejects 1.0 and true (Python treats both as 1)."""
    return isinstance(value, int) and not isinstance(value, bool) and value == expected


def _public_key_entries(entries: Any, what: str) -> List[Tuple[str, bytes, Dict[str, Any]]]:
    """Validate a list of {key_id, public_key, ...}: canonical base64 of 32
    bytes, key_id derived from the key, no duplicates."""
    if not isinstance(entries, list):
        raise RegistryError(f"'{what}' must be a list")
    out: List[Tuple[str, bytes, Dict[str, Any]]] = []
    seen_ids: set = set()
    seen_public: set = set()
    for i, v in enumerate(entries):
        if not isinstance(v, dict):
            raise RegistryError(f"{what}[{i}] must be an object")
        pk = b64decode_strict(v.get("public_key"))
        if pk is None or len(pk) != 32:
            raise RegistryError(f"{what}[{i}].public_key must be base64 of 32 bytes")
        kid = v.get("key_id")
        if kid != key_id_for(pk):
            raise RegistryError(f"{what}[{i}].key_id does not match its public_key")
        if kid in seen_ids or pk in seen_public:
            raise RegistryError(f"{what}[{i}] duplicates an earlier key")
        seen_ids.add(kid)
        seen_public.add(pk)
        out.append((kid, pk, v))
    return out


def _independence_evidence(value: Any, i: int) -> Tuple[Dict[str, str], ...]:
    """Optional list of {"type", "sha256", "ref"?} entries; sha256 is the digest of the evidence document."""
    if value is None:
        return ()
    if not isinstance(value, list):
        raise RegistryError(f"verifiers[{i}].independence_evidence must be a list")
    out = []
    for j, e in enumerate(value):
        if not isinstance(e, dict) or not isinstance(e.get("type"), str) or not e["type"]:
            raise RegistryError(f"verifiers[{i}].independence_evidence[{j}] needs a non-empty 'type'")
        digest = e.get("sha256")
        if not isinstance(digest, str) or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
            raise RegistryError(f"verifiers[{i}].independence_evidence[{j}].sha256 must be 64 lowercase hex characters")
        ref = e.get("ref", "")
        if not isinstance(ref, str):
            raise RegistryError(f"verifiers[{i}].independence_evidence[{j}].ref must be a string")
        out.append({"type": e["type"], "sha256": digest, "ref": ref})
    return tuple(out)


def _verify(public_key: bytes, signature: bytes, message: bytes) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, message)
        return True
    except (InvalidSignature, ValueError):
        return False


class TrustRoot:
    """Pinned root public keys and the number of them that must sign a
    registry. Comes from deployment configuration, never from the registry."""

    def __init__(self, keys: Dict[str, bytes], threshold: int, digest: str) -> None:
        self.keys = keys
        self.threshold = threshold
        self.digest = digest  # SHA-256 hex of the trust root file bytes

    @classmethod
    def from_bytes(cls, data: bytes) -> "TrustRoot":
        try:
            doc = json.loads(data.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as e:
            raise RegistryError(f"trust root is not valid JSON: {e}") from e
        if not isinstance(doc, dict) or not _is_exact_int(doc.get("trust_root_version"), 1):
            raise RegistryError("trust_root_version must be 1")
        entries = _public_key_entries(doc.get("root_keys"), "root_keys")
        threshold = doc.get("threshold")
        if isinstance(threshold, bool) or not isinstance(threshold, int) or threshold < 1:
            raise RegistryError("threshold must be a positive integer")
        if threshold > len(entries):
            raise RegistryError("threshold is larger than the number of root keys")
        if 2 * threshold <= len(entries):
            raise RegistryError("threshold must be more than half of the root keys")
        return cls({kid: pk for kid, pk, _ in entries}, threshold, hashlib.sha256(data).hexdigest())

    @classmethod
    def from_file(cls, path: str | Path) -> "TrustRoot":
        return cls.from_bytes(Path(path).read_bytes())


def registry_signing_message(registry_bytes: bytes) -> bytes:
    """What a root key holder signs: a domain tag plus the exact file bytes."""
    return REGISTRY_SIGNING_DOMAIN + registry_bytes


def verify_registry_signatures(data: bytes, signatures: str, root: TrustRoot) -> List[str]:
    """Check the detached signature file (one `<root key_id> <base64 signature>`
    per line; blank lines and lines starting with '#' are ignored). Returns the
    sorted key_ids of distinct root keys with a valid signature; raises
    RegistryError if they are fewer than root.threshold. Lines from keys not
    in the trust root, or with a wrong signature, are not counted."""
    message = registry_signing_message(data)
    signers: set = set()
    for n, raw in enumerate(signatures.split("\n"), 1):
        line = raw.strip(" \t\r")
        if not line or line.startswith("#"):
            continue
        parts = line.split(" ")
        if len(parts) != 2 or not parts[0] or not parts[1]:
            raise RegistryError(f"signature line {n} must be '<key_id> <signature>'")
        kid, sig_text = parts
        sig = b64decode_strict(sig_text)
        if sig is None or len(sig) != 64:
            raise RegistryError(f"signature line {n} is not base64 of 64 bytes")
        if kid in root.keys and _verify(root.keys[kid], sig, message):
            signers.add(kid)
    if len(signers) < root.threshold:
        raise RegistryError(
            f"registry has {len(signers)} valid root signature(s), {root.threshold} required"
        )
    return sorted(signers)


class VerifierRegistry:
    def __init__(
        self, keys: Dict[str, RegisteredKey], digest: str, trust_root_digest: str, signers: List[str]
    ) -> None:
        self.keys = keys
        self.digest = digest  # SHA-256 hex of the registry file bytes
        self.trust_root_digest = trust_root_digest
        self.signers = signers  # root key_ids whose signatures verified

    @classmethod
    def from_bytes(cls, data: bytes, signatures: str, trust_root: TrustRoot) -> "VerifierRegistry":
        """Accept the registry only if enough root keys signed these exact bytes."""
        signers = verify_registry_signatures(data, signatures, trust_root)
        try:
            doc = json.loads(data.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as e:
            raise RegistryError(f"registry is not valid JSON: {e}") from e
        if not isinstance(doc, dict) or not _is_exact_int(doc.get("registry_version"), 1):
            raise RegistryError("registry_version must be 1")

        keys: Dict[str, RegisteredKey] = {}
        for i, (kid, pk, v) in enumerate(_public_key_entries(doc.get("verifiers"), "verifiers")):
            operator = v.get("operator")
            if not isinstance(operator, str) or not operator:
                raise RegistryError(f"verifiers[{i}].operator must be a non-empty string")
            revoked = v.get("revoked", False)
            if not isinstance(revoked, bool):
                raise RegistryError(f"verifiers[{i}].revoked must be true or false")
            keys[kid] = RegisteredKey(kid, pk, operator, revoked, _independence_evidence(v.get("independence_evidence"), i))
        return cls(keys, hashlib.sha256(data).hexdigest(), trust_root.digest, signers)

    @classmethod
    def from_file(cls, path: str | Path, trust_root: TrustRoot) -> "VerifierRegistry":
        """Reads `path` and its detached signatures from `path` + '.sig'."""
        path = Path(path)
        sig_path = path.with_name(path.name + ".sig")
        return cls.from_bytes(path.read_bytes(), sig_path.read_text(encoding="utf-8"), trust_root)


def signing_message(artifact_id: str, record: Any) -> bytes:
    """The exact bytes a verifier signs. Raises MalformedRecord."""
    text_fields = [
        artifact_id,
        record.record_id,
        record.timestamp,
        record.provenance,
        record.integrity_hash,
    ]
    for value in text_fields:
        if not isinstance(value, str) or "\n" in value or "\r" in value:
            raise MalformedRecord("text fields must be strings without line breaks")

    theta = record.theta
    if isinstance(theta, bool) or not isinstance(theta, (int, float)) or not math.isfinite(theta):
        raise MalformedRecord("theta must be a finite number")
    theta_text = f"{theta:.6f}"
    if float(theta_text) != float(theta):
        raise MalformedRecord("theta must have at most 6 decimals")

    if record.result is True:
        result = "true"
    elif record.result is False:
        result = "false"
    elif record.result is None:
        result = "null"
    else:
        raise MalformedRecord("result must be true, false or null")

    lines = [
        SIGNING_DOMAIN,
        artifact_id,
        record.record_id,
        theta_text,
        result,
        record.timestamp,
        record.provenance,
        record.integrity_hash,
    ]
    return "\n".join(lines).encode("utf-8")


def screen_evidence(
    registry: VerifierRegistry, artifact_id: str, evidence: List[Any]
) -> Tuple[List[Tuple[Any, str]], List[Dict[str, str]]]:
    """Split evidence into admissible (record, operator) pairs and excluded
    {record_id, reason} entries. Check order is fixed (see design §5)."""
    admissible: List[Tuple[Any, str]] = []
    excluded: List[Dict[str, str]] = []
    for e in evidence:
        reason = _exclusion_reason(registry, artifact_id, e)
        if reason is None:
            admissible.append((e, registry.keys[e.key_id].operator))
        else:
            excluded.append({"record_id": e.record_id, "reason": reason})
    return admissible, excluded


def _exclusion_reason(registry: VerifierRegistry, artifact_id: str, e: Any) -> Optional[str]:
    if not e.key_id or not e.signature:
        return "unsigned"
    key = registry.keys.get(e.key_id)
    if key is None:
        return "unknown_key"
    if key.revoked:
        return "revoked_key"
    try:
        message = signing_message(artifact_id, e)
    except MalformedRecord:
        return "malformed"
    signature = b64decode_strict(e.signature)
    if signature is None or len(signature) != 64:
        return "bad_signature"
    if not _verify(key.public_key, signature, message):
        return "bad_signature"
    return None
