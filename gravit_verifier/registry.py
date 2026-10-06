"""
Verifier registry and signed evidence (CANON-SIG-011).

See docs/sybil-design.md. A Record counts toward Verified Fact only if it is
signed by a key listed in the registry, the key is not revoked, and the
signature verifies over the exact message produced by `signing_message()`.
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


class VerifierRegistry:
    def __init__(self, keys: Dict[str, RegisteredKey], digest: str) -> None:
        self.keys = keys
        self.digest = digest  # SHA-256 hex of the registry file bytes

    @classmethod
    def from_bytes(cls, data: bytes) -> "VerifierRegistry":
        try:
            doc = json.loads(data.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as e:
            raise RegistryError(f"registry is not valid JSON: {e}") from e
        if not isinstance(doc, dict) or doc.get("registry_version") != 1:
            raise RegistryError("registry_version must be 1")
        entries = doc.get("verifiers")
        if not isinstance(entries, list):
            raise RegistryError("'verifiers' must be a list")

        keys: Dict[str, RegisteredKey] = {}
        seen_public: set = set()
        for i, v in enumerate(entries):
            if not isinstance(v, dict):
                raise RegistryError(f"verifiers[{i}] must be an object")
            pk = b64decode_strict(v.get("public_key"))
            if pk is None or len(pk) != 32:
                raise RegistryError(f"verifiers[{i}].public_key must be base64 of 32 bytes")
            kid = v.get("key_id")
            if kid != key_id_for(pk):
                raise RegistryError(f"verifiers[{i}].key_id does not match its public_key")
            operator = v.get("operator")
            if not isinstance(operator, str) or not operator:
                raise RegistryError(f"verifiers[{i}].operator must be a non-empty string")
            revoked = v.get("revoked", False)
            if not isinstance(revoked, bool):
                raise RegistryError(f"verifiers[{i}].revoked must be true or false")
            if kid in keys or pk in seen_public:
                raise RegistryError(f"verifiers[{i}] duplicates an earlier key")
            seen_public.add(pk)
            keys[kid] = RegisteredKey(kid, pk, operator, revoked)
        return cls(keys, hashlib.sha256(data).hexdigest())

    @classmethod
    def from_file(cls, path: str | Path) -> "VerifierRegistry":
        return cls.from_bytes(Path(path).read_bytes())


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
    try:
        Ed25519PublicKey.from_public_bytes(key.public_key).verify(signature, message)
    except InvalidSignature:
        return "bad_signature"
    return None
