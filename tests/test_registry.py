"""Registry loading, root signatures and signing-message rules (CANON-SIG-011)."""
import base64
import json

import pytest

from gravit_verifier.kernel import EvidenceRecord
from gravit_verifier.registry import (
    MalformedRecord, RegistryError, TrustRoot, VerifierRegistry, signing_message,
)


def _entry(signer, name):
    return next(v for v in json.loads(signer.registry_bytes)["verifiers"]
                if v["operator"] == f"op-{name}")


def _load(signer, verifiers, version=1):
    """Build a registry document and sign it validly, so only content rules are tested."""
    data = json.dumps({"registry_version": version, "verifiers": verifiers}).encode()
    return VerifierRegistry.from_bytes(data, signer.sign_registry(data, signer.roots[:2]), signer.trust_root)


def test_registry_digest_is_sha256_of_file_bytes(signer):
    import hashlib
    assert signer.registry.digest == hashlib.sha256(signer.registry_bytes).hexdigest()


def test_key_id_must_match_public_key(signer):
    entry = dict(_entry(signer, "v-01"), key_id="0" * 16)
    with pytest.raises(RegistryError, match="key_id"):
        _load(signer, [entry])


def test_duplicate_key_is_rejected(signer):
    entry = _entry(signer, "v-01")
    with pytest.raises(RegistryError, match="duplicates"):
        _load(signer, [entry, dict(entry, operator="someone-else")])


def test_public_key_must_be_canonical_base64_of_32_bytes(signer):
    entry = dict(_entry(signer, "v-01"), public_key=base64.b64encode(b"x" * 31).decode())
    with pytest.raises(RegistryError, match="public_key"):
        _load(signer, [entry])


def test_wrong_registry_version_is_rejected(signer):
    with pytest.raises(RegistryError, match="registry_version"):
        _load(signer, [], version=2)


# --- root signatures (v0.5.0) ------------------------------------------------

def test_registry_records_signers_and_trust_root(signer):
    assert len(signer.registry.signers) == 2
    assert signer.registry.trust_root_digest == signer.trust_root.digest


def test_too_few_root_signatures_are_rejected(signer):
    one = signer.sign_registry(signer.registry_bytes, signer.roots[:1])
    with pytest.raises(RegistryError, match="1 valid root signature"):
        VerifierRegistry.from_bytes(signer.registry_bytes, one, signer.trust_root)


def test_same_root_key_counts_once(signer):
    line = signer.sign_registry(signer.registry_bytes, signer.roots[:1])
    with pytest.raises(RegistryError, match="1 valid root signature"):
        VerifierRegistry.from_bytes(signer.registry_bytes, line * 3, signer.trust_root)


def test_registry_changed_after_signing_is_rejected(signer):
    tampered = signer.registry_bytes.replace(b'"revoked": false', b'"revoked": true', 1)
    assert tampered != signer.registry_bytes
    with pytest.raises(RegistryError, match="0 valid root signature"):
        VerifierRegistry.from_bytes(tampered, signer.registry_signatures, signer.trust_root)


def test_signatures_from_unknown_keys_do_not_count(signer):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    outsider = signer.sign_registry(signer.registry_bytes, [Ed25519PrivateKey.generate()])
    one = signer.sign_registry(signer.registry_bytes, signer.roots[:1])
    with pytest.raises(RegistryError, match="1 valid root signature"):
        VerifierRegistry.from_bytes(signer.registry_bytes, one + outsider, signer.trust_root)


def test_malformed_signature_line_is_rejected(signer):
    with pytest.raises(RegistryError, match="line 1"):
        VerifierRegistry.from_bytes(signer.registry_bytes, "just-one-field\n", signer.trust_root)


def test_trust_root_threshold_must_be_a_majority(signer):
    doc = json.loads(signer.trust_root_bytes)
    doc["threshold"] = 1  # 1 of 3 is not more than half
    with pytest.raises(RegistryError, match="more than half"):
        TrustRoot.from_bytes(json.dumps(doc).encode())


def _record(**kw):
    base = dict(record_id="r1", theta=0.9, result=True, verifier_id="v", timestamp="t",
                provenance="p", integrity_hash="h")
    base.update(kw)
    return EvidenceRecord(**base)


def test_signing_message_layout():
    msg = signing_message("art", _record()).decode()
    assert msg == "gravit-evidence-v1\nart\nr1\n0.900000\ntrue\nt\np\nh"


@pytest.mark.parametrize("kw", [
    {"theta": 0.9000001},       # more than 6 decimals
    {"theta": True},            # bool is not a number here
    {"result": "yes"},          # result must be true/false/null
    {"provenance": "a\nb"},     # line break would forge field boundaries
])
def test_malformed_records_cannot_be_signed(kw):
    with pytest.raises(MalformedRecord):
        signing_message("art", _record(**kw))
