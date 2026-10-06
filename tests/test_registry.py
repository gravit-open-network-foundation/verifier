"""Registry loading and signing-message rules (CANON-SIG-011)."""
import base64
import json

import pytest

from gravit_verifier.kernel import EvidenceRecord
from gravit_verifier.registry import (
    MalformedRecord, RegistryError, VerifierRegistry, signing_message,
)


def _entry(signer, name):
    return next(v for v in json.loads(signer.registry_bytes)["verifiers"]
                if v["operator"] == f"op-{name}")


def _load(verifiers):
    return VerifierRegistry.from_bytes(json.dumps({"registry_version": 1, "verifiers": verifiers}).encode())


def test_registry_digest_is_sha256_of_file_bytes(signer):
    import hashlib
    assert signer.registry.digest == hashlib.sha256(signer.registry_bytes).hexdigest()


def test_key_id_must_match_public_key(signer):
    entry = dict(_entry(signer, "v-01"), key_id="0" * 16)
    with pytest.raises(RegistryError, match="key_id"):
        _load([entry])


def test_duplicate_key_is_rejected(signer):
    entry = _entry(signer, "v-01")
    with pytest.raises(RegistryError, match="duplicates"):
        _load([entry, dict(entry, operator="someone-else")])


def test_public_key_must_be_canonical_base64_of_32_bytes(signer):
    entry = dict(_entry(signer, "v-01"), public_key=base64.b64encode(b"x" * 31).decode())
    with pytest.raises(RegistryError, match="public_key"):
        _load([entry])


def test_wrong_registry_version_is_rejected():
    with pytest.raises(RegistryError, match="registry_version"):
        VerifierRegistry.from_bytes(b'{"registry_version": 2, "verifiers": []}')


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
