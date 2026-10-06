"""Shared fixtures: a throwaway verifier registry and a signer for its keys."""
import base64
import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from gravit_verifier.registry import VerifierRegistry, key_id_for, signing_message


def _raw_public(sk):
    return sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


class TestSigner:
    """Registry with one key per operator name; signs records in place."""

    def __init__(self, operators, revoked=()):
        self.keys = {name: Ed25519PrivateKey.generate() for name in operators}
        entries = [
            {
                "key_id": key_id_for(_raw_public(sk)),
                "public_key": base64.b64encode(_raw_public(sk)).decode(),
                "operator": f"op-{name}",
                "revoked": name in revoked,
            }
            for name, sk in self.keys.items()
        ]
        self.registry_bytes = json.dumps({"registry_version": 1, "verifiers": entries}).encode()
        self.registry = VerifierRegistry.from_bytes(self.registry_bytes)

    def sign(self, artifact_id, record, key_name):
        sk = self.keys[key_name]
        record.key_id = key_id_for(_raw_public(sk))
        record.signature = base64.b64encode(sk.sign(signing_message(artifact_id, record))).decode()
        return record


@pytest.fixture
def signer():
    return TestSigner(["v-01", "v-02", "v-03"])
