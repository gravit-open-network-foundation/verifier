"""Shared fixtures: a throwaway verifier registry and a signer for its keys."""
import base64
import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from gravit_verifier.registry import (
    TrustRoot, VerifierRegistry, key_id_for, registry_signing_message, signing_message,
)


def _raw_public(sk):
    return sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def _b64(raw):
    return base64.b64encode(raw).decode()


class TestSigner:
    """Registry with one key per operator name, signed by 2 of 3 throwaway
    root keys; signs records in place."""

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
        self.roots = [Ed25519PrivateKey.generate() for _ in range(3)]
        self.trust_root_bytes = json.dumps({
            "trust_root_version": 1,
            "threshold": 2,
            "root_keys": [{"key_id": key_id_for(_raw_public(r)), "public_key": _b64(_raw_public(r))}
                          for r in self.roots],
        }).encode()
        self.trust_root = TrustRoot.from_bytes(self.trust_root_bytes)
        self.registry_signatures = self.sign_registry(self.registry_bytes, self.roots[:2])
        self.registry = VerifierRegistry.from_bytes(
            self.registry_bytes, self.registry_signatures, self.trust_root
        )

    @staticmethod
    def sign_registry(registry_bytes, roots):
        msg = registry_signing_message(registry_bytes)
        return "".join(f"{key_id_for(_raw_public(r))} {_b64(r.sign(msg))}\n" for r in roots)

    def sign(self, artifact_id, record, key_name):
        sk = self.keys[key_name]
        record.key_id = key_id_for(_raw_public(sk))
        record.signature = base64.b64encode(sk.sign(signing_message(artifact_id, record))).decode()
        return record


@pytest.fixture
def signer():
    return TestSigner(["v-01", "v-02", "v-03"])
