"""tools/ceremony.py: proof-of-possession checks used in the root key ceremony."""
import base64
import importlib.util
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("ceremony", ROOT / "tools" / "ceremony.py")
ceremony = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ceremony)

ARGS = ["--holder", "Test Holder", "--date", "2026-10-20"]


@pytest.fixture
def device(tmp_path):
    """Stand-in for a holder's token: only pub.pem and the signature leave it."""
    sk = Ed25519PrivateKey.generate()
    (tmp_path / "pub.pem").write_bytes(
        sk.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    )
    return sk, tmp_path


def test_plain_signature_over_challenge_is_accepted(device, capsys):
    sk, d = device
    assert ceremony.main(["challenge", *ARGS, "--out", str(d / "c.bin")]) == 0
    (d / "sig.bin").write_bytes(sk.sign((d / "c.bin").read_bytes()))
    assert ceremony.main(["verify", *ARGS, "--public-key", str(d / "pub.pem"),
                          "--signature", str(d / "sig.bin")]) == 0
    assert '"key_id"' in capsys.readouterr().out


def test_base64_signature_is_accepted(device):
    sk, d = device
    sig = base64.b64encode(sk.sign(ceremony.proof_message("Test Holder", "2026-10-20"))).decode()
    assert ceremony.main(["verify", *ARGS, "--public-key", str(d / "pub.pem"), "--signature", sig]) == 0


def test_signature_for_another_holder_fails(device):
    sk, d = device
    (d / "sig.bin").write_bytes(sk.sign(ceremony.proof_message("Someone Else", "2026-10-20")))
    assert ceremony.main(["verify", *ARGS, "--public-key", str(d / "pub.pem"),
                          "--signature", str(d / "sig.bin")]) == 1


def test_wrapped_signature_is_rejected_as_input_error(device):
    sk, d = device
    (d / "sig.bin").write_bytes(b"\x88\x75" + sk.sign(ceremony.proof_message("Test Holder", "2026-10-20")))
    assert ceremony.main(["verify", *ARGS, "--public-key", str(d / "pub.pem"),
                          "--signature", str(d / "sig.bin")]) == 2


def test_golden_registry_has_three_of_five(capsys):
    assert ceremony.main(["check-registry", str(ROOT / "tests/golden/registry.json"),
                          "--trust-root", str(ROOT / "tests/golden/trust_root.json")]) == 0
    assert "3 of 5" in capsys.readouterr().out


def test_selftest_passes():
    assert ceremony.main(["selftest"]) == 0
