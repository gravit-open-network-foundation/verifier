"""Root key ceremony helper (docs/root-key-custody.md §4, docs/ceremony-dry-run.md).

Checks that a device produces the *plain* Ed25519 signatures the kernel
verifies, and turns a holder's public key + proof into the exact entries for
registry/trust_root.json and registry/ROOT_KEYS.md. Never handles private
keys of real holders: signing happens on the holder's own device.

    python tools/ceremony.py challenge --holder "Jane Example" --date 2026-10-20 --out challenge.bin
    python tools/ceremony.py verify    --holder "Jane Example" --date 2026-10-20 \\
                                       --public-key pub.pem --signature sig.bin
    python tools/ceremony.py registry-message registry/verifiers.json --out to-sign.bin
    python tools/ceremony.py check-registry registry/verifiers.json --trust-root registry/trust_root.json
    python tools/ceremony.py selftest

Exit code 0 = ok, 1 = check failed, 2 = bad input.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import (
    Encoding, PublicFormat, load_der_public_key, load_pem_public_key,
)

from gravit_verifier.registry import (
    RegistryError, TrustRoot, b64decode_strict, key_id_for, registry_signing_message,
    verify_registry_signatures,
)

PROOF_DOMAIN = "gravit-root-key-v1"


class InputError(ValueError):
    pass


def proof_message(holder: str, date: str) -> bytes:
    """Proof-of-possession text from root-key-custody.md §4, as exact bytes."""
    if not holder.strip() or "\n" in holder or "\r" in holder:
        raise InputError("holder must be a single non-empty line")
    if len(date) != 10 or date[4] != "-" or date[7] != "-" or not (date[:4] + date[5:7] + date[8:]).isdigit():
        raise InputError("date must be YYYY-MM-DD")
    return f"{PROOF_DOMAIN} {holder} {date}".encode("utf-8")


def read_public_key(text_or_path: str) -> bytes:
    """Raw 32-byte Ed25519 public key from: a PEM or DER file, a file holding
    base64 of the raw key, or base64 given directly."""
    p = Path(text_or_path)
    data = p.read_bytes() if p.is_file() else text_or_path.encode()
    if b"-----BEGIN" in data:
        key = load_pem_public_key(data)
    elif len(data) == 44 and data.startswith(b"\x30\x2a"):
        key = load_der_public_key(data)
    else:
        raw = b64decode_strict(data.decode("ascii", "replace").strip())
        if raw is None or len(raw) != 32:
            raise InputError("public key must be PEM, DER, or base64 of 32 raw bytes")
        return raw
    if not isinstance(key, Ed25519PublicKey):
        raise InputError("public key is not an Ed25519 key")
    return key.public_bytes(Encoding.Raw, PublicFormat.Raw)


def read_signature(text_or_path: str) -> bytes:
    """64-byte signature from a binary file, a file holding base64, or base64."""
    p = Path(text_or_path)
    if p.is_file():
        data = p.read_bytes()
        if len(data) == 64:
            return data
        text = data.decode("ascii", "replace").strip()
    else:
        text = text_or_path.strip()
    raw = b64decode_strict(text)
    if raw is None or len(raw) != 64:
        raise InputError(
            "signature must be exactly 64 bytes (plain Ed25519). Anything else, e.g. an "
            "OpenPGP or CMS signature, will not be accepted by the kernel"
        )
    return raw


def plain_ed25519_ok(public_key: bytes, signature: bytes, message: bytes) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, message)
        return True
    except Exception:
        return False


def trust_root_entry(public_key: bytes) -> dict:
    return {"key_id": key_id_for(public_key), "public_key": base64.b64encode(public_key).decode()}


def cmd_challenge(a) -> int:
    msg = proof_message(a.holder, a.date)
    Path(a.out).write_bytes(msg)
    print(f"wrote {len(msg)} bytes to {a.out}: {msg.decode()!r}")
    print(f"sha256 {hashlib.sha256(msg).hexdigest()}  (compare out-of-band before signing)")
    print("sign these exact bytes with plain Ed25519 (no hashing, no wrapper) on the device")
    return 0


def cmd_verify(a) -> int:
    msg = proof_message(a.holder, a.date)
    pk = read_public_key(a.public_key)
    sig = read_signature(a.signature)
    if not plain_ed25519_ok(pk, sig, msg):
        print("FAIL: signature does not verify as plain Ed25519 over the challenge bytes.")
        print("      Check that the device signed the exact file from `challenge` and")
        print("      produced a raw Ed25519 signature, not OpenPGP/CMS or a hash-then-sign.")
        return 1
    entry = trust_root_entry(pk)
    print("OK: plain Ed25519 proof verified; the kernel will accept this key's signatures.")
    print("\ntrust_root.json entry:")
    print(json.dumps(entry, indent=1))
    print("\nROOT_KEYS.md columns:  Root key id | Public key (base64)")
    print(f"  {entry['key_id']} | {entry['public_key']}")
    return 0


def cmd_registry_message(a) -> int:
    msg = registry_signing_message(Path(a.registry).read_bytes())
    Path(a.out).write_bytes(msg)
    print(f"wrote {len(msg)} bytes to {a.out}")
    print(f"sha256 {hashlib.sha256(msg).hexdigest()}  (every holder compares this before signing)")
    print("append one line per holder to <registry>.sig:  <root key_id> <base64 signature>")
    return 0


def cmd_check_registry(a) -> int:
    reg = Path(a.registry)
    sig = reg.with_name(reg.name + ".sig")
    root = TrustRoot.from_file(a.trust_root)
    try:
        signers = verify_registry_signatures(reg.read_bytes(), sig.read_text(encoding="utf-8"), root)
    except RegistryError as e:
        print(f"FAIL: {e}")
        return 1
    print(f"OK: {len(signers)} of {len(root.keys)} root keys signed (threshold {root.threshold}): {', '.join(signers)}")
    return 0


def cmd_selftest(a) -> int:
    """What a correct device does, end to end, with a throwaway software key."""
    sk = Ed25519PrivateKey.generate()
    pk = sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    msg = proof_message("Selftest Holder", "2026-01-01")
    good = plain_ed25519_ok(pk, sk.sign(msg), msg)
    wrong_msg = plain_ed25519_ok(pk, sk.sign(msg + b" "), msg)
    hashed = plain_ed25519_ok(pk, sk.sign(hashlib.sha256(msg).digest()), msg)
    print(f"plain signature over challenge accepted: {good}")
    print(f"signature over different bytes rejected: {not wrong_msg}")
    print(f"hash-then-sign rejected:                 {not hashed}")
    return 0 if good and not wrong_msg and not hashed else 1


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("challenge", help="write the proof-of-possession bytes to sign")
    c.add_argument("--holder", required=True); c.add_argument("--date", required=True)
    c.add_argument("--out", required=True)
    v = sub.add_parser("verify", help="check a holder's public key + proof signature")
    v.add_argument("--holder", required=True); v.add_argument("--date", required=True)
    v.add_argument("--public-key", required=True); v.add_argument("--signature", required=True)
    r = sub.add_parser("registry-message", help="write the bytes holders sign for a registry")
    r.add_argument("registry"); r.add_argument("--out", required=True)
    k = sub.add_parser("check-registry", help="count valid root signatures in <registry>.sig")
    k.add_argument("registry"); k.add_argument("--trust-root", required=True)
    sub.add_parser("selftest", help="show what a correct device does, with a software key")
    a = ap.parse_args(argv)
    try:
        return {"challenge": cmd_challenge, "verify": cmd_verify, "registry-message": cmd_registry_message,
                "check-registry": cmd_check_registry, "selftest": cmd_selftest}[a.cmd](a)
    except (InputError, RegistryError, OSError, ValueError) as e:
        print(f"Error: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
