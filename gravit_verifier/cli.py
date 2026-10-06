#!/usr/bin/env python3
"""
gravit-verify — CLI for Canonical Verification Binding evaluation.

Usage:
    gravit-verify artifact.json [--bindings-dir ./bindings]
                  [--registry verifiers.json --trust-root trust_root.json]
                  [--output decision.json] [--pretty]

The registry's root signatures are read from <registry>.sig.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .loader import load_bindings_from_dir
from .registry import RegistryError, TrustRoot, VerifierRegistry
from .kernel import (
    VerifierKernel,
    VerificationRequest,
    EvidenceRecord,
    EpistemicState,
)


def load_artifact(path: Path) -> VerificationRequest:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    evidence = [
        EvidenceRecord(
            record_id=e["record_id"],
            theta=float(e["theta"]),
            result=e.get("result"),
            verifier_id=e["verifier_id"],
            timestamp=e["timestamp"],
            provenance=e["provenance"],
            integrity_hash=e["integrity_hash"],
            key_id=e.get("key_id", ""),
            signature=e.get("signature", ""),
        )
        for e in data.get("evidence", [])
    ]

    claimed = data.get("claimed_state")
    claimed_state = EpistemicState(claimed) if claimed else None

    return VerificationRequest(
        artifact_id=data["artifact_id"],
        claimed_state=claimed_state,
        evidence=evidence,
        context=data.get("context", {}),
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Gravit Canonical Verifier")
    parser.add_argument("artifact", type=Path, help="Path to artifact.json")
    parser.add_argument("--bindings-dir", type=Path, default=Path("bindings"))
    parser.add_argument("--registry", type=Path,
                        help="Verifier registry JSON (signatures in <file>.sig); required for Verified Fact")
    parser.add_argument("--trust-root", type=Path,
                        help="Pinned root keys that must have signed the registry; required with --registry")
    parser.add_argument("--output", "-o", type=Path, help="Write DecisionRecord to file")
    parser.add_argument("--pretty", action="store_true", help="Pretty-print JSON")
    args = parser.parse_args()

    if not args.artifact.exists():
        print(f"Error: artifact file not found: {args.artifact}", file=sys.stderr)
        sys.exit(2)

    if not args.bindings_dir.exists():
        print(f"Error: bindings directory not found: {args.bindings_dir}", file=sys.stderr)
        sys.exit(2)

    kernel = VerifierKernel()
    if args.registry:
        if not args.trust_root:
            print("Error: --registry requires --trust-root", file=sys.stderr)
            sys.exit(2)
        try:
            root = TrustRoot.from_file(args.trust_root)
            kernel.load_verifier_registry(VerifierRegistry.from_file(args.registry, root))
        except (OSError, RegistryError) as e:
            print(f"Error: cannot use verifier registry {args.registry}: {e}", file=sys.stderr)
            sys.exit(2)
    for binding in load_bindings_from_dir(args.bindings_dir):
        kernel.load_binding(binding)

    request = load_artifact(args.artifact)
    decision = kernel.verify(request)

    output = decision.to_json(indent=2 if args.pretty else None)

    if args.output:
        args.output.write_text(output, encoding="utf-8")
        print(f"Decision written to {args.output}")
    else:
        print(output)

    # 0 = claim justified, 3 = downgraded, 1 = rejected (2 = usage/input error).
    sys.exit({"SUCCESS": 0, "DEGRADED": 3}.get(decision.status.value, 1))


if __name__ == "__main__":
    main()
