#!/usr/bin/env python3
"""
gravit-verify — CLI for Canonical Verification Binding evaluation.

Usage:
    gravit-verify artifact.json [--bindings-dir ./bindings] [--output decision.json] [--pretty]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .loader import load_bindings_from_dir
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

    sys.exit(0 if decision.status.value in ("SUCCESS", "DEGRADED") else 1)


if __name__ == "__main__":
    main()
