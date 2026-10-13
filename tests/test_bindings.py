import json
from pathlib import Path

import pytest

try:
    import jsonschema
except ImportError:  # pragma: no cover
    jsonschema = None

from gravit_verifier.loader import load_binding_from_yaml, load_bindings_from_dir

BINDINGS_DIR = Path(__file__).parent.parent / "bindings"
SCHEMA_PATH = Path(__file__).parent.parent / "schemas" / "canonical-verification-binding-0.2.0.json"


def test_load_single_binding(tmp_path):
    yaml_content = """
requirement_id: "CANON-NAL-001"
title: "No Aggregation Laundering"
version: "1.0"
status: "normative"
kind: "state_gate"
canonical_reference: ["Gravit Canon v1.1"]
policy_obligation:
  description: "Test"
  allowed_epistemic_states: ["Verified Fact"]
verification_condition:
  required_verification_state: "COMMITTED"
decision_outcome:
  success: "Verified Fact"
  failure_states: ["REJECTED"]
traceability:
  must_link_to_evidence: true
  must_link_to_canon: true
  audit_level: "full"
"""
    file = tmp_path / "nal-001.yaml"
    file.write_text(yaml_content, encoding="utf-8")
    binding = load_binding_from_yaml(file)
    assert binding["requirement_id"] == "CANON-NAL-001"
    assert binding["status"] == "normative"
    assert binding["kind"] == "state_gate"


def test_all_bindings_load_and_are_nine():
    bindings = load_bindings_from_dir(BINDINGS_DIR)
    ids = {b["requirement_id"] for b in bindings}
    assert ids == {
        "CANON-NAL-001",
        "CANON-VAL-002",
        "CANON-VER-003",
        "CANON-IND-004",
        "CANON-FRS-005",
        "CANON-PRV-006",
        "CANON-NSD-007",
        "CANON-SIG-011",
        "CANON-RES-012",
    }


def test_state_gate_vs_constraint_split():
    bindings = load_bindings_from_dir(BINDINGS_DIR)
    gates = {b["requirement_id"] for b in bindings if b["kind"] == "state_gate"}
    constraints = {b["requirement_id"] for b in bindings if b["kind"] == "constraint"}
    assert gates == {"CANON-NAL-001", "CANON-VAL-002", "CANON-VER-003"}
    assert constraints == {"CANON-IND-004", "CANON-FRS-005", "CANON-PRV-006", "CANON-NSD-007",
                           "CANON-SIG-011", "CANON-RES-012"}


@pytest.mark.skipif(jsonschema is None, reason="jsonschema not installed")
def test_all_bindings_validate_against_schema():
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    for binding in load_bindings_from_dir(BINDINGS_DIR):
        jsonschema.validate(instance=binding, schema=schema)
