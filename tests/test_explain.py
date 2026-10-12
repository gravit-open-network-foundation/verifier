"""Decision explanations: evaluated vs not evaluable, rule revisions, independence basis."""

import json
import subprocess
import sys
from pathlib import Path

import pytest

from gravit_verifier.registry import RegistryError, _independence_evidence

ROOT = Path(__file__).resolve().parent.parent
EX = ROOT / "examples" / "explained"


@pytest.fixture(scope="module")
def cases():
    subprocess.run([sys.executable, str(ROOT / "tools" / "make_explained_examples.py")], check=True, capture_output=True)
    return {p.stem: json.loads(p.read_text()) for p in EX.glob("case-*.json")}


def x(cases, name):
    return cases[name]["explanation"]


def test_evidenced_operators(cases):
    e = x(cases, "case-1-two-evidenced-operators")
    assert e["evaluation"]["result"] == "evaluated"
    assert {o["status"] for o in e["independence"]["operators"]} == {"evidenced"}
    assert e["independence"]["registry_digest"] and e["independence"]["limits"]


def test_assumed_operator_is_marked(cases):
    e = x(cases, "case-2-one-operator-assumed")
    assert e["outcome"]["status"] == "SUCCESS"  # the kernel's decision is unchanged ...
    statuses = {o["operator"]: o["status"] for o in e["independence"]["operators"]}
    assert statuses["Example Operator C GmbH"] == "assumed, not evidenced"  # ... but the assumption is explicit
    assert "assumed" in e["independence"]["conclusion"]


def test_one_operator_is_one_source(cases):
    e = x(cases, "case-3-two-keys-one-operator")
    assert len(e["independence"]["operators"]) == 1
    assert "one source" in e["independence"]["conclusion"]


def test_no_registry_is_not_an_evaluated_denial(cases):
    e = x(cases, "case-4-no-registry")
    assert e["evaluation"]["result"] == "not_evaluable"
    assert e["outcome"]["status"] != "SUCCESS"


def test_rule_revisions_are_reported(cases):
    rules = x(cases, "case-1-two-evidenced-operators")["rules_applied"]
    assert rules and all(r["revision"] for r in rules)


def test_explanation_does_not_change_golden_decisions():
    out = subprocess.run([sys.executable, str(ROOT / "tools" / "verify_golden.py")], capture_output=True, text=True)
    assert out.returncode == 0, out.stdout[-500:]


@pytest.mark.parametrize("bad", ["x", [{"type": "", "sha256": "0" * 64}], [{"type": "t", "sha256": "ABC"}],
                                 [{"type": "t", "sha256": "0" * 64, "ref": 3}]])
def test_malformed_independence_evidence_rejected(bad):
    with pytest.raises(RegistryError):
        _independence_evidence(bad, 0)
