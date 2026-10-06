"""YAML loading for Canonical Verification Binding records."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Union

import yaml

PathLike = Union[str, Path]


def load_binding_from_yaml(path: PathLike) -> Dict[str, Any]:
    """Load a single Canonical Verification Binding from a YAML file."""
    path = Path(path)
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    if not isinstance(data, dict):
        raise ValueError(f"Invalid Binding file: {path}")
    if "requirement_id" not in data:
        raise ValueError(f"Missing requirement_id in {path}")
    return data


def load_bindings_from_dir(directory: PathLike) -> List[Dict[str, Any]]:
    """Load all *.yaml / *.yml Binding files from a directory, sorted by
    requirement_id for deterministic ordering."""
    dir_path = Path(directory)
    files = sorted(dir_path.glob("*.yaml")) + sorted(dir_path.glob("*.yml"))
    bindings = [load_binding_from_yaml(f) for f in files]
    bindings.sort(key=lambda b: b["requirement_id"])
    return bindings
