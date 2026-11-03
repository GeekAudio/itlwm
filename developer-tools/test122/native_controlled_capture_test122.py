#!/usr/bin/env python3
"""Test122 path adapter around the reviewed Test121 controlled-capture worker.

The frozen Test104 worker and Test121 sampler/terminal behavior remain shared.
Only the private candidate binding is replaced with Test122's exact bundle
validator; this process does not arm unless the parent coordinator invokes its
explicit one-use run path.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path
import sys


TOOL_DIR = Path(__file__).resolve().parent
REPO_ROOT = TOOL_DIR.parents[1]
TEST121_DIR = REPO_ROOT / "developer-tools/test121"
TEST121_WORKER_PATH = TEST121_DIR / "native_controlled_capture_test121.py"
TEST121_CONTRACT_PATH = TEST121_DIR / "test121_capture_contract.py"


def _load(name: str, path: Path):
    if path.is_symlink() or not path.is_file():
        raise RuntimeError("TEST122_COMPONENT_UNAVAILABLE:" + path.name)
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError("TEST122_COMPONENT_UNAVAILABLE:" + path.name)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


BINDING = _load("test122_worker_binding",
                TOOL_DIR / "rx149_binding_test122.py")
_WORKER = _load("test122_frozen_test121_worker", TEST121_WORKER_PATH)
_WORKER.TOOL_DIR = TOOL_DIR
_ORIGINAL_LOAD = _WORKER._load


def _load_test122_binding(name: str, path: Path):
    if Path(path).name == "rx149_binding_test121.py":
        return BINDING
    return _ORIGINAL_LOAD(name, path)


_WORKER._load = _load_test122_binding


def main() -> int:
    """Delegate CLI behavior; the worker still requires explicit arguments."""
    return int(_WORKER.main())


if __name__ == "__main__":
    raise SystemExit(main())
