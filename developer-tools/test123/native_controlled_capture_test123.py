#!/usr/bin/env python3
"""Tool123 wrapper delegating the unchanged Test122 native capture worker."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import sys


TOOL_DIR = Path(__file__).resolve().parent
REPO_ROOT = TOOL_DIR.parents[1]
KERNEL_WORKER = REPO_ROOT / "developer-tools/test122/native_controlled_capture_test122.py"


def _load(name: str, path: Path):
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise RuntimeError("TEST123_COMPONENT_UNAVAILABLE:" + path.name)
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError("TEST123_COMPONENT_UNAVAILABLE:" + path.name)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    except Exception:
        if sys.modules.get(spec.name) is module:
            del sys.modules[spec.name]
        raise
    return module


_KERNEL_WORKER = _load("tool123_frozen_test122_native_worker", KERNEL_WORKER)


def main() -> int:
    return int(_KERNEL_WORKER.main())


if __name__ == "__main__":
    raise SystemExit(main())
