#!/usr/bin/env python3
"""Test099 native worker adapter with token-bound RX149 arm helper.

All capture, claim, counter, privacy, and report behavior is reused from the
unchanged Test087 worker. This wrapper changes only the compiled Swift helper
and passes the coordinator's one-use token before the existing arm property.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path
import subprocess as _subprocess
import sys


TOOL_DIR = Path(__file__).resolve().parent
REPO_ROOT = TOOL_DIR.parents[1]
TEST087_WORKER = REPO_ROOT / "developer-tools/test087/native_controlled_capture.py"
TEST099_ARM_HELPER = TOOL_DIR / "arm_p2p_rx149_test099.swift"


class _WorkerSubprocessAdapter:
    """Append the one-use token only to the compiled RX149 arm helper call."""

    def __init__(self, token_state: dict[str, str | None]):
        self._token_state = token_state

    def __getattr__(self, name: str):
        return getattr(_subprocess, name)

    def run(self, args, *positional, **kwargs):
        command = list(args) if isinstance(args, (list, tuple)) else args
        if (isinstance(command, list) and command and
                Path(str(command[0])).name == "arm-p2p-rx149"):
            token = self._token_state.get("run_token")
            if not isinstance(token, str) or not token:
                raise RuntimeError("Test099 helper token was not captured")
            if "--run-token" in command:
                raise RuntimeError("Test099 helper token argument was duplicated")
            command = [*command, "--run-token", token]
        return _subprocess.run(command, *positional, **kwargs)


def configure_worker(namespace: dict) -> None:
    """Bind the worker to Test099 helper and the coordinator's ARM token."""
    namespace["HELPER_SOURCE"] = TEST099_ARM_HELPER
    token_state: dict[str, str | None] = {"run_token": None}
    original_gate = namespace.get("_wait_for_helper_gate")
    original_load = namespace.get("_load_module")
    if not callable(original_gate):
        raise RuntimeError("NATIVE_ARM_GATE_UNAVAILABLE")
    if not callable(original_load):
        raise RuntimeError("NATIVE_MODULE_LOADER_UNAVAILABLE")

    def capture_token_from_gate():
        decision, token = original_gate()
        token_state["run_token"] = token
        return decision, token

    namespace["_wait_for_helper_gate"] = capture_token_from_gate
    def load_with_test099_helper(name, path):
        module = original_load(name, path)
        if Path(path).name == "test087_controlled.py":
            module.HELPER_SOURCE = TEST099_ARM_HELPER
        return module

    namespace["_load_module"] = load_with_test099_helper
    namespace["subprocess"] = _WorkerSubprocessAdapter(token_state)


def load_test087_worker():
    """Import Test087 as a real module so hooks change function globals."""
    if TEST087_WORKER.is_symlink() or not TEST087_WORKER.is_file():
        raise RuntimeError("NATIVE_WORKER_SOURCE_UNAVAILABLE")
    spec = importlib.util.spec_from_file_location(
        "test099_native_worker_adapter_runtime", TEST087_WORKER)
    if spec is None or spec.loader is None:
        raise RuntimeError("NATIVE_WORKER_SOURCE_UNAVAILABLE")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    except Exception:
        sys.modules.pop(spec.name, None)
        raise RuntimeError("NATIVE_WORKER_SOURCE_IMPORT_FAILED")
    return module


def main() -> int:
    if TEST087_WORKER.is_symlink() or not TEST087_WORKER.is_file():
        print("NATIVE_WORKER_SOURCE_UNAVAILABLE", file=sys.stderr)
        return 2
    if TEST099_ARM_HELPER.is_symlink() or not TEST099_ARM_HELPER.is_file():
        print("TEST099_ARM_HELPER_UNAVAILABLE", file=sys.stderr)
        return 2
    try:
        worker = load_test087_worker()
        configure_worker(worker.__dict__)
    except RuntimeError as error:
        print(str(error), file=sys.stderr)
        return 2
    worker_main = worker.main
    if not callable(worker_main):
        print("NATIVE_WORKER_ENTRY_UNAVAILABLE", file=sys.stderr)
        return 2
    return int(worker_main())


if __name__ == "__main__":
    raise SystemExit(main())

