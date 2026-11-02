#!/usr/bin/env python3
"""Small Test121 adapter for shared receipt and HAL-lifecycle primitives.

It reuses Test120's candidate-neutral source-freeze and lifecycle validators,
but owns the Test121 lifecycle schema. It performs no system or network I/O.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path
import sys


REPO_ROOT = Path(__file__).resolve().parents[2]
SHARED_CONTRACT_PATH = REPO_ROOT / "developer-tools/test120/test120_capture_contract.py"


def _load_shared_contract():
    if SHARED_CONTRACT_PATH.is_symlink() or not SHARED_CONTRACT_PATH.is_file():
        raise RuntimeError("TEST121_SHARED_CONTRACT_UNAVAILABLE")
    spec = importlib.util.spec_from_file_location(
        "test121_shared_receipt_contract", SHARED_CONTRACT_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("TEST121_SHARED_CONTRACT_UNAVAILABLE")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


_SHARED = _load_shared_contract()
ContractError = _SHARED.ContractError
read_private_document = _SHARED.read_private_document
verify_source_freeze_raw = _SHARED.verify_source_freeze_raw


def report_final_probe_sample(properties: dict, *, sample_index: int) -> dict:
    """Copy only the shared helper's whitelisted numeric lifecycle fields."""
    result = _SHARED.report_final_probe_sample(properties, sample_index=sample_index)
    return {**result, "schema": "test121-native-p2p-probe-lifecycle/v1"}
