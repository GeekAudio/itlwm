#!/usr/bin/env python3
"""Keep the Test101 sender's full provenance beside the frozen Test088 view.

Test088 still validates its exact, older SENDER_RESULT projection. Test101
classifies the untouched new-schema event separately. The projection is never
fed back into the provenance classifier and is not radio evidence.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import sys
from typing import Any


TOOL_DIR = Path(__file__).resolve().parent
REPO_ROOT = TOOL_DIR.parents[1]
OPENWRT_CLASSIFIER = (
    REPO_ROOT / "developer-tools/openwrt-tx-observation/openwrt_tx_observation.py")
EXPECTED_PROVENANCE_SCHEMA = "openwrt-tx-observation/v1"

# This is exactly the Test087 parser's legacy compatibility view. New fields
# stay in the original sender event; Test088's parser remains unchanged.
LEGACY_RESULT_KEYS = frozenset({
    "event", "status", "frames_attempted", "frames_completed", "sent",
    "payload_bytes", "mpdu_bytes", "radiotap_bytes", "packet_bytes",
    "udp_payload_bytes", "elapsed_ms", "deadline_hit", "error_count",
    "last_errno", "stop_reason", "tx_flags_requested", "hardware_honoring",
})


class SenderAdapterError(ValueError):
    pass


def _load_classifier():
    if OPENWRT_CLASSIFIER.is_symlink() or not OPENWRT_CLASSIFIER.is_file():
        raise SenderAdapterError("openwrt_classifier_unavailable")
    spec = importlib.util.spec_from_file_location(
        "test101_openwrt_tx_observation", OPENWRT_CLASSIFIER)
    if spec is None or spec.loader is None:
        raise SenderAdapterError("openwrt_classifier_unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    except Exception as error:
        sys.modules.pop(spec.name, None)
        raise SenderAdapterError("openwrt_classifier_import_failed") from error
    return module


CLASSIFIER = _load_classifier()
ProvenanceError = CLASSIFIER.ObservationError


def project_legacy_result(sender_result: Any) -> dict:
    """Return a copy of the exact Test088 compatibility fields only."""
    if not isinstance(sender_result, dict) or sender_result.get("event") != "SENDER_RESULT":
        raise SenderAdapterError("sender_result_invalid")
    missing = LEGACY_RESULT_KEYS - sender_result.keys()
    if missing:
        raise SenderAdapterError("legacy_projection_missing_fields")
    if sender_result.get("tx_provenance", {}).get("schema") != EXPECTED_PROVENANCE_SCHEMA:
        raise SenderAdapterError("new_provenance_schema_missing")
    return {key: sender_result[key] for key in sorted(LEGACY_RESULT_KEYS)}


def classify_sender_result(sender_result: Any) -> dict:
    """Classify full raw event and annotate only the schema adapter boundary."""
    legacy = project_legacy_result(sender_result)
    try:
        provenance = CLASSIFIER.classify_sender_result(sender_result)
    except CLASSIFIER.ObservationError:
        raise
    except Exception as error:
        raise SenderAdapterError("new_sender_classification_failed") from error
    try:
        canonical = json.dumps(sender_result, sort_keys=True,
                               separators=(",", ":"), ensure_ascii=False)
    except (TypeError, ValueError) as error:
        raise SenderAdapterError("sender_result_not_json_safe") from error
    return {
        **provenance,
        "adapter_schema": "test101-sender-schema-adapter/v1",
        "raw_sender_result_sha256": hashlib.sha256(
            canonical.encode("utf-8")).hexdigest(),
        "raw_sender_result_preserved_by_test088_capture": True,
        "test088_legacy_projection": legacy,
        "legacy_projection_is_not_rf_evidence": True,
        "rf_transmission_proven": False,
        "ack_proven": False,
        "peer_receipt_proven": False,
        "airdrop_proven": False,
    }
