#!/usr/bin/env python3
"""Preserve Test102 sender evidence beside Test088's compatibility view."""
from __future__ import annotations

import hashlib
import json
from typing import Any

import sender_protocol_test102 as protocol


class SenderAdapterError(ValueError):
    pass


def classify_sender_result(sender_result: Any) -> dict:
    """Strictly validate the raw event and return non-authoritative counters."""
    if not isinstance(sender_result, dict):
        raise SenderAdapterError("sender_result_not_object")
    token = sender_result.get("run_token")
    try:
        validated = protocol.validate_result(sender_result, token)
        canonical = json.dumps(sender_result, ensure_ascii=False, sort_keys=True,
                               separators=(",", ":"))
    except (protocol.SenderProtocolError, TypeError, ValueError) as error:
        raise SenderAdapterError("sender_result_validation_failed") from error
    return {
        "schema": "test102-sender-adapter/v1",
        "status": "local_sender_result_validated",
        "raw_sender_result_sha256": hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
        "frames_requested": validated.get("frames_requested"),
        "frames_attempted": validated.get("frames_attempted"),
        "frames_completed": validated.get("frames_completed"),
        "send_timing": validated.get("send_timing", []),
        "monitor_observation": validated.get("monitor_observation"),
        "raw_txs": "unknown",
        "mac_ack": "unknown",
        "rf_transmission_proven": False,
        "peer_receipt_proven": False,
        "native_awdl0_ingress_proven": False,
        "airdrop_proven": False,
        "test088_legacy_projection_is_non_authoritative": True,
    }
