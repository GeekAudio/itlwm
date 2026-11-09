#!/usr/bin/env python3
"""Test128 peer-only experiment using the unchanged Test127 driver/helper."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "developer-tools/test127"))
import coordinate_directed_test127 as previous

PRIVATE = previous.BASE / "RuntimeTest128/research/preparation-private"
SCRIPT = ROOT / "developer-tools/test128/openwrt_monitor_window128.sh"
CAPABILITY_SOURCE = ROOT / "developer-tools/test128/openwrt_active_monitor_capability128.cpp"
CHANNEL_HEADER = ROOT / "developer-tools/test110/openwrt_echo_channel.hpp"


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def validate(path):
    # Keep Test127's immutable kext, helper, deployment and target-OS evidence.
    config = previous.validate(path)
    receipt, _ = previous.read_receipt(PRIVATE / "test128-tools-private.json")
    if (config.get("prepare_peer_mac_required") is not True or
            Path(config["remote_script_path_resolved"]) != SCRIPT.resolve() or
            receipt.get("schema") != "test128-peer-tools/v1" or
            receipt.get("driver_candidate") != previous.BUILD or
            receipt.get("driver_uuid") != previous.UUID or
            receipt.get("monitor_script_sha256") != digest(SCRIPT) or
            receipt.get("capability_source_sha256") != digest(CAPABILITY_SOURCE) or
            receipt.get("channel_header_sha256") != digest(CHANNEL_HEADER) or
            receipt.get("offline_tests_passed") is not True or
            receipt.get("independent_review_passed") is not True):
        raise ValueError("Test128 peer contract or review binding mismatch")
    binary = PRIVATE / "openwrt_active_monitor_capability128"
    if (binary.is_symlink() or
            receipt.get("capability_binary_sha256") != digest(binary) or
            config.get("capability_helper_path") != str(binary) or
            config.get("capability_helper_sha256") != digest(binary)):
        raise ValueError("Test128 capability helper binding mismatch")
    return config


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--run", action="store_true")
    args = parser.parse_args()
    config = validate(args.config)
    if args.run:
        previous.verify_target_os()
        result = previous.shared.execute_run(config, build_id=previous.BUILD)
    else:
        result = previous.shared.make_plan(config, build_id=previous.BUILD)
    # The kernel build remains Test127. A tool campaign is not a new kext.
    result["tool_campaign"] = "Test128"
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0 if not args.run or result.get("orchestration_completed") is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
