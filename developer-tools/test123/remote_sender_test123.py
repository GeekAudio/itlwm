#!/usr/bin/env python3
"""Build the bounded Test123 router transaction without contacting a router."""
from __future__ import annotations

import hashlib
import importlib.util
from pathlib import Path
import re
import sys


TOOL_DIR = Path(__file__).resolve().parent
REPO_ROOT = TOOL_DIR.parents[1]
T122_STATUS_PATH = (REPO_ROOT / "developer-tools/test122/router-status/"
                    "router_status_tail_test122.py")
T123_PROTOCOL_PATH = (TOOL_DIR / "router-status/dual_sender_protocol_test123.py")
T087_BASE_PROTOCOL_PATH = REPO_ROOT / "developer-tools/test087/test087_controlled.py"
T122_STATUS_MODULE = "test123_frozen_test122_remote_builder_unpatched"
T087_BASE_PROTOCOL_MODULE = "test123_frozen_test087_base_remote_protocol"
TOKEN_RE = re.compile(r"^[0-9a-f]{32}$")
PACKET_SET_LENGTH = 536
MAX_BINARY_BYTES = 2 * 1024 * 1024
MAX_SCRIPT_BYTES = 180_000
AP_INTERFACE = "wlan7"
MONITOR_INTERFACE = "iwn102mon"
TEMP_ANCHOR = 'TMP="/tmp/iwn-test122-tail-$RUN_TOKEN"'
BIN_ANCHOR = 'BIN="$TMP/router_status_tail_test122"'
MON_ANCHOR = "MON=iwtail122"
OLD_COMMAND = ('"$BIN" --send --packet-set "$PSET" --interface "$MON" '
               '--source-interface "$AP" --nonce "$RUN_TOKEN" --wait-go <&3 &')
NEW_COMMAND = ('"$BIN" --send --packet-set "$PSET" --interface "$MON" '
               '--source-interface "$AP" --run-token "$RUN_TOKEN" --wait-go <&3 &')


class RemoteScriptError(ValueError):
    pass


def _load(name: str, path: Path):
    if path.is_symlink() or not path.is_file():
        raise RemoteScriptError("test122_status_builder_unavailable")
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RemoteScriptError("test122_status_builder_unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    except Exception as error:
        if sys.modules.get(spec.name) is module:
            del sys.modules[spec.name]
        raise RemoteScriptError("test122_status_builder_import_failed") from error
    return module


def build_remote_script(*, sender_binary: bytes, packet_set: bytes,
                        run_token: str, ap: str = AP_INTERFACE,
                        monitor: str = MONITOR_INTERFACE) -> str:
    """Create the existing cleanup-guarded monitor transaction for T123."""
    if not isinstance(sender_binary, bytes) or not sender_binary or len(sender_binary) > MAX_BINARY_BYTES:
        raise RemoteScriptError("sender_binary_size_invalid")
    if not isinstance(packet_set, bytes) or len(packet_set) != PACKET_SET_LENGTH:
        raise RemoteScriptError("packet_set_length_invalid")
    if not TOKEN_RE.fullmatch(run_token or ""):
        raise RemoteScriptError("run_token_invalid")
    if ap != AP_INTERFACE or monitor != MONITOR_INTERFACE:
        raise RemoteScriptError("interface_profile_mismatch")

    protocol = _load("test123_remote_sender_protocol", T123_PROTOCOL_PATH)
    packet_sha = hashlib.sha256(packet_set).hexdigest()
    try:
        protocol.bind_packet_set(packet_set, expected_sha256=packet_sha)
    except Exception as error:
        raise RemoteScriptError("packet_set_v2_binding_invalid") from error

    # The T122 script builder loads ``test087_controlled`` by its legacy
    # sys.modules key. In an active Test123 run that key is the shared
    # RUNNER.PROTOCOL object, whose builder has been monkeypatched back to
    # Test123; using it recurses into this function after the nonce claim.
    # Give the frozen T087 base protocol and T122 builder private module names
    # so this shell-template step cannot observe or alter the active runner.
    base_protocol = _load(T087_BASE_PROTOCOL_MODULE, T087_BASE_PROTOCOL_PATH)
    status = _load(T122_STATUS_MODULE, T122_STATUS_PATH)
    status._load_router_protocol = lambda: base_protocol
    digest = packet_sha
    try:
        script = status.build_remote_script(
            binary=sender_binary,
            binary_sha256=hashlib.sha256(sender_binary).hexdigest(),
            packet_set=packet_set,
            packet_set_sha256=digest,
            run_token=run_token)
    except Exception as error:
        raise RemoteScriptError("test122_remote_script_rejected") from error

    replacements = (
        (TEMP_ANCHOR, 'TMP="/tmp/test123-$RUN_TOKEN"'),
        (BIN_ANCHOR, 'BIN="$TMP/awdl_router_rx_lease_sender_test123"'),
        (MON_ANCHOR, "MON=iwn102mon"),
        (OLD_COMMAND, NEW_COMMAND),
    )
    for before, after in replacements:
        if script.count(before) != 1:
            raise RemoteScriptError("remote_script_anchor_mismatch")
        script = script.replace(before, after, 1)
    validate_remote_script(script, run_token=run_token,
                           packet_set_sha256=digest)
    return script


def validate_remote_script(script: str, *, run_token: str | None = None,
                           packet_set_sha256: str | None = None) -> dict:
    if not isinstance(script, str) or not script.startswith("#!/bin/sh\n"):
        raise RemoteScriptError("remote_script_invalid")
    required = (
        'TMP="/tmp/test123-$RUN_TOKEN"',
        'BIN="$TMP/awdl_router_rx_lease_sender_test123"',
        "MON=iwn102mon", 'PSET="$TMP/packetset.bin"',
        'sha256sum "$PSET"', '--verify-only --packet-set "$PSET"',
        '--source-interface "$AP"', '--run-token "$RUN_TOKEN" --wait-go',
        'AP_AFTER="$(ap_config_digest 2>/dev/null || true)"',
        "trap cleanup EXIT",
    )
    if any(item not in script for item in required):
        raise RemoteScriptError("remote_script_contract_incomplete")
    if "--nonce" in script or "--count 16" in script or "--interval-ms 80" in script:
        raise RemoteScriptError("legacy_sender_invocation_remains")
    if any(item in script for item in (
            "uci set", "uci commit", "reload_config", "wifi reload",
            'iw dev "$AP" set', "iw dev $AP set")):
        raise RemoteScriptError("remote_script_contains_router_configuration_change")
    if len(script.encode("utf-8")) > MAX_SCRIPT_BYTES:
        raise RemoteScriptError("remote_script_size_invalid")
    if run_token is not None and not TOKEN_RE.fullmatch(run_token):
        raise RemoteScriptError("run_token_invalid")
    if packet_set_sha256 is not None and not re.fullmatch(r"[0-9a-f]{64}", packet_set_sha256):
        raise RemoteScriptError("packet_set_sha_invalid")
    return {
        "valid": True,
        "schema": "test123-remote-script/v1",
        "tool_test": "Test123",
        "running_kernel_test": "Test122",
        "router_configuration_changed": False,
        "wan_lan_changed": False,
        "packet_set_sha_verified_before_go": True,
        "one_use_go": True,
        "frames": 4,
        "interval_ms": 10,
        "send_budget_ms": 40,
        "status_tail_ms": 2000,
        "driver_rx_lease_ms": 100,
    }
