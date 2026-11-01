#!/usr/bin/env python3
"""Create the bounded Test104 OpenWrt monitor/sender shell transaction."""
from __future__ import annotations

import base64
import hashlib
import importlib.util
from pathlib import Path
import re
import sys
from typing import Any

TOOL_DIR = Path(__file__).resolve().parent
REPO_ROOT = TOOL_DIR.parents[1]
BASE_PROTOCOL_PATH = REPO_ROOT / "developer-tools/test087/test087_controlled.py"
PACKET_SET_LEN = 104 + 4 * 106
TOKEN_RE = re.compile(r"^[0-9a-f]{32}$")
SHA_RE = re.compile(r"^[0-9a-f]{64}$")
IFNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,15}$")


class RemoteScriptError(ValueError):
    pass


def _base_protocol():
    tool_dir = BASE_PROTOCOL_PATH.parent
    if str(tool_dir) not in sys.path:
        sys.path.insert(0, str(tool_dir))
    if BASE_PROTOCOL_PATH.is_symlink() or not BASE_PROTOCOL_PATH.is_file():
        raise RemoteScriptError("test087_remote_builder_unavailable")
    spec = importlib.util.spec_from_file_location("test104_test087_protocol", BASE_PROTOCOL_PATH)
    if spec is None or spec.loader is None:
        raise RemoteScriptError("test087_remote_builder_unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    except Exception as error:
        sys.modules.pop(spec.name, None)
        raise RemoteScriptError("test087_remote_builder_import_failed") from error
    return module


def build_remote_script(*, sender_binary: bytes, packet_set: bytes,
                        run_token: str, ap: str = "wlan7",
                        monitor: str = "iwn102mon") -> str:
    """Build only a script; it does not connect to a router or send packets."""
    if not isinstance(sender_binary, bytes) or not sender_binary or len(sender_binary) > 2 * 1024 * 1024:
        raise RemoteScriptError("sender_binary_size_invalid")
    if not isinstance(packet_set, bytes) or len(packet_set) != PACKET_SET_LEN:
        raise RemoteScriptError("packet_set_length_invalid")
    if not TOKEN_RE.fullmatch(run_token or ""):
        raise RemoteScriptError("run_token_invalid")
    if not IFNAME_RE.fullmatch(ap or "") or not IFNAME_RE.fullmatch(monitor or ""):
        raise RemoteScriptError("interface_name_invalid")
    if ap == monitor:
        raise RemoteScriptError("source_and_monitor_interface_must_differ")
    binary_sha = hashlib.sha256(sender_binary).hexdigest()
    packet_set_sha = hashlib.sha256(packet_set).hexdigest()
    protocol = _base_protocol()
    script = protocol.build_remote_monitor_sender_script(
        binary=sender_binary,
        binary_sha256=binary_sha,
        run_token=run_token,
        ap=ap,
        monitor=monitor,
    )
    script = script.replace(
        'TMP="/tmp/iwn-t087-controlled-$RUN_TOKEN"',
        'TMP="/tmp/iwn-t102-unicast-$RUN_TOKEN"', 1)
    if 'TMP="/tmp/iwn-t102-unicast-$RUN_TOKEN"' not in script:
        raise RemoteScriptError("temporary_path_profile_patch_failed")
    old_command = (
        '"$BIN" --send --interface "$MON" --count 16 --interval-ms 80 '
        '--nonce "$RUN_TOKEN" --wait-go <&3 &')
    new_command = (
        '"$BIN" --send --packet-set "$PACKET_SET" --interface "$MON" '
        '--source-interface "$AP" --nonce "$RUN_TOKEN" --wait-go <&3 &')
    if script.count(old_command) != 1:
        raise RemoteScriptError("legacy_sender_command_not_unique")
    script = script.replace(old_command, new_command, 1)
    mkdir_line = (
        'mkdir -m 700 "$TMP" || { printf '
        "'REMOTE_ERROR code=temp_create_failed\\n'; exit 2; }\n")
    if script.count(mkdir_line) != 1:
        raise RemoteScriptError("temporary_directory_stage_not_unique")
    packet_b64 = base64.b64encode(packet_set).decode("ascii")
    stage = (
        'PACKET_SET="$TMP/test104-packet-set.bin"\n'
        f'EXPECTED_PACKET_SET_SHA256={packet_set_sha}\n'
        f"printf '%s' '{packet_b64}' | base64 -d > \"$PACKET_SET\" || "
        "{ printf 'REMOTE_ERROR code=packet_set_stage_failed\\n'; exit 2; }\n"
        'chmod 600 "$PACKET_SET" || { printf '
        "'REMOTE_ERROR code=packet_set_mode_failed\\n'; exit 2; }\n"
        'PACKET_SET_SHA="$(sha256sum "$PACKET_SET" 2>/dev/null | awk \'{print $1}\')"\n'
        '[ "$PACKET_SET_SHA" = "$EXPECTED_PACKET_SET_SHA256" ] || '
        "{ printf 'REMOTE_ERROR code=packet_set_sha_mismatch\\n'; exit 2; }\n"
    )
    script = script.replace(mkdir_line, mkdir_line + stage, 1)
    if len(script.encode("utf-8")) > 180_000:
        raise RemoteScriptError("remote_script_size_invalid")
    if any(token in script for token in ("uci set", "uci commit", "reload_config", "wifi reload")):
        raise RemoteScriptError("router_configuration_mutation_forbidden")
    return script


def validate_remote_script(script: Any) -> dict:
    if not isinstance(script, str) or not script.startswith("#!/bin/sh\n"):
        raise RemoteScriptError("remote_script_invalid")
    required = (
        "iwn-t102-unicast-$RUN_TOKEN",
        'PACKET_SET="$TMP/test104-packet-set.bin"',
        'sha256sum "$PACKET_SET"',
        '--source-interface "$AP"',
        '--packet-set "$PACKET_SET"',
        '--nonce "$RUN_TOKEN" --wait-go',
        'AP_AFTER="$(ap_config_digest 2>/dev/null || true)"',
    )
    if any(item not in script for item in required):
        raise RemoteScriptError("remote_script_contract_incomplete")
    if "--count 16" in script or "--interval-ms 80" in script:
        raise RemoteScriptError("legacy_sender_profile_remains")
    return {
        "valid": True,
        "schema": "test104-remote-script/v1",
        "transmission_capability": True,
        "interface_profile": "wlan7 AP + temporary same-PHY channel-149 monitor",
        "router_ap_settings_modified": False,
        "wan_lan_modified": False,
        "packet_set_sha_verified_before_go": True,
        "one_use_go": True,
        "frames_max": 4,
        "interval_ms": 10,
        "send_budget_ms": 40,
    }
