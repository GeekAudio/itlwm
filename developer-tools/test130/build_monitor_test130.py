#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Render a private Test130 monitor adapter from the frozen Test128 lease script.

The generated script retains Test128's prepare/restore/watchdog implementation;
only the Test130 identity, peer hash and two-nonce peer invocation are changed.
This builder is offline-only and never contacts or changes a router.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re

REPO_ROOT = Path(__file__).resolve().parents[2]
BASE = REPO_ROOT.parent.parent
PRIVATE_DIR = BASE / "RuntimeTest130/research/preparation-private"
PEER_RECEIPT = PRIVATE_DIR / "tools/test130-peer-build-private.json"
SOURCE_SCRIPT = REPO_ROOT / "developer-tools/test128/openwrt_monitor_window128.sh"
CHANNEL_SOURCE = REPO_ROOT / "developer-tools/test110/openwrt_echo_channel.hpp"
BUILD_ID = "25G416-Test130"


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _replace_once(text: str, old: str, new: str) -> str:
    if text.count(old) != 1:
        raise ValueError("expected one adapter anchor: " + old[:80])
    return text.replace(old, new, 1)


def render(source: str, peer_sha256: str) -> str:
    if re.fullmatch(r"[0-9a-f]{64}", peer_sha256) is None:
        raise ValueError("invalid Test130 peer hash")
    result = source
    result = _replace_once(result, "SCHEMA='test128-openwrt-monitor-window/v1'",
                           "SCHEMA='test130-openwrt-monitor-window/v1'")
    result = _replace_once(result, "ECHO_NAME='openwrt_echo110'",
                           "ECHO_NAME='openwrt_echo130'")
    result = _replace_once(result,
                           "ECHO_SHA256='72f50bb507b708157207f8f1520470ed2066eaf5caf6ad0752e89d60a1fec9a3'",
                           "ECHO_SHA256='" + peer_sha256 + "'")
    result = _replace_once(result,
                           'case "$SCRIPT_PATH" in "$STATE_DIR/monitor_window111.sh") ;; *) die \'script must run from its token-scoped state directory\' ;; esac',
                           'case "$SCRIPT_PATH" in "$STATE_DIR/monitor_window130.sh") ;; *) die \'script must run from its token-scoped state directory\' ;; esac')
    result = _replace_once(result, "NONCE=''", "NONCE=''\nNONCE2=''")
    result = _replace_once(result,
        '--run --state-dir /tmp/iw111echo-<32-hex-token> --run-token <token> --echo-binary <same-dir>/openwrt_echo110 --local-mac <mac> --peer-mac <mac> --local-ipv6 <ll-ipv6> --peer-ipv6 <ll-ipv6> --nonce <16-hex>',
        '--run --state-dir /tmp/iw111echo-<32-hex-token> --run-token <token> --echo-binary <same-dir>/openwrt_echo130 --local-mac <mac> --peer-mac <mac> --local-ipv6 <ll-ipv6> --peer-ipv6 <ll-ipv6> --packet-count 2 --nonce <16-hex> --nonce-2 <16-hex>')
    result = _replace_once(result,
        "            --nonce) [ \"$#\" -ge 2 ] || die '--nonce needs a value'; NONCE=$2; shift 2 ;;",
        "            --nonce) [ \"$#\" -ge 2 ] || die '--nonce needs a value'; NONCE=$2; shift 2 ;;\n            --nonce-2) [ \"$#\" -ge 2 ] || die '--nonce-2 needs a value'; NONCE2=$2; shift 2 ;;\n            --packet-count) [ \"$#\" -ge 2 ] || die '--packet-count needs a value'; [ \"$2\" = 2 ] || die 'Test130 requires packet-count 2'; shift 2 ;;")
    result = _replace_once(result,
        "    [ \"${#NONCE}\" -eq 16 ] || die 'nonce must be 16 hex characters'",
        "    [ \"${#NONCE}\" -eq 16 ] || die 'nonce must be 16 hex characters'\n    case \"$NONCE2\" in *[!0-9a-f]*|'') die 'nonce-2 must be lowercase hex' ;; esac\n    [ \"${#NONCE2}\" -eq 16 ] || die 'nonce-2 must be 16 hex characters'\n    [ \"$NONCE\" != \"$NONCE2\" ] || die 'packet nonces must be distinct'")
    result = _replace_once(result,
        '        --local-ipv6 "$LOCAL_IPV6" --peer-ipv6 "$PEER_IPV6" --nonce "$NONCE" --run-token "$RUN_TOKEN" --window-ms 16000',
        '        --local-ipv6 "$LOCAL_IPV6" --peer-ipv6 "$PEER_IPV6" --packet-count 2 --nonce "$NONCE" --nonce-2 "$NONCE2" --run-token "$RUN_TOKEN" --window-ms 16000')
    result = result.replace("echo110", "echo130")
    return result


def main() -> None:
    os.umask(0o077)
    with PEER_RECEIPT.open("r", encoding="utf-8") as stream:
        peer = json.load(stream)
    peer_path = Path(peer["binary_path"])
    peer_raw = peer_path.read_bytes()
    peer_sha = sha(peer_raw)
    if (peer.get("schema") != "test130-two-packet-peer-build/v1" or
            peer.get("candidate") != BUILD_ID or peer.get("status") != "built_offline" or
            peer.get("uploaded") is not False or peer.get("rf_tested") is not False or
            peer.get("binary_sha256") != peer_sha):
        raise ValueError("Test130 peer build receipt mismatch")
    source_raw = SOURCE_SCRIPT.read_bytes()
    channel_raw = CHANNEL_SOURCE.read_bytes()
    script_raw = render(source_raw.decode("utf-8"), peer_sha).encode("utf-8")

    output_dir = PRIVATE_DIR / "tools"
    output_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    if output_dir.is_symlink():
        raise ValueError("output directory may not be a symlink")
    output_dir.chmod(0o700)
    output = output_dir / "openwrt_monitor_window130.sh"
    staged = output_dir / "openwrt_monitor_window130.sh.building"
    staged.write_bytes(script_raw)
    staged.chmod(0o700)
    staged.replace(output)
    output.chmod(0o700)

    inputs = {
        str(SOURCE_SCRIPT.relative_to(REPO_ROOT)): sha(source_raw),
        str(CHANNEL_SOURCE.relative_to(REPO_ROOT)): sha(channel_raw),
        str(Path(__file__).resolve().relative_to(REPO_ROOT)): sha(Path(__file__).read_bytes()),
    }
    receipt = {
        "schema": "test130-openwrt-monitor-adapter-build/v1",
        "candidate": BUILD_ID,
        "status": "built_offline",
        "router_mutated": False,
        "rf_tested": False,
        "base_script_sha256": sha(source_raw),
        "channel_source_sha256": sha(channel_raw),
        "peer_binary_sha256": peer_sha,
        "source_hashes": inputs,
        "binary_path": str(output),
        "binary_sha256": sha(script_raw),
        "builder_sha256": sha(Path(__file__).read_bytes()),
    }
    receipt_path = output_dir / "test130-monitor-build-private.json"
    receipt_path.write_text(json.dumps(receipt, ensure_ascii=False, indent=2) + "\n")
    receipt_path.chmod(0o600)
    print(json.dumps({"status": "built_offline", "receipt": str(receipt_path),
                      "adapter_sha256": receipt["binary_sha256"],
                      "router_mutated": False, "rf_tested": False}))


if __name__ == "__main__":
    main()
