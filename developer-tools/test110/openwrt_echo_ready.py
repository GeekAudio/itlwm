"""Create a private helper receipt only from a live echo peer's stdout.

The coordinator owns process launch and capture readiness. This module never
changes interfaces, launches RF work, or accepts a pre-existing READY artifact.
"""
from __future__ import annotations
import datetime
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import select
import time

FIXED = dict(channel=6, request_source_port=49153,
             request_destination_port=49152, reply_source_port=49152,
             reply_destination_port=49153, hop_limit=1, payload_bytes=8,
             echo_mode="exact-request-payload-once")
IDENTITIES = ("run_token", "nonce", "local_mac", "peer_mac", "local_ipv6", "peer_ipv6")
TWO_PACKET_SCHEMA = "test130-openwrt-echo-peer/v1"
TWO_PACKET_IDENTITIES = ("run_token", "nonces", "local_mac", "peer_mac",
                         "local_ipv6", "peer_ipv6")
TWO_PACKET_FIXED = dict(channel=6, packet_count=2,
                        request_source_port=49153,
                        request_destination_port=49152, reply_source_port=49152,
                        reply_destination_port=49153, hop_limit=1, payload_bytes=8,
                        echo_mode="ordered-exact-payload-once-per-packet")


def normalize(value: dict) -> dict:
    result = {name: value[name] for name in IDENTITIES}
    for name, length in (("run_token", 32), ("nonce", 16)):
        if not isinstance(result[name], str) or not re.fullmatch("[0-9a-f]{%d}" % length, result[name]) or not int(result[name], 16):
            raise ValueError("invalid token/nonce")
    for name in ("local_mac", "peer_mac"):
        raw = result[name]
        if not isinstance(raw, str) or not re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}|[0-9a-f]{12}", raw):
            raise ValueError("invalid MAC")
        raw = raw.replace(":", "")
        if not int(raw, 16) or int(raw[:2], 16) & 1:
            raise ValueError("non-unicast MAC")
        result[name] = raw
    for name in ("local_ipv6", "peer_ipv6"):
        if not isinstance(result[name], str) or "%" in result[name]:
            raise ValueError("scope is supplied by the bound interface")
        ip = ipaddress.IPv6Address(result[name])
        if not ip.is_link_local:
            raise ValueError("non-link-local IPv6")
        result[name] = str(ip)
    if result["peer_mac"] == result["local_mac"] or result["peer_ipv6"] == result["local_ipv6"]:
        raise ValueError("peer must be distinct")
    return result


def contract_digest(identity: dict) -> str:
    v = normalize(identity)
    text = ("test110-echo/v1\n" + v["run_token"] + "\n" + v["nonce"] + "\n" +
            v["local_mac"] + "\n" + v["peer_mac"] + "\n" +
            ipaddress.IPv6Address(v["local_ipv6"]).packed.hex() + "\n" +
            ipaddress.IPv6Address(v["peer_ipv6"]).packed.hex() + "\n" +
            "6,49153,49152,49152,49153,1,8\n")
    return hashlib.sha256(text.encode("ascii")).hexdigest()


def validate_live_line(line: bytes, expected: dict, elapsed_ms: int) -> dict:
    """Pure validator; callers must not treat its output alone as live READY."""
    if not line.endswith(b"\n") or len(line) > 4096:
        raise ValueError("unbounded/incomplete READY")
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("duplicate JSON key")
            value[key] = item
        return value
    event = json.loads(line, object_pairs_hook=unique)
    keys = {"schema", "event", "window_ms", "ifindex", "monotonic_start_ns",
            "monotonic_deadline_ns", "token_bytes_hex", *IDENTITIES, *FIXED}
    if set(event) != keys or event["schema"] != "test110-openwrt-echo-peer/v1" or event["event"] != "READY":
        raise ValueError("wrong peer contract")
    for key, value in FIXED.items():
        if type(event[key]) is not type(value) or event[key] != value:
            raise ValueError("wrong fixed contract")
    for key in ("window_ms", "ifindex", "monotonic_start_ns", "monotonic_deadline_ns"):
        if type(event[key]) is not int or not 0 < event[key] < 2**64:
            raise ValueError("invalid clock/interface field")
    if event["window_ms"] != 16000 or event["monotonic_deadline_ns"] - event["monotonic_start_ns"] != 16_000_000_000:
        raise ValueError("unbounded peer window")
    if event["token_bytes_hex"] != event["run_token"] or normalize(event) != normalize(expected):
        raise ValueError("peer identity mismatch")
    if type(elapsed_ms) is not int or elapsed_ms < 0 or elapsed_ms >= 10000:
        raise ValueError("insufficient remaining peer window")
    # Conservatively deduct launch-to-read latency, including remote startup.
    # This makes the local deadline earlier than the remote monotonic deadline.
    return {"schema": "test110-openwrt-echo-coordinator-ready/v1", "event": "READY",
            **normalize(event), **FIXED, "window_ms": 16000 - elapsed_ms,
            "contract_identity_digest": contract_digest(event),
            "router_ready_sha256": hashlib.sha256(line).hexdigest()}


def capture_ready(process, launched_monotonic: float, expected: dict, path: Path) -> dict:
    """Read a READY from this running child and atomically write mode-0600 JSON.

    Call immediately after Popen; stdin/stdout must belong to the actual peer
    process (or its SSH session). Never reconstruct readiness from saved logs.
    The caller remains responsible for terminating/collecting this bounded peer.
    """
    if process.stdout is None or process.poll() is not None:
        raise RuntimeError("peer is not running")
    if not path.is_absolute() or path.exists() or path.is_symlink():
        raise ValueError("new absolute private receipt required")
    parent = path.parent.stat()
    if parent.st_mode & 0o077:
        raise ValueError("receipt parent must be private")
    fd = process.stdout.fileno()
    data = bytearray()
    while True:
        elapsed = time.monotonic() - launched_monotonic
        if elapsed < 0 or elapsed >= 10 or process.poll() is not None:
            raise RuntimeError("live peer READY expired")
        if not select.select([fd], [], [], min(.1, 10-elapsed))[0]:
            continue
        byte = os.read(fd, 1)
        if not byte:
            raise RuntimeError("peer ended before READY")
        data.extend(byte)
        if len(data) > 4096:
            raise RuntimeError("oversized peer READY")
        if byte == b"\n":
            break
    # Ceiling elapsed time so fractional milliseconds cannot extend readiness.
    elapsed_ms = int((time.monotonic() - launched_monotonic) * 1000) + 1
    receipt = validate_live_line(bytes(data), expected, elapsed_ms)
    receipt["created_utc"] = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    if process.poll() is not None:
        raise RuntimeError("peer exited while validating READY")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    with os.fdopen(descriptor, "w") as output:
        json.dump(receipt, output, sort_keys=True, indent=2)
        output.write("\n")
    return receipt


def normalize_two_packet(value: dict) -> dict:
    """Validate the ordered two-nonce Test130 peer identity."""
    result = {name: value[name] for name in TWO_PACKET_IDENTITIES}
    if (not isinstance(result["run_token"], str) or
            not re.fullmatch("[0-9a-f]{32}", result["run_token"]) or
            not int(result["run_token"], 16)):
        raise ValueError("invalid run token")
    nonces = result["nonces"]
    if (not isinstance(nonces, list) or len(nonces) != 2 or
            any(not isinstance(nonce, str) or
                not re.fullmatch("[0-9a-f]{16}", nonce) or not int(nonce, 16)
                for nonce in nonces) or nonces[0] == nonces[1]):
        raise ValueError("invalid or repeated packet nonce")
    # Reuse v1's strict address canonicalization without changing its contract.
    common = normalize({"run_token": result["run_token"], "nonce": nonces[0],
                        "local_mac": result["local_mac"],
                        "peer_mac": result["peer_mac"],
                        "local_ipv6": result["local_ipv6"],
                        "peer_ipv6": result["peer_ipv6"]})
    result.update({key: common[key] for key in
                   ("local_mac", "peer_mac", "local_ipv6", "peer_ipv6")})
    return result


def two_packet_contract_digest(identity: dict) -> str:
    value = normalize_two_packet(identity)
    text = ("test130-echo/v1\n" + value["run_token"] + "\n" +
            value["nonces"][0] + "\n" + value["nonces"][1] + "\n" +
            value["local_mac"] + "\n" + value["peer_mac"] + "\n" +
            ipaddress.IPv6Address(value["local_ipv6"]).packed.hex() + "\n" +
            ipaddress.IPv6Address(value["peer_ipv6"]).packed.hex() + "\n" +
            "6,49153,49152,49152,49153,1,8,272,273\n")
    return hashlib.sha256(text.encode("ascii")).hexdigest()


def _unique_json_line(line: bytes) -> dict:
    if not line.endswith(b"\n") or len(line) > 8192:
        raise ValueError("unbounded/incomplete READY")
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("duplicate JSON key")
            value[key] = item
        return value
    event = json.loads(line, object_pairs_hook=unique)
    if not isinstance(event, dict):
        raise ValueError("READY is not an object")
    return event


def validate_live_line_two_packet(line: bytes, expected: dict,
                                  elapsed_ms: int) -> dict:
    """Accept only a live Test130 READY bound to both ordered packet identities."""
    event = _unique_json_line(line)
    keys = {"schema", "event", "run_token", "packet_count", "local_mac",
            "peer_mac", "local_ipv6", "peer_ipv6", "window_ms", "ifindex",
            "monotonic_start_ns", "monotonic_deadline_ns", "token_bytes_hex",
            "packets", *TWO_PACKET_FIXED}
    if (set(event) != keys or event["schema"] != TWO_PACKET_SCHEMA or
            event["event"] != "READY"):
        raise ValueError("wrong two-packet peer contract")
    for key, value in TWO_PACKET_FIXED.items():
        if type(event[key]) is not type(value) or event[key] != value:
            raise ValueError("wrong fixed two-packet contract")
    for key in ("window_ms", "ifindex", "monotonic_start_ns",
                "monotonic_deadline_ns"):
        if type(event[key]) is not int or not 0 < event[key] < 2**64:
            raise ValueError("invalid clock/interface field")
    if (event["window_ms"] != 16000 or
            event["monotonic_deadline_ns"] - event["monotonic_start_ns"] !=
            16_000_000_000 or event["token_bytes_hex"] != event["run_token"]):
        raise ValueError("invalid bounded window or token binding")
    if not isinstance(event["packets"], list) or len(event["packets"]) != 2:
        raise ValueError("two ordered packet identities required")
    normalized = normalize_two_packet({
        "run_token": event["run_token"],
        "nonces": [packet.get("nonce") if isinstance(packet, dict) else None
                   for packet in event["packets"]],
        "local_mac": event["local_mac"], "peer_mac": event["peer_mac"],
        "local_ipv6": event["local_ipv6"], "peer_ipv6": event["peer_ipv6"],
    })
    if normalized != normalize_two_packet(expected):
        raise ValueError("peer identity mismatch")
    packets = event["packets"]
    packet_keys = {"slot", "nonce", "run_token", "local_mac", "peer_mac",
                   "local_ipv6", "peer_ipv6", "reply_wifi_sequence",
                   "reply_awdl_sequence"}
    normalized_packets = []
    for slot, packet in enumerate(packets):
        if not isinstance(packet, dict) or set(packet) != packet_keys:
            raise ValueError("packet identity or sequence mismatch")
        packet_identity = normalize({
            "run_token": packet["run_token"], "nonce": packet["nonce"],
            "local_mac": packet["local_mac"], "peer_mac": packet["peer_mac"],
            "local_ipv6": packet["local_ipv6"], "peer_ipv6": packet["peer_ipv6"],
        })
        if (type(packet["slot"]) is not int or packet["slot"] != slot or
                packet_identity["nonce"] != normalized["nonces"][slot] or
                packet_identity["run_token"] != normalized["run_token"] or
                any(packet_identity[key] != normalized[key] for key in
                    ("local_mac", "peer_mac", "local_ipv6", "peer_ipv6")) or
                type(packet["reply_wifi_sequence"]) is not int or
                packet["reply_wifi_sequence"] != 0x110 + slot or
                type(packet["reply_awdl_sequence"]) is not int or
                packet["reply_awdl_sequence"] != 0x110 + slot):
            raise ValueError("packet identity or sequence mismatch")
        normalized_packets.append({
            "slot": slot, **packet_identity,
            "reply_wifi_sequence": packet["reply_wifi_sequence"],
            "reply_awdl_sequence": packet["reply_awdl_sequence"],
        })
    if type(elapsed_ms) is not int or elapsed_ms < 0 or elapsed_ms >= 10000:
        raise ValueError("insufficient remaining peer window")
    return {"schema": "test130-openwrt-echo-coordinator-ready/v1",
            "event": "READY", **normalized, **TWO_PACKET_FIXED,
            "packets": normalized_packets, "window_ms": 16000 - elapsed_ms,
            "contract_identity_digest": two_packet_contract_digest(normalized),
            "router_ready_sha256": hashlib.sha256(line).hexdigest()}


def capture_ready_two_packet(process, launched_monotonic: float,
                             expected: dict, path: Path) -> dict:
    """Write a private receipt from the live v2 peer, never a saved READY."""
    if process.stdout is None or process.poll() is not None:
        raise RuntimeError("peer is not running")
    if not path.is_absolute() or path.exists() or path.is_symlink():
        raise ValueError("new absolute private receipt required")
    if path.parent.stat().st_mode & 0o077:
        raise ValueError("receipt parent must be private")
    fd = process.stdout.fileno()
    data = bytearray()
    while True:
        elapsed = time.monotonic() - launched_monotonic
        if elapsed < 0 or elapsed >= 10 or process.poll() is not None:
            raise RuntimeError("live peer READY expired")
        if not select.select([fd], [], [], min(.1, 10-elapsed))[0]:
            continue
        byte = os.read(fd, 1)
        if not byte:
            raise RuntimeError("peer ended before READY")
        data.extend(byte)
        if len(data) > 8192:
            raise RuntimeError("oversized peer READY")
        if byte == b"\n":
            break
    elapsed_ms = int((time.monotonic() - launched_monotonic) * 1000) + 1
    receipt = validate_live_line_two_packet(bytes(data), expected, elapsed_ms)
    receipt["created_utc"] = datetime.datetime.now(
        datetime.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    if process.poll() is not None:
        raise RuntimeError("peer exited while validating READY")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    with os.fdopen(descriptor, "w") as output:
        json.dump(receipt, output, sort_keys=True, indent=2)
        output.write("\n")
    return receipt
