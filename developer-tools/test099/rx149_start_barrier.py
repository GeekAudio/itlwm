#!/usr/bin/env python3
"""Test099 live ROC START gate for the bounded RX149 sender.

This module compiles a read-only IOKit snapshot reader before a run and can
wrap Test087's NATIVE_ARMED parser. The original event remains setter-ACK only;
the wrapper raises unless a matching, current channel-149/100 ms START snapshot is
read with enough live time remaining. The caller must abort the sender on a
barrier error. This module never arms the driver or sends packets itself.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import time
from typing import Any, Callable


TOOL_DIR = Path(__file__).resolve().parent
READER_SOURCE = TOOL_DIR / "read_rx149_start_test099.swift"
MINIMUM_REMAINING_US = 60_000
DEFAULT_WAIT_MS = 8_000

READY_KEYS = {
    "event", "schema", "build", "run_token", "snapshot_run_token",
    "snapshot_revision", "profile_mode", "channel", "duration_ms",
    "configuration", "command_result", "start_seen", "start_status",
    "end_seen", "outcome_unknown", "owner_serial", "context_generation",
    "power_generation", "station_generation", "roc_generation",
    "start_observed_us", "hard_deadline_us", "published_us",
    "observed_now_us", "remaining_us", "minimum_remaining_us",
    "peer_receipt_proven", "native_awdl_reply_proven", "airdrop_proven",
    "retry_allowed",
}


class StartBarrierError(RuntimeError):
    """Sanitized helper, snapshot, or GO-barrier rejection."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def _is_int(value: Any) -> bool:
    return type(value) is int


def validate_ready_event(value: Any, *, build: str, run_token: str,
                         minimum_remaining_us: int = MINIMUM_REMAINING_US) -> dict:
    if not isinstance(value, dict) or set(value) != READY_KEYS:
        raise StartBarrierError("NATIVE_RX_READY_FIELD_SET_INVALID")
    uint_fields = (
        "schema", "snapshot_revision", "profile_mode", "channel",
        "duration_ms", "configuration", "start_seen", "start_status",
        "end_seen", "outcome_unknown", "owner_serial", "context_generation",
        "power_generation", "station_generation", "roc_generation",
        "start_observed_us", "hard_deadline_us", "published_us",
        "observed_now_us", "remaining_us", "minimum_remaining_us",
    )
    if not _is_int(value.get("command_result")):
        raise StartBarrierError("NATIVE_RX_READY_NUMBER_INVALID")
    if any(not _is_int(value.get(field)) or value[field] < 0
           for field in uint_fields):
        raise StartBarrierError("NATIVE_RX_READY_NUMBER_INVALID")
    if (value.get("event") != "NATIVE_RX_READY" or value.get("schema") != 1 or
            value.get("build") != build or value.get("run_token") != run_token or
            value.get("snapshot_run_token") != run_token or
            not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", build) or
            not re.fullmatch(r"[0-9a-f]{32}", run_token)):
        raise StartBarrierError("NATIVE_RX_READY_BINDING_INVALID")
    if (value.get("snapshot_revision") == 0 or
            value["snapshot_revision"] & 1 or
            value.get("profile_mode") != 2 or value.get("channel") != 149 or
            value.get("duration_ms") != 100 or value.get("configuration") != 2 or
            value.get("command_result") != 0 or
            value.get("start_seen") != 1 or value.get("start_status") != 1 or
            value.get("end_seen") != 0 or value.get("outcome_unknown") != 0 or
            value.get("owner_serial") == 0 or value.get("context_generation") == 0 or
            value.get("power_generation") == 0 or value.get("station_generation") == 0 or
            value.get("roc_generation") != value.get("context_generation") or
            value.get("start_observed_us") == 0 or
            value.get("hard_deadline_us") <= value.get("start_observed_us") or
            value.get("hard_deadline_us") - value.get("start_observed_us") != 100_000 or
            value.get("published_us") < value.get("start_observed_us") or
            value.get("observed_now_us") < value.get("published_us") or
            value.get("observed_now_us") >= value.get("hard_deadline_us") or
            value.get("remaining_us") != value.get("hard_deadline_us") - value.get("observed_now_us") or
            value.get("minimum_remaining_us") != minimum_remaining_us or
            value.get("remaining_us") < minimum_remaining_us or
            minimum_remaining_us < 60_000 or minimum_remaining_us > 80_000 or
            value.get("peer_receipt_proven") is not False or
            value.get("native_awdl_reply_proven") is not False or
            value.get("airdrop_proven") is not False or
            value.get("retry_allowed") is not False):
        raise StartBarrierError("NATIVE_RX_READY_LIVE_GATE_FAILED")
    return {key: value[key] for key in sorted(READY_KEYS)}


def compile_reader(output_directory: Path | str) -> Path:
    """Compile the direct IOKit reader before any ARM or RF operation."""
    output_directory = Path(output_directory).expanduser().resolve(strict=True)
    if not output_directory.is_dir() or output_directory.is_symlink():
        raise StartBarrierError("RX149_READER_OUTPUT_DIRECTORY_INVALID")
    if READER_SOURCE.is_symlink() or not READER_SOURCE.is_file():
        raise StartBarrierError("RX149_READER_SOURCE_UNAVAILABLE")
    swiftc = shutil.which("swiftc")
    if swiftc is None:
        raise StartBarrierError("SWIFT_COMPILER_UNAVAILABLE")
    executable = output_directory / "read_rx149_start_test099"
    if executable.exists() or executable.is_symlink():
        raise StartBarrierError("RX149_READER_OUTPUT_ALREADY_EXISTS")
    result = subprocess.run(
        [swiftc, "-O", str(READER_SOURCE), "-o", str(executable)],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE, check=False, timeout=45)
    if result.returncode != 0 or not executable.is_file() or executable.is_symlink():
        try:
            executable.unlink(missing_ok=True)
        except OSError:
            pass
        raise StartBarrierError("RX149_READER_COMPILE_FAILED")
    executable.chmod(0o700)
    return executable


def read_ready(executable: Path | str, *, build: str, run_token: str,
               minimum_remaining_us: int = MINIMUM_REMAINING_US,
               wait_ms: int = DEFAULT_WAIT_MS) -> dict:
    """Wait for the already-loaded driver's matching live START snapshot."""
    executable = Path(executable)
    if (executable.is_symlink() or not executable.is_file() or
            not os.access(executable, os.X_OK)):
        raise StartBarrierError("RX149_READER_EXECUTABLE_UNAVAILABLE")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", build):
        raise StartBarrierError("RX149_BUILD_INVALID")
    if not re.fullmatch(r"[0-9a-f]{32}", run_token):
        raise StartBarrierError("RX149_RUN_TOKEN_INVALID")
    if (type(minimum_remaining_us) is not int or
            not 60_000 <= minimum_remaining_us <= 80_000 or
            type(wait_ms) is not int or not 10 <= wait_ms <= 10_000):
        raise StartBarrierError("RX149_WAIT_POLICY_INVALID")
    started_ns = time.monotonic_ns()
    try:
        result = subprocess.run(
            [str(executable), "--expect-build", build,
             "--expect-run-token", run_token,
             "--minimum-remaining-us", str(minimum_remaining_us),
             "--wait-ms", str(wait_ms)],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True, encoding="utf-8",
            errors="strict", check=False, timeout=wait_ms / 1000 + 2)
    except (OSError, subprocess.SubprocessError, UnicodeError) as error:
        raise StartBarrierError("RX149_READER_INVOCATION_FAILED") from error
    if result.returncode != 0:
        code = result.stderr.strip()
        if not re.fullmatch(r"[A-Z0-9_]{1,80}", code):
            code = "RX149_READER_REJECTED"
        raise StartBarrierError(code)
    lines = result.stdout.splitlines()
    if len(lines) != 1:
        raise StartBarrierError("NATIVE_RX_READY_OUTPUT_INVALID")
    try:
        value = json.loads(lines[0])
    except (ValueError, TypeError):
        raise StartBarrierError("NATIVE_RX_READY_JSON_INVALID")
    ready = validate_ready_event(
        value, build=build, run_token=run_token,
        minimum_remaining_us=minimum_remaining_us)
    # The helper samples at the end of its polling iteration and exits without
    # further IOKit work. Preserve a host-side elapsed receipt for the caller;
    # this is a delay bound, not a second clock-domain mapping.
    ready["helper_return_elapsed_us"] = max(
        0, (time.monotonic_ns() - started_ns) // 1000)
    return ready


def install_native_armed_go_barrier(coordinator: Any, *, reader: Path | str,
                                    build: str,
                                    minimum_remaining_us: int = MINIMUM_REMAINING_US,
                                    wait_ms: int = DEFAULT_WAIT_MS) -> Callable[[], None]:
    """Patch one imported Test087 coordinator instance with a fail-closed gate.

    The source Test087 parser first validates its unchanged NATIVE_ARMED
    setter-ACK contract. Only then does the read-only Test099 helper wait for
    live START. Raising CoordinatorError prevents the following sender GO;
    the caller's existing cleanup sends ABORT because GO was not consumed.
    """
    original = coordinator._parse_native_armed

    def parse_then_require_start(line: str, token: str) -> dict:
        ack = original(line, token)
        try:
            ready = read_ready(
                reader, build=build, run_token=token,
                minimum_remaining_us=minimum_remaining_us,
                wait_ms=wait_ms)
        except StartBarrierError as error:
            raise coordinator.CoordinatorError(
                "NATIVE_RX_READY_REQUIRED",
                {"reason": error.code, "retry_allowed": False}) from error
        ack = dict(ack)
        ack["native_rx_ready"] = ready
        return ack

    coordinator._parse_native_armed = parse_then_require_start

    def restore() -> None:
        coordinator._parse_native_armed = original

    return restore

