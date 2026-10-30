"""Test088-only parser and bounded retry for macOS netstat interface rows."""
from __future__ import annotations

import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import time
from typing import Any, Callable, Dict, List, Optional


COMMAND = ["/usr/sbin/netstat", "-bI", "en1"]
MAX_ATTEMPTS = 2
RETRY_DELAY_SECONDS = 0.2
HEADER_FIELDS = ("Name", "Network", "Ipkts", "Ierrs", "Ibytes", "Opkts",
                 "Oerrs", "Obytes", "Coll")
COUNTER_FIELDS = {
    "input_packets": "Ipkts",
    "input_errors": "Ierrs",
    "input_bytes": "Ibytes",
    "output_packets": "Opkts",
    "output_errors": "Oerrs",
    "output_bytes": "Obytes",
    "collisions": "Coll",
}


class NetstatReadError(RuntimeError):
    pass


def parse_netstat_output(output: str, interface: str = "en1") -> Dict[str, int]:
    """Find one en1 link row by column names, independent of header position."""
    lines = output.splitlines()
    header_index: Optional[int] = None
    header: Optional[List[str]] = None
    required = set(HEADER_FIELDS)
    for index, line in enumerate(lines):
        fields = line.split()
        if required.issubset(fields):
            header_index, header = index, fields
            break
    if header_index is None or header is None:
        raise ValueError("netstat header missing required link-counter columns")

    indexes = {name: header.index(name) for name in HEADER_FIELDS}
    if any(header.count(name) != 1 for name in HEADER_FIELDS):
        raise ValueError("netstat header has duplicate required columns")
    needed_index = max(indexes.values())
    link_rows: List[List[str]] = []
    en_rows = 0
    for line in lines[header_index + 1:]:
        fields = line.split()
        if len(fields) <= needed_index or fields[indexes["Name"]] != interface:
            continue
        en_rows += 1
        network = fields[indexes["Network"]]
        if re.fullmatch(r"<Link#[0-9]+>", network):
            link_rows.append(fields)
    if len(link_rows) != 1:
        raise ValueError("netstat en1 link row count=" + str(len(link_rows)) +
                         " en1 rows=" + str(en_rows))

    row = link_rows[0]
    counters: Dict[str, int] = {}
    for output_name, column in COUNTER_FIELDS.items():
        value = row[indexes[column]]
        if not value.isascii() or not value.isdigit():
            raise ValueError("netstat link counter is non-numeric: " + column)
        counters[output_name] = int(value)
    return counters


def _as_bytes(value: Any) -> bytes:
    if value is None:
        return b""
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return value.encode("utf-8", "replace")
    return bytes(value)


def _timestamp() -> str:
    return datetime.datetime.now().astimezone().isoformat(timespec="microseconds")


def _write_private(path: Path, contents: bytes) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        os.chmod(path.parent, 0o700)
    except OSError:
        pass
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(str(path), flags, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(contents)
        stream.flush()
        os.fsync(stream.fileno())


def _save_failed_attempt(raw_dir: Path, attempt: int, *, observed_at: str,
                         return_code: Optional[int], stdout: bytes,
                         stderr: bytes, reason: str) -> Dict[str, Any]:
    stamp = datetime.datetime.now().astimezone().strftime("%Y%m%d-%H%M%S-%f")
    stem = "netstat-en1-attempt" + str(attempt) + "-" + stamp
    stdout_path = raw_dir / (stem + ".stdout.bin")
    stderr_path = raw_dir / (stem + ".stderr.bin")
    _write_private(stdout_path, stdout)
    _write_private(stderr_path, stderr)
    return {
        "attempt": attempt,
        "observed_at": observed_at,
        "return_code": return_code,
        "reason": reason,
        "stdout_file": str(stdout_path),
        "stdout_bytes": len(stdout),
        "stdout_sha256": hashlib.sha256(stdout).hexdigest(),
        "stderr_file": str(stderr_path),
        "stderr_bytes": len(stderr),
        "stderr_sha256": hashlib.sha256(stderr).hexdigest(),
    }


def make_counter_reader(
    raw_dir: Path,
    *,
    command_runner: Callable[..., Any] = subprocess.run,
    sleep: Callable[[float], None] = time.sleep,
) -> Callable[[], Dict[str, Any]]:
    """Create an en1 counter reader that retries one failed text read only."""
    raw_dir = Path(raw_dir)

    def read() -> Dict[str, Any]:
        read_started_at = _timestamp()
        failures: List[Dict[str, Any]] = []
        for attempt in range(1, MAX_ATTEMPTS + 1):
            attempt_at = _timestamp()
            return_code: Optional[int] = None
            stdout = b""
            stderr = b""
            reason = ""
            try:
                result = command_runner(COMMAND, capture_output=True,
                                       text=False, timeout=10)
                return_code = result.returncode
                stdout = _as_bytes(result.stdout)
                stderr = _as_bytes(result.stderr)
                if return_code != 0:
                    reason = "netstat_exit_nonzero"
                else:
                    try:
                        parsed = parse_netstat_output(stdout.decode("utf-8", "replace"))
                    except (ValueError, UnicodeError) as error:
                        reason = "netstat_output_unparsed: " + str(error)
                    else:
                        return {
                            "source": "netstat -bI en1 header-matched link row",
                            **parsed,
                            "counter_read_attempts": attempt,
                            "counter_read_retry_count": attempt - 1,
                            "counter_read_failures": failures,
                            "counter_read_started_at": read_started_at,
                            "counter_read_completed_at": _timestamp(),
                        }
            except subprocess.TimeoutExpired as error:
                stdout = _as_bytes(error.stdout)
                stderr = _as_bytes(error.stderr)
                reason = "netstat_timeout"
            except OSError as error:
                stderr = (type(error).__name__ + ": " + str(error)).encode(
                    "utf-8", "replace")
                reason = "netstat_exec_error"

            failures.append(_save_failed_attempt(
                raw_dir, attempt, observed_at=attempt_at,
                return_code=return_code, stdout=stdout, stderr=stderr,
                reason=reason or "netstat_read_error"))
            if attempt < MAX_ATTEMPTS:
                sleep(RETRY_DELAY_SECONDS)

        detail = {
            "status": "unknown_counter_read_failed_after_bounded_retry",
            "command": COMMAND,
            "attempts": failures,
        }
        raise NetstatReadError(json.dumps(detail, ensure_ascii=False,
                                          sort_keys=True))

    return read
