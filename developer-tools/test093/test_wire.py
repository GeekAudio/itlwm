#!/usr/bin/env python3
"""Exercise the explicit Test093 decoders against C++ target-layout fixtures."""

from __future__ import annotations

import struct
import subprocess
import tempfile
from pathlib import Path

from decode_trace import decode_power, decode_scan


ROOT = Path(__file__).resolve().parents[2]


def expect_value_error(callable_, label: str) -> None:
    try:
        callable_()
    except ValueError:
        return
    raise AssertionError(f"decoder accepted invalid {label}")


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="test093-wire-", dir="/private/tmp") as tmp:
        tmp_path = Path(tmp)
        binary = tmp_path / "trace-wire-fixture"
        scan_path = tmp_path / "scan.bin"
        power_path = tmp_path / "power.bin"
        subprocess.run([
            "xcrun", "clang++", "-std=c++14", "-O1", "-Wall", "-Wextra", "-Werror",
            "-I", str(ROOT), str(ROOT / "native/tests/test093_trace_wire_fixture.cpp"),
            "-o", str(binary),
        ], cwd=ROOT, check=True)
        subprocess.run([str(binary), str(scan_path), str(power_path)], check=True)
        scan = scan_path.read_bytes()
        power = power_path.read_bytes()

        decoded_scan = decode_scan(scan, schema=1, record_bytes=136)
        assert decoded_scan["retained_count"] == 1
        assert decoded_scan["request_count"] == 1
        assert decoded_scan["replacement_count"] == 1
        row = decoded_scan["records"][0]
        assert row["request_serial"] == 7 and row["hal_generation"] == 42
        assert row["busy_class"] == "radio_reported" and row["busy_reason_code"] == 4
        assert row["last_admission"] == "ok" and row["event201_count"] == 2
        assert row["firmware_terminal_consumed_ns"] == 150
        assert row["native237_emit_call_ns"] == 151

        expect_value_error(lambda: decode_scan(scan, schema=2, record_bytes=136), "scan schema")
        expect_value_error(lambda: decode_scan(scan, schema=1, record_bytes=128), "scan RecordBytes")
        expect_value_error(lambda: decode_scan(scan[:-1], schema=1, record_bytes=136), "scan length")
        bad_scan = bytearray(scan)
        struct.pack_into("<I", bad_scan, 40 + 116, 99)
        expect_value_error(lambda: decode_scan(bad_scan, schema=1, record_bytes=136), "scan status enum")
        bad_scan = bytearray(scan)
        bad_scan[40 + 130] = 1
        expect_value_error(lambda: decode_scan(bad_scan, schema=1, record_bytes=136), "scan padding")
        bad_scan = bytearray(scan)
        bad_scan[40 + 136] = 1
        expect_value_error(lambda: decode_scan(bad_scan, schema=1, record_bytes=136), "unused scan row")

        decoded_power = decode_power(power, schema=1, record_bytes=56)
        assert decoded_power["capacity"] == 32 and decoded_power["count"] == 2
        assert decoded_power["newest_sequence"] == 2
        assert decoded_power["entries"][0]["operation"] == "power_set"
        assert decoded_power["entries"][1]["phase"] == "call_end"
        expect_value_error(lambda: decode_power(power, schema=2, record_bytes=56), "power schema")
        expect_value_error(lambda: decode_power(power, schema=1, record_bytes=48), "power RecordBytes")
        expect_value_error(lambda: decode_power(power[:-1], schema=1, record_bytes=56), "power length")
        bad_power = bytearray(power)
        struct.pack_into("<I", bad_power, 16 + 52, 1)
        expect_value_error(lambda: decode_power(bad_power, schema=1, record_bytes=56), "power reserved")
        bad_power = bytearray(power)
        bad_power[16 + 2 * 56] = 1
        expect_value_error(lambda: decode_power(bad_power, schema=1, record_bytes=56), "unused power row")

    print("Test093 scan/power wire decoders passed against C++ x86_64 fixtures")


if __name__ == "__main__":
    main()
