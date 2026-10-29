#!/usr/bin/env python3
"""Focused ASan/UBSan tests for the Test071 bounded RX event timeline helper."""
from pathlib import Path
import hashlib
import json
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[2]
HEADER = ROOT / "native/awdl_rx_event_timeline.hpp"
FIXTURE = Path(__file__).with_name("awdl_rx_event_timeline_test.cpp")
ARTIFACT = ROOT.parent / "IntelWirelessNative/research/test071-rx-event-timeline-helper-review-v3-private.json"


def run(command):
    return subprocess.run(command, check=True, capture_output=True, text=True)


def main():
    with tempfile.TemporaryDirectory(prefix="test071-rx-timeline-",
                                     dir="/private/tmp") as tmp:
        binary = Path(tmp) / "rx-event-timeline-test"
        run([
            "xcrun", "clang++", "-std=c++14", "-O1", "-g", "-Wall",
            "-Wextra", "-Werror", "-fsanitize=address,undefined",
            "-fno-omit-frame-pointer", str(FIXTURE),
            str(ROOT / "native/intel_roc_event_state.cpp"), "-o", str(binary),
        ])
        run([str(binary)])

    # Use a tiny explicit translation unit for the macro-off compile.
    with tempfile.TemporaryDirectory(prefix="test071-rx-tu-",
                                     dir="/private/tmp") as tmp:
        source = Path(tmp) / "helper.cpp"
        source.write_text(
            '#include "native/awdl_rx_event_timeline.hpp"\n'
            'int main() { NativeAwdlRxTrace::Timeline t; '
            'return (int)t.snapshot().eventCount; }\n'
        )
        run([
            "xcrun", "clang++", "-std=c++14", "-Wall", "-Wextra", "-Werror",
            "-fno-exceptions", "-fno-rtti", "-fsyntax-only", "-I", str(ROOT),
            str(source),
        ])

    sources = [HEADER, FIXTURE, ROOT / "native/intel_roc_event_state.cpp",
               Path(__file__)]
    report = {
        "schema": "test071-rx-event-timeline-helper-review-v3",
        "scope": "pure fixed-capacity helper and focused host harness only",
        "asan_ubsan_passed": True,
        "kernel_style_macro_off_tu_passed": True,
        "source_sha256": {
            str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sources
        },
        "cases": [
            "empty owner0/epoch0 preflight",
            "attempted/result-present with zero status and GP2=0-present",
            "canonical failed START status0 survives later conflict and duplicate",
            "production SessionTracker before/after snapshots derive canonical edge",
            "production SessionTracker retains END-first and rejects later START edge",
            "END-before-START retained and later START cannot repair ordering",
            "SESSION_PROTECTION16 and TIME_EVENT24 remain distinct",
            "per-ticket TX wire fields and 64-bit diagnostic generation",
            "full six-byte source equality, stable in-owner ordinal, table-full unknown",
            "event capacity overflow and untracked accepted queue drain",
            "two overflow queue identities survive duplicate completion without cross-decrement",
            "completed tracked row rejects requeue",
            "completion after producer close updates original event",
            "stale old-owner completion cannot mutate new owner row",
            "owner/epoch mismatch notification is stale and does not occupy boundary",
        ],
        "limits": [
            "fixed 16-entry pending identity table mirrors existing router queue depth",
            "driver producer/consumer wiring and IORegistry publisher are outside this helper harness",
            "no actual RX/TX, RF, AirDrop, Wi-Fi, or EFI test",
            "pre-dispatch short notification, lease-generation early return, and pre-CRC paths remain unknown",
        ],
    }
    ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
    ARTIFACT.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    print("PASS: Test071 bounded RX event timeline helper under ASan/UBSan")
    print("PASS: macro-off kernel-style helper TU syntax compile")
    print(ARTIFACT)


if __name__ == "__main__":
    main()
