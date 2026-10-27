#!/usr/bin/env python3
"""Run the allocation-free reset trace helper with concurrent host readers."""

from pathlib import Path
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "native/tests/iwx_reset_trace_test.cpp"

with tempfile.TemporaryDirectory(prefix="iwx-reset-trace-") as directory:
    binary = Path(directory) / "iwx-reset-trace-test"
    subprocess.run(
        [
            "xcrun",
            "clang++",
            "-std=c++14",
            "-O1",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-fsanitize=address,undefined",
            "-fno-omit-frame-pointer",
            "-pthread",
            "-I",
            str(ROOT),
            str(SOURCE),
            "-o",
            str(binary),
        ],
        check=True,
    )
    subprocess.run([str(binary)], check=True)

print("PASS: stable reset reasons, first/last counts, coherent bounded snapshots, concurrent trigger counters")
