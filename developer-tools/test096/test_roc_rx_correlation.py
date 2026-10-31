#!/usr/bin/env python3
"""Compile and run the fixed-storage ROC RX correlation core offline."""

import os
from pathlib import Path
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[2]
SOURCE = Path(__file__).with_name("test_roc_rx_correlation.cpp")


def main() -> int:
    compiler = os.environ.get("CXX", "clang++")
    with tempfile.TemporaryDirectory(prefix="iwx-roc-rx-correlation-") as tmp:
        executable = Path(tmp) / "test_roc_rx_correlation"
        subprocess.run([
            compiler,
            "-std=c++14",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-pedantic",
            "-fsanitize=address,undefined",
            "-fno-sanitize-recover=all",
            "-fno-omit-frame-pointer",
            "-I",
            str(ROOT),
            str(SOURCE),
            "-o",
            str(executable),
        ], check=True)
        subprocess.run([str(executable)], check=True, env={
            **os.environ,
            "ASAN_OPTIONS": "halt_on_error=1",
            "UBSAN_OPTIONS": "halt_on_error=1:print_stacktrace=1",
        })
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
