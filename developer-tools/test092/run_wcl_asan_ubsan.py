#!/usr/bin/env python3
"""Compile and run the WCL backend host suite with ASan and UBSan."""

from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="test092-wcl-", dir="/private/tmp") as tmp:
        binary = Path(tmp) / "wcl-test-asan-ubsan"
        command = [
            "xcrun", "clang++", "-std=c++14", "-O1", "-g",
            "-Wall", "-Wextra", "-Werror",
            "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
            "native/wcl_wire.cpp", "native/wcl_backend.cpp",
            "native/tests/wcl_test.cpp", "-o", str(binary),
        ]
        subprocess.run(command, cwd=ROOT, check=True)
        subprocess.run([str(binary)], cwd=ROOT, check=True)
    print("Test092 WCL ASan/UBSan host suite passed")


if __name__ == "__main__":
    main()
