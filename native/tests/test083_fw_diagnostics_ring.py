#!/usr/bin/env python3
import os
from pathlib import Path
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[2]
SOURCE = Path(__file__).with_name("test083_fw_diagnostics_ring.cpp")


def compiler_command():
    compiler = os.environ.get("CXX", "clang++")
    return [compiler, "-std=c++14", "-Wall", "-Wextra", "-Werror"]


def main():
    with tempfile.TemporaryDirectory(prefix="test083-fw-ring-") as tmp:
        output = Path(tmp) / "test083-fw-diagnostics-ring"
        command = compiler_command() + [str(SOURCE), "-o", str(output)]
        subprocess.run(command, cwd=ROOT, check=True)
        subprocess.run([str(output)], cwd=ROOT, check=True)
    print("Test083 firmware diagnostic ring/wire checks passed")


if __name__ == "__main__":
    main()
