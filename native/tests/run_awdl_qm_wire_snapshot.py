#!/usr/bin/env python3
"""Build and run the address-free native Qm TX header-role test."""

from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "tests" / "awdl_qm_wire_snapshot_test.cpp"

with tempfile.TemporaryDirectory(prefix="awdl-qm-wire-") as temporary:
    binary = Path(temporary) / "awdl-qm-wire-snapshot-test"
    subprocess.run(
        ["c++", "-std=c++14", "-Wall", "-Wextra", "-Werror",
         str(SOURCE), "-o", str(binary)],
        check=True,
    )
    subprocess.run([str(binary)], check=True)

subprocess.run(
    [sys.executable, str(ROOT / "tests" / "test077_qm_wire_snapshot_integration.py")],
    check=True,
)

print("AWDL Qm wire snapshot tests passed")
