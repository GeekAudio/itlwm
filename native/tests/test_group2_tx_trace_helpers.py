#!/usr/bin/env python3
"""Compile and execute the production Group2 numeric trace helpers."""
from __future__ import annotations

import os
from pathlib import Path
import shlex
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "native/tests/group2_tx_trace_helpers_test.cpp"


def main() -> int:
    compiler = shlex.split(os.environ.get("CXX", "c++"))
    with tempfile.TemporaryDirectory(prefix="group2-tx-trace-") as temporary:
        executable = Path(temporary) / "group2_tx_trace_helpers_test"
        subprocess.run(
            compiler + [
                "-std=c++17", "-Wall", "-Wextra", "-Werror", "-pthread",
                str(SOURCE), "-o", str(executable),
            ],
            cwd=ROOT,
            check=True,
        )
        subprocess.run([str(executable)], cwd=ROOT, check=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
