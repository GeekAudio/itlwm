#!/usr/bin/env python3
"""Build the small Test072 active-ROC publication gate fixture."""
from pathlib import Path
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "native/tests/awdl_data_tx_publish_gate_test.cpp"


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="awdl-data-tx-publish-gate-") as temp:
        binary = Path(temp) / "awdl-data-tx-publish-gate-test"
        subprocess.run(
            ["clang++", "-std=c++14", "-Wall", "-Wextra", "-Werror",
             str(SOURCE), "-o", str(binary)],
            cwd=ROOT,
            check=True,
        )
        subprocess.run([str(binary)], cwd=ROOT, check=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
