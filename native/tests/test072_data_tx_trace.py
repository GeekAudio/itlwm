#!/usr/bin/env python3
"""Build and run the fixed-capacity DATA-TX trace tests with ASan/UBSan."""

from pathlib import Path
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "native/tests/awdl_data_tx_trace_test.cpp"


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="awdl-data-tx-trace-") as temp:
        binary = Path(temp) / "awdl-data-tx-trace-test"
        subprocess.run(
            [
                "clang++",
                "-std=c++14",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-pthread",
                "-DNATIVE_AWDL_DATA_TX_TRACE_TESTING",
                "-fsanitize=address,undefined",
                "-fno-omit-frame-pointer",
                str(SOURCE),
                "-o",
                str(binary),
            ],
            cwd=ROOT,
            check=True,
        )
        subprocess.run([str(binary)], cwd=ROOT, check=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
