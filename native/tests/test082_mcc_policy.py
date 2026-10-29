#!/usr/bin/env python3
"""Compile and exercise the production MCC policy gates on the host."""

from pathlib import Path
import shutil
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "native/tests/test082_mcc_policy_test.cpp"


def main() -> None:
    compiler = shutil.which("clang++") or shutil.which("c++")
    if not compiler:
        raise SystemExit("No C++ compiler found")
    with tempfile.TemporaryDirectory(prefix="test082-mcc-policy-") as directory:
        binary = Path(directory) / "test082_mcc_policy"
        compile_result = subprocess.run(
            [compiler, "-std=c++14", "-Wall", "-Wextra", "-Werror", "-I",
             str(ROOT), str(SOURCE), "-o", str(binary)],
            capture_output=True,
            text=True,
        )
        if compile_result.returncode:
            raise RuntimeError(compile_result.stderr or compile_result.stdout)
        run_result = subprocess.run([str(binary)], capture_output=True, text=True)
        if run_result.returncode:
            raise AssertionError(run_result.stdout + run_result.stderr)
    print("PASS: production MCC request, response-generation and bounded-profile policies")


if __name__ == "__main__":
    main()
