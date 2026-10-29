#!/usr/bin/env python3
"""Run the Test079 pure bootstrap-to-paired-MIF transition policy."""
from pathlib import Path
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "native/tests/awdl_bootstrap_pair_transition_test079.cpp"


def run(arguments):
    result = subprocess.run(
        arguments, cwd=ROOT, text=True, capture_output=True, check=False
    )
    if result.returncode:
        raise RuntimeError(
            f"command failed ({result.returncode}): {' '.join(arguments)}\n"
            f"{result.stdout}{result.stderr}"
        )


def main():
    with tempfile.TemporaryDirectory(prefix="awdl-test079-pair-transition-") as temp:
        binary = Path(temp) / "pair-transition"
        run([
            "xcrun", "clang++", "-std=c++14", "-O1", "-g", "-Wall",
            "-Wextra", "-Werror", "-fsanitize=address,undefined",
            "-fno-omit-frame-pointer", "-fno-sanitize-recover=all",
            str(SOURCE), "-o", str(binary),
        ])
        run([str(binary)])
    print(
        "PASS: Test079 bootstrap completion/reclaim, fresh same-entry PSF/MIF, "
        "identity/epoch/channel/window/ring gates, and one-shot budget "
        "under ASan/UBSan"
    )


if __name__ == "__main__":
    main()
