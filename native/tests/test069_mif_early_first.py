#!/usr/bin/env python3
"""Run Test069 MIF pacing policy tests with ASan and UBSan."""
from pathlib import Path
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[2]
HEADER = ROOT / "native/awdl_mif_pacing.hpp"
SOURCE = ROOT / "native/tests/awdl_mif_early_first_test069.cpp"


def run(arguments):
    result = subprocess.run(
        arguments, cwd=ROOT, text=True, capture_output=True, check=False
    )
    if result.returncode:
        raise RuntimeError(
            f"command failed ({result.returncode}): {' '.join(arguments)}\n"
            f"{result.stdout}{result.stderr}"
        )
    return result.stdout


def main():
    header = HEADER.read_text(encoding="utf-8")
    assert "Test069EarlyFirstMif = 2" in header
    assert "MifPacingReason::PsfBeforePhaseOrigin" in header
    assert "MifPacingDetail::offsetForPolicy(" in header

    with tempfile.TemporaryDirectory(prefix="awdl-mif-early-first-069-") as temp:
        binary = Path(temp) / "awdl-mif-early-first-test069"
        run(
            [
                "xcrun",
                "clang++",
                "-std=c++14",
                "-O1",
                "-g",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-fsanitize=address,undefined",
                "-fno-omit-frame-pointer",
                "-fno-sanitize-recover=all",
                str(SOURCE),
                "-o",
                str(binary),
            ]
        )
        run([str(binary)])

    print(
        "PASS: Test069 policy offsets, legacy/Test066 compatibility, fresh "
        "phase-bound anchors, 16-TU lease, epochs, channel/ROC/deadline "
        "fences, overflow boundaries, and unknown-policy rejection "
        "under ASan/UBSan"
    )


if __name__ == "__main__":
    main()
