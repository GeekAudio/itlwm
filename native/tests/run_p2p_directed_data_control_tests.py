#!/usr/bin/env python3
"""Run directed-data control, recovery, and two-packet cleanup tests."""
from pathlib import Path
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[2]


def run(args):
    result = subprocess.run(args, cwd=ROOT, text=True, capture_output=True)
    if result.returncode:
        raise RuntimeError(
            f"command failed ({result.returncode}): {' '.join(map(str, args))}\n"
            f"{result.stdout}{result.stderr}"
        )
    return result.stdout


def main():
    with tempfile.TemporaryDirectory(prefix="p2p-directed-control-") as temp:
        temp_path = Path(temp)
        cases = (
            ("control", ["native/tests/p2p_directed_data_control_test.cpp"]),
            ("recovery", ["native/tests/p2p_hal_probe_test.cpp",
                          "native/p2p_hal_probe.cpp"]),
            ("cleanup-two-packet", ["native/tests/test130_directed_cleanup.cpp"]),
        )
        for name, sources in cases:
            binary = temp_path / f"p2p-directed-{name}"
            run([
                "xcrun", "clang++", "-std=c++14", "-O1", "-g", "-Wall",
                "-Wextra", "-Werror", "-fsanitize=address,undefined",
                "-fno-sanitize-recover=all", "-fno-omit-frame-pointer",
                "-Inative", *sources, "-o", str(binary),
            ])
            run([str(binary)])
        print("Directed-data control/recovery/two-packet cleanup tests passed")


if __name__ == "__main__":
    main()
