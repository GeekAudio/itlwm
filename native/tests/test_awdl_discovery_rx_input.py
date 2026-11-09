#!/usr/bin/env python3
"""Run the standalone discovery RX policy under ASan and UBSan."""
from pathlib import Path
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[2]
TEST_SOURCE = ROOT / "native/tests/awdl_discovery_rx_input_test.cpp"


def run(args: list[str]) -> str:
    result = subprocess.run(
        args, cwd=ROOT, text=True, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, check=False
    )
    if result.returncode:
        raise RuntimeError(result.stdout)
    return result.stdout


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="awdl-discovery-rx-input-") as temp:
        binary = Path(temp) / "awdl-discovery-rx-input-asan-ubsan"
        run([
            "xcrun", "clang++", "-std=c++14", "-O1", "-g",
            "-Wall", "-Wextra", "-Werror",
            "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
            "-Inative", str(TEST_SOURCE), "-o", str(binary),
        ])
        run([str(binary)])
    print(
        "AWDL discovery RX input policy passed under ASan/UBSan "
        "(ownership and identity boundary matrix); offline policy only, "
        "no kernel, RF, or runtime validation."
    )


if __name__ == "__main__":
    main()
