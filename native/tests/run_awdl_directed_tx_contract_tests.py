#!/usr/bin/env python3
"""Run the isolated directed-AWDL TX contract model under ASan/UBSan."""
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "native/tests/awdl_directed_tx_contract_test.cpp"


def run(args):
    result = subprocess.run(args, cwd=ROOT, text=True, capture_output=True)
    if result.returncode:
        raise RuntimeError(
            f"command failed ({result.returncode}): {' '.join(map(str, args))}\n"
            f"{result.stdout}{result.stderr}"
        )
    return result.stdout


def main():
    with tempfile.TemporaryDirectory(prefix="awdl-directed-tx-") as temp:
        for enabled in (0, 1):
            binary = Path(temp) / f"awdl-directed-tx-{enabled}"
            run([
                "xcrun", "clang++", "-std=c++14", "-O1", "-g", "-Wall",
                "-Wextra", "-Werror", "-fsanitize=address,undefined",
                "-fno-sanitize-recover=all", "-fno-omit-frame-pointer",
                f"-DITL_NATIVE_AWDL_DIRECTED_REPLY_TX_25G332={enabled}",
                "-Inative", str(SOURCE), "-o", str(binary),
            ])
            print(run([str(binary)]), end="")


if __name__ == "__main__":
    main()
