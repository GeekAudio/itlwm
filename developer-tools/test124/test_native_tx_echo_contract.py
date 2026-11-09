#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Compile the actual native TX producer and OpenWrt consumer together offline."""
import importlib.util
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("origin_fixture", ROOT / "native/tests/test107_directed_origin_tx.py")
origin = importlib.util.module_from_spec(spec)
spec.loader.exec_module(origin)


def main():
    with tempfile.TemporaryDirectory(prefix="test124-native-echo-") as temporary:
        directory = Path(temporary)
        origin.create_shims(directory)
        binary = directory / "native-tx-echo"
        command = ["xcrun", "clang++", "-std=c++14", "-O1", "-g", "-Wall", "-Wextra", "-Werror",
                   "-Wno-unused-function", "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
                   *origin.PROFILE, "-I" + str(directory), "-I.", "-Inative/tests", "-Inative",
                   "native/awdl_native_bsd_data_25G332.cpp", "native/awdl_data_frame.cpp",
                   "developer-tools/test124/test_native_tx_echo_contract.cpp", "-o", str(binary)]
        subprocess.run(command, cwd=ROOT, check=True)
        subprocess.run([str(binary)], cwd=ROOT, check=True)


if __name__ == "__main__":
    main()
