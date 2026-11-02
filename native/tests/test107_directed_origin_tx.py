#!/usr/bin/env python3
"""Compile the production BSD origin gate under host mbuf/ifnet shims.

This is offline ownership and lifecycle coverage; it does not load a kext,
touch a Wi-Fi interface, transmit over RF, or prove peer receipt.
"""
from pathlib import Path
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[2]
HEADERS = (
    "IOKit/IOLib.h",
    "IOKit/IOLocks.h",
    "kern/clock.h",
    "net/kpi_interfacefilter.h",
    "net/if.h",
    "sys/socket.h",
    "sys/mbuf.h",
    "net/kpi_interface.h",
    "sys/kpi_socket.h",
    "netinet/in.h",
    "netinet6/in6_var.h",
)
PROFILE = (
    "-DITL_NATIVE_AWDL_RESIDENT_25G332=1",
    "-DITL_NATIVE_AWDL_RX149_DATA_INPUT_25G332=1",
    "-DITL_NATIVE_AWDL_DIRECTED_DATA_TX_25G332=1",
)


def run(arguments: list[str], cwd: Path = ROOT) -> str:
    result = subprocess.run(
        arguments,
        cwd=cwd,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    if result.returncode:
        raise RuntimeError(result.stdout)
    return result.stdout


def create_shims(directory: Path) -> None:
    for name in HEADERS:
        path = directory / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('#include "awdl_bsd_bridge_shim.hpp"\n')


def compile_binary(directory: Path, name: str, sanitizer: str) -> Path:
    output = directory / name
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
            "-Wno-unused-function",
            f"-fsanitize={sanitizer}",
            "-fno-omit-frame-pointer",
            *PROFILE,
            f"-I{directory}",
            "-Inative/tests",
            "-Inative",
            "native/awdl_native_bsd_data_25G332.cpp",
            "native/awdl_data_frame.cpp",
            "native/tests/awdl_directed_origin_tx_test.cpp",
            "-o",
            str(output),
        ]
    )
    return output


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="test107-origin-tx-") as temp:
        directory = Path(temp)
        create_shims(directory)
        functional = compile_binary(directory, "origin-asan-ubsan",
                                    "address,undefined")
        for case in range(1, 12):
            run([str(functional), str(case)])

        tsan = compile_binary(directory, "origin-tsan", "thread")
        for case in (7, 8, 9):
            run([str(tsan), str(case)])

    print(
        "Test107 production BSD host-shim coverage passed: "
        "11 ASan/UBSan ownership/address-scope cases + 3 TSAN concurrency cases. "
        "Native kernel, firmware, RF and peer delivery were not tested."
    )


if __name__ == "__main__":
    main()
