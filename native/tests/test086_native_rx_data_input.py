#!/usr/bin/env python3
"""Test086 production BSD RX permit, ticket, ownership, and TX-deny gates."""

from __future__ import annotations

from pathlib import Path
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[2]
FUNCTIONAL = Path(__file__).with_name(
    "awdl_native_rx149_data_input_test.cpp"
)
TSAN = Path(__file__).with_name(
    "awdl_native_rx149_data_input_tsan_test.cpp"
)


def run(command: list[str], cwd: Path = ROOT) -> str:
    result = subprocess.run(
        command, cwd=cwd, text=True, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, check=False
    )
    if result.returncode:
        raise RuntimeError(result.stdout)
    return result.stdout


def write_shims(temp: Path) -> None:
    headers = (
        "IOKit/IOLib.h", "IOKit/IOLocks.h", "kern/clock.h",
        "net/kpi_interfacefilter.h", "net/if.h", "sys/socket.h",
        "sys/mbuf.h", "net/kpi_interface.h", "sys/kpi_socket.h",
        "netinet/in.h", "netinet6/in6_var.h"
    )
    for header in headers:
        path = temp / header
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('#include "awdl_bsd_bridge_shim.hpp"\n')


def compile_binary(temp: Path, source: Path, suffix: str,
                   sanitizer: str) -> Path:
    output = temp / f"test086-{suffix}"
    command = [
        "xcrun", "clang++", "-std=c++14", "-O1", "-g", "-Wall",
        "-Wextra", "-Werror", "-Wno-unused-function",
        f"-fsanitize={sanitizer}", "-fno-omit-frame-pointer",
        "-DITL_NATIVE_AWDL_RESIDENT_25G332=1",
        "-DITL_NATIVE_AWDL_RX149_DATA_INPUT_25G332=1",
        f"-I{temp}", "-Inative/tests", "-Inative",
        "native/awdl_native_bsd_data_25G332.cpp",
        "native/awdl_data_frame.cpp", str(source), "-o", str(output),
    ]
    run(command)
    return output


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="test086-rx149-") as directory:
        temp = Path(directory)
        write_shims(temp)
        functional = compile_binary(temp, FUNCTIONAL, "asan-ubsan",
                                    "address,undefined")
        cases = 0
        for case in range(1, 9):
            run([str(functional), str(case)])
            cases += 1

        tsan = compile_binary(temp, TSAN, "tsan", "thread")
        run([str(tsan)])
        print(
            "Test086 production BSD RX cases passed: "
            f"{cases} ASan/UBSan cases + TSAN capture/poll/revoke/close."
        )


if __name__ == "__main__":
    main()
