#!/usr/bin/env python3
"""Run production mode-4 address/retry cases under the native bridge shims."""
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
    "-DITL_NATIVE_AWDL_RX149_TEST_HOOKS=1",
)


def run(args: list[str]) -> None:
    result = subprocess.run(
        args, cwd=ROOT, text=True, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, check=False
    )
    if result.returncode:
        raise RuntimeError(result.stdout)


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="test124-directed-retry-") as temp:
        directory = Path(temp)
        for header in HEADERS:
            path = directory / header
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('#include "awdl_bsd_bridge_shim.hpp"\n')
        compiler = [
            "xcrun", "clang++", "-std=c++14", "-O1", "-g",
            "-Wall", "-Wextra", "-Werror", "-Wno-unused-function",
            "-fno-omit-frame-pointer",
            *PROFILE, f"-I{directory}", "-Inative/tests", "-Inative",
            "native/awdl_native_bsd_data_25G332.cpp",
            "native/awdl_data_frame.cpp",
            "native/tests/awdl_directed_data_rx_test.cpp",
        ]
        binary = directory / "directed-rx-retry-asan-ubsan"
        run([*compiler, "-fsanitize=address,undefined", "-o", str(binary)])
        for scenario in range(9, 20):
            run([str(binary), str(scenario)])
        concurrent = directory / "directed-rx-retry-tsan"
        run([*compiler, "-fsanitize=thread", "-o", str(concurrent)])
        run([str(concurrent), "19"])
    print(
        "PASS: 11 directed RX address/Retry cases under ASan/UBSan and "
        "1 concurrent exact-Retry case under TSan, including valid ff02 "
        "multicast, early address rejection, queue-full non-commit, "
        "and owner/ifnet/TID isolation; "
        "no device, firmware, RF, or EFI access"
    )


if __name__ == "__main__":
    main()
