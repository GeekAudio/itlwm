#!/usr/bin/env python3
"""Run production mode-4 retry-domain cases under the native bridge shims."""
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
        binary = directory / "directed-rx-retry-asan-ubsan"
        run([
            "xcrun", "clang++", "-std=c++14", "-O1", "-g",
            "-Wall", "-Wextra", "-Werror", "-Wno-unused-function",
            "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
            *PROFILE, f"-I{directory}", "-Inative/tests", "-Inative",
            "native/awdl_native_bsd_data_25G332.cpp",
            "native/awdl_data_frame.cpp",
            "native/tests/awdl_directed_data_rx_test.cpp",
            "-o", str(binary),
        ])
        for scenario in (9, 10, 11):
            run([str(binary), str(scenario)])
    print(
        "PASS: directed RX exact Retry identity, queue-full non-commit, "
        "and owner/ifnet-incarnation isolation under ASan/UBSan; "
        "no device, firmware, RF, or EFI access"
    )


if __name__ == "__main__":
    main()
