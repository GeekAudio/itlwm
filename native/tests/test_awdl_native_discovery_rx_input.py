#!/usr/bin/env python3
"""Run the production Discovery RX BSD bridge under offline KPI shims."""
from pathlib import Path
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[2]
HEADERS = (
    "IOKit/IOLib.h", "IOKit/IOLocks.h", "kern/clock.h",
    "net/kpi_interfacefilter.h", "net/if.h", "sys/socket.h",
    "sys/mbuf.h", "net/kpi_interface.h", "sys/kpi_socket.h",
    "netinet/in.h", "netinet6/in6_var.h",
)


def run(command: list[str]) -> None:
    result = subprocess.run(
        command, cwd=ROOT, text=True, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, check=False,
    )
    if result.returncode:
        raise RuntimeError(result.stdout)


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="native-discovery-rx-") as temp:
        directory = Path(temp)
        for header in HEADERS:
            path = directory / header
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('#include "awdl_bsd_bridge_shim.hpp"\n')
        binary = directory / "discovery-rx-asan-ubsan"
        run([
            "xcrun", "clang++", "-std=c++14", "-O1", "-g", "-Wall",
            "-Wextra", "-Werror", "-Wno-unused-function",
            "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
            "-DITL_NATIVE_AWDL_RESIDENT_25G332=1",
            "-DITL_NATIVE_AWDL_DISCOVERY_RX_INPUT_25G332=1",
            f"-I{directory}", "-Inative/tests", "-Inative",
            "native/awdl_native_bsd_data_25G332.cpp",
            "native/awdl_data_frame.cpp",
            "native/tests/awdl_native_discovery_rx_input_test.cpp",
            "-o", str(binary),
        ])
        for scenario in range(1, 8):
            run([str(binary), str(scenario)])
    print(
        "Discovery RX production bridge passed: 7 ASan/UBSan scenarios "
        "under offline KPI shims. No kernel, RF, firmware, or EFI action ran."
    )


if __name__ == "__main__":
    main()
