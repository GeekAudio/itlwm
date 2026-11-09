#!/usr/bin/env python3
"""Exercise the production mode-4 RX bridge under offline KPI shims."""
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


def run(args: list[str]) -> None:
    result = subprocess.run(
        args, cwd=ROOT, text=True, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, check=False
    )
    if result.returncode:
        raise RuntimeError(result.stdout)


def compile_bridge(directory: Path, sanitizer: str) -> Path:
    for header in HEADERS:
        path = directory / header
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('#include "awdl_bsd_bridge_shim.hpp"\n')
    binary = directory / f"directed-rx-{sanitizer}"
    run([
        "xcrun", "clang++", "-std=c++14", "-O1", "-g",
        "-Wall", "-Wextra", "-Werror", "-Wno-unused-function",
        f"-fsanitize={sanitizer}", "-fno-omit-frame-pointer", *PROFILE,
        f"-I{directory}", "-Inative/tests", "-Inative",
        "native/awdl_native_bsd_data_25G332.cpp",
        "native/awdl_data_frame.cpp",
        "native/tests/awdl_directed_data_rx_test.cpp",
        "-o", str(binary),
    ])
    return binary


def run_receipt_publisher(directory: Path) -> None:
    binary = directory / "receipt-publisher"
    run([
        "xcrun", "clang++", "-std=c++14", "-Wall", "-Wextra", "-Werror",
        "-Inative", "native/tests/test110_directed_rx_receipt_publisher.cpp",
        "-o", str(binary),
    ])
    run([str(binary)])


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="test110-directed-rx-") as temp:
        directory = Path(temp)
        functional = compile_bridge(directory, "address,undefined")
        for scenario in range(1, 9):
            run([str(functional), str(scenario)])
        tsan = compile_bridge(directory, "thread")
        for scenario in (4, 6, 7, 8):
            run([str(tsan), str(scenario)])
        run_receipt_publisher(directory)
    print(
        "Test110 directed RX bridge passed: 8 ASan/UBSan cases and "
        "4 TSAN cases under host KPI shims plus 1 numeric receipt-publisher "
        "case. Native kernel, RF, firmware, "
        "peer reply and AirDrop were not tested."
    )


if __name__ == "__main__":
    main()
