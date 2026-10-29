#!/usr/bin/env python3
"""Run the production BSD bridge generation-race test with ThreadSanitizer."""
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


def run(arguments, cwd=ROOT):
    result = subprocess.run(
        arguments, cwd=cwd, text=True, capture_output=True, check=False
    )
    if result.returncode:
        raise RuntimeError(result.stdout + result.stderr)
    return result.stdout


def main():
    with tempfile.TemporaryDirectory(prefix="native-awdl060-tsan-") as temp:
        directory = Path(temp)
        for header in HEADERS:
            path = directory / header
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('#include "awdl_bsd_bridge_shim.hpp"\n')

        binary = directory / "bridge-tsan"
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
                "-fsanitize=thread",
                "-fno-omit-frame-pointer",
                "-DITL_NATIVE_AWDL_RESIDENT_25G332=1",
                f"-I{directory}",
                "-Inative/tests",
                "-Inative",
                "native/awdl_native_bsd_data_25G332.cpp",
                "native/awdl_data_frame.cpp",
                "native/tests/awdl_native_bsd_data_tsan_test.cpp",
                "-o",
                str(binary),
            ]
        )
        run([str(binary)])
        print("Production AWDL bridge generation-race TSan test passed")


if __name__ == "__main__":
    main()
