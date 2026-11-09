#!/usr/bin/env python3
"""Compile the production Test134 worker and REMOVE gate against host stubs."""
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "itlwm/hal_iwx/ItlIwxP2PProbe.cpp"
FIXTURE = Path(__file__).with_suffix(".cpp")


def extract(source: str, marker: str) -> str:
    start = source.index(marker)
    while True:
        opening = source.index("{", start)
        semicolon = source.find(";", start)
        if semicolon < 0 or opening < semicolon:
            break
        start = source.index(marker, semicolon + 1)
    opening = source.index("{", start)
    depth = 1
    for index in range(opening + 1, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[start:index + 1]
    raise AssertionError(f"unterminated production function: {marker}")


def production_source() -> str:
    source = SOURCE.read_text()
    markers = (
        "static int reserveP2PStation(",
        "static int changeP2PStationReservation(",
        "static bool nextMulticastAllocationSerial(",
        "static void publishMulticastAdmissionState(",
        "static bool multicastAdmissionOwnLeasesAbsent(",
        "static bool multicastAdmissionOldLeaseAbsent(",
        "static bool multicastAdmissionNeverDoorbelled(",
        "static IOReturn captureMulticastPreparedAbortProofAction(",
        "static int exerciseMulticastAdmissionOnly(",
        "static int remove(void *opaque)",
        "static void finalizeMulticastAdmissionState(",
    )
    extracted = [extract(source, marker) for marker in markers]
    struct_marker = "struct MulticastPreparedAbortProof"
    extracted.insert(7, extract(source, struct_marker) + ";")
    return "\n\n".join(extracted)


class MulticastWorkerHostTests(unittest.TestCase):
    def test_extracted_production_worker_and_outer_remove_gate(self):
        template = FIXTURE.read_text()
        marker = "/* PRODUCTION_WORKER_AND_REMOVE */"
        self.assertEqual(template.count(marker), 1)
        source = template.replace(marker, production_source())
        with tempfile.TemporaryDirectory(prefix="test134-multicast-worker-",
                                         dir="/private/tmp") as temporary:
            cpp = Path(temporary) / "worker.cpp"
            executable = Path(temporary) / "worker"
            cpp.write_text(source)
            compile_result = subprocess.run([
                "clang++", "-std=c++14", "-Wall", "-Wextra", "-Werror",
                "-Wno-unused-function", "-fsanitize=address,undefined",
                "-fno-omit-frame-pointer", "-I", str(ROOT), str(cpp),
                str(ROOT / "native/p2p_hal_probe.cpp"),
                str(ROOT / "native/p2p_tx_resources.cpp"),
                "-o", str(executable),
            ], check=False, capture_output=True, text=True)
            self.assertEqual(compile_result.returncode, 0, compile_result.stderr)
            subprocess.run([str(executable)], check=True, timeout=10)


if __name__ == "__main__":
    unittest.main()
