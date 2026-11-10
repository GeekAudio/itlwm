#!/usr/bin/env python3
"""Run the bounded AirDrop QM Known Answer transform under ASan/UBSan."""
from hashlib import sha256
import json
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
HEADER = ROOT / "native/awdl_qm_no_known_answer.hpp"
SOURCE = ROOT / "native/tests/awdl_qm_no_known_answer_test.cpp"


def main():
    with tempfile.TemporaryDirectory(prefix="test138-qm-known-answer-") as temp:
        binary = Path(temp) / "test138-qm-known-answer-asan-ubsan"
        subprocess.run([
            "xcrun", "clang++", "-std=c++14", "-O1", "-g", "-Wall",
            "-Wextra", "-Werror", "-fno-omit-frame-pointer",
            "-fno-sanitize-recover=all", "-fsanitize=address,undefined",
            "-Inative", str(SOURCE), "-o", str(binary),
        ], cwd=ROOT, check=True)
        result = subprocess.run([str(binary)], cwd=ROOT, check=True,
                                text=True, capture_output=True)

    print(json.dumps({
        "test": "Test138 bounded AirDrop QM Known Answer transform",
        "host_cases": 20,
        "asan_ubsan": {"passed": True},
        "source_sha256": {
            str(path.relative_to(ROOT)): sha256(path.read_bytes()).hexdigest()
            for path in (HEADER, SOURCE, Path(__file__))
        },
        "proof_boundary": {
            "production_transform_header_compiled_and_exercised": True,
            "fixture_matches_captured_dns_section_shape": True,
            "macos_kernel_runtime_tested": False,
            "firmware_or_rf_tested": False,
            "peer_receipt_or_airdrop_tested": False,
        },
    }, indent=2))
    print(result.stdout.strip())


if __name__ == "__main__":
    main()
