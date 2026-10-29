#!/usr/bin/env python3
"""Build and run the offline Test077 current-AW fallback checks."""

import hashlib
import pathlib
import shlex
import subprocess
import sys
import tempfile


EXPECTED_TEST076_HEADER_SHA256 = (
    "f62a8bee9b70968504fd2fd2e224d5473f1ee814b4b7773e622a2cfdf4d805ce"
)
HERE = pathlib.Path(__file__).resolve().parent
NATIVE = HERE.parent
HEADER = NATIVE / "awdl_mif_current_aw_fallback.hpp"
BASE_HEADER = NATIVE / "awdl_mif_current_phase_test066.hpp"
TEST_SOURCE = HERE / "awdl_mif_current_aw_fallback_test.cpp"
RUNNER = pathlib.Path(__file__).resolve()


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def frozen_inputs():
    return {
        "Test076 base header": BASE_HEADER,
        "new fallback header": HEADER,
        "focused test": TEST_SOURCE,
        "test runner": RUNNER,
    }


def main():
    actual_base = sha256(BASE_HEADER)
    print(f"Test076 base SHA-256: {actual_base}")
    if actual_base != EXPECTED_TEST076_HEADER_SHA256:
        print("FAIL: base header does not match frozen Test076 source", file=sys.stderr)
        return 2

    before = {label: sha256(path) for label, path in frozen_inputs().items()}
    with tempfile.TemporaryDirectory(prefix="test077-current-aw-") as temporary:
        binary = pathlib.Path(temporary) / "awdl_mif_current_aw_fallback_test"
        command = [
            "clang++", "-std=c++14", "-O1", "-g", "-Wall", "-Wextra",
            "-Werror", "-fsanitize=address,undefined",
            "-fno-omit-frame-pointer", str(TEST_SOURCE), "-o", str(binary),
        ]
        print("Build command: " + " ".join(shlex.quote(part) for part in command))
        build = subprocess.run(command, text=True, capture_output=True)
        print(f"Compiler exit: {build.returncode}")
        if build.stdout:
            print(build.stdout, end="")
        if build.stderr:
            print(build.stderr, end="", file=sys.stderr)
        if build.returncode:
            return build.returncode

        run = subprocess.run([str(binary)], text=True, capture_output=True)
        print(f"Test exit: {run.returncode}")
        if run.stdout:
            print(run.stdout, end="")
        if run.stderr:
            print(run.stderr, end="", file=sys.stderr)

    after = {label: sha256(path) for label, path in frozen_inputs().items()}
    for label in before:
        print(f"{label} SHA-256 before: {before[label]}")
        print(f"{label} SHA-256 after:  {after[label]}")
        if before[label] != after[label]:
            print(f"FAIL: {label} changed during test", file=sys.stderr)
            return 3
    return run.returncode


if __name__ == "__main__":
    raise SystemExit(main())
