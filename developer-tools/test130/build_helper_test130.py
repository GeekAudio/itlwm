#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Build the Test130 helper offline and record its exact local inputs."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess

REPO_ROOT = Path(__file__).resolve().parents[2]
PRIVATE_DIR = REPO_ROOT.parent.parent / "RuntimeTest130" / "research" / "preparation-private"
BUILD_ID = "25G416-Test130"
HELPER_SOURCES = (
    "developer-tools/test130/arm_directed_data130.swift",
    "developer-tools/test107/IORegistryBooleanFlag107.swift",
    "developer-tools/test114/Test114RxLease.swift",
    "developer-tools/test130/Test130TwoPacketGate.swift",
    "developer-tools/test110/matched_return_test110.c",
    "developer-tools/test110/matched_return_test110.h",
)


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main(*, build_id: str = BUILD_ID, private_dir: Path = PRIVATE_DIR) -> None:
    if build_id != BUILD_ID:
        raise ValueError("unsupported helper profile")
    os.umask(0o077)
    output_dir = private_dir / "tools"
    output_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    if output_dir.is_symlink():
        raise ValueError("helper output directory may not be a symlink")
    output_dir.chmod(0o700)
    build_dir = output_dir / "objects"
    build_dir.mkdir(exist_ok=True, mode=0o700)
    if build_dir.is_symlink():
        raise ValueError("helper object directory may not be a symlink")
    build_dir.chmod(0o700)

    sources = {name: sha(REPO_ROOT / name) for name in HELPER_SOURCES}
    binary = output_dir / "arm_directed_data130"
    staged = output_dir / "arm_directed_data130.building"
    commands = [
        ["xcrun", "swiftc", "-parse-as-library", "-emit-module", "-emit-object",
         "-module-name", "IORegistryBooleanFlag107",
         str(REPO_ROOT / HELPER_SOURCES[1]), "-o", str(build_dir / "IORegistryBooleanFlag107.o"),
         "-emit-module-path", str(build_dir / "IORegistryBooleanFlag107.swiftmodule")],
        ["xcrun", "swiftc", "-parse-as-library", "-emit-module", "-emit-object",
         "-module-name", "Test114RxLease", str(REPO_ROOT / HELPER_SOURCES[2]),
         "-o", str(build_dir / "Test114RxLease.o"),
         "-emit-module-path", str(build_dir / "Test114RxLease.swiftmodule")],
        ["xcrun", "swiftc", "-parse-as-library", "-emit-module", "-emit-object",
         "-module-name", "Test130TwoPacketGate", str(REPO_ROOT / HELPER_SOURCES[3]),
         "-o", str(build_dir / "Test130TwoPacketGate.o"),
         "-emit-module-path", str(build_dir / "Test130TwoPacketGate.swiftmodule")],
        ["xcrun", "clang", "-std=c11", "-Wall", "-Wextra", "-Werror", "-c",
         str(REPO_ROOT / HELPER_SOURCES[4]), "-o", str(build_dir / "matched_return_test110.o")],
        ["xcrun", "swiftc", "-I", str(build_dir),
         str(build_dir / "IORegistryBooleanFlag107.o"),
         str(build_dir / "Test114RxLease.o"),
         str(build_dir / "Test130TwoPacketGate.o"),
         str(REPO_ROOT / HELPER_SOURCES[0]),
         str(build_dir / "matched_return_test110.o"), "-o", str(staged)],
    ]
    log_path = output_dir / "helper-build.log"
    with log_path.open("w") as log:
        for command in commands:
            log.write(json.dumps(command) + "\n")
            log.flush()
            subprocess.run(command, cwd=REPO_ROOT, stdout=log,
                           stderr=subprocess.STDOUT, check=True)
    if sources != {name: sha(REPO_ROOT / name) for name in HELPER_SOURCES}:
        raise RuntimeError("helper inputs changed during build")
    staged.replace(binary)
    binary.chmod(0o700)
    compiler = subprocess.run(["xcrun", "swiftc", "--version"],
                              capture_output=True, text=True, check=True).stdout.strip()
    receipt = {
        "schema": "test130-two-packet-helper-build/v1",
        "candidate": build_id,
        "status": "built_offline",
        "installed": False,
        "rf_tested": False,
        "binary_path": str(binary),
        "binary_sha256": sha(binary),
        "source_path": HELPER_SOURCES[0],
        "source_sha256": sources[HELPER_SOURCES[0]],
        "source_hashes": sources,
        "commands": commands,
        "compiler": compiler,
        "builder_sha256": sha(Path(__file__)),
        "build_log_sha256": sha(log_path),
    }
    receipt_path = output_dir / "test130-helper-build-private.json"
    receipt_path.write_text(json.dumps(receipt, ensure_ascii=False, indent=2) + "\n")
    receipt_path.chmod(0o600)
    print(json.dumps({"status": "built_offline", "receipt": str(receipt_path),
                      "binary_sha256": receipt["binary_sha256"], "rf_tested": False}))


if __name__ == "__main__":
    main()
