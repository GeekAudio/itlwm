#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Build the existing mode-4 helper offline and record its exact inputs."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess

from coordinate_directed_test124 import BUILD_ID, HELPER_SOURCES, PRIVATE_DIR, REPO_ROOT


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    os.umask(0o077)
    output_dir = PRIVATE_DIR / "tools"
    output_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    build_dir = output_dir / "objects"
    build_dir.mkdir(exist_ok=True, mode=0o700)
    sources = {name: sha(REPO_ROOT / name) for name in HELPER_SOURCES}
    binary = output_dir / "arm_directed_data124"
    staged = output_dir / "arm_directed_data124.building"
    commands = []
    for module, source in (
        ("IORegistryBooleanFlag107", HELPER_SOURCES[1]),
        ("Test114RxLease", HELPER_SOURCES[2]),
    ):
        commands.append([
            "xcrun", "swiftc", "-parse-as-library", "-emit-module", "-emit-object",
            "-module-name", module, str(REPO_ROOT / source),
            "-o", str(build_dir / (module + ".o")),
            "-emit-module-path", str(build_dir / (module + ".swiftmodule")),
        ])
    commands.extend([
        ["xcrun", "clang", "-std=c11", "-Wall", "-Wextra", "-Werror", "-c",
         str(REPO_ROOT / HELPER_SOURCES[3]), "-o", str(build_dir / "matched_return_test110.o")],
        ["xcrun", "swiftc", "-I", str(build_dir),
         str(build_dir / "IORegistryBooleanFlag107.o"),
         str(build_dir / "Test114RxLease.o"), str(REPO_ROOT / HELPER_SOURCES[0]),
         str(build_dir / "matched_return_test110.o"), "-o", str(staged)],
    ])
    log_path = output_dir / "helper-build.log"
    with log_path.open("w") as log:
        for command in commands:
            log.write(json.dumps(command) + "\n")
            log.flush()
            subprocess.run(command, cwd=REPO_ROOT, stdout=log, stderr=subprocess.STDOUT,
                           check=True)
    if sources != {name: sha(REPO_ROOT / name) for name in HELPER_SOURCES}:
        raise RuntimeError("helper inputs changed during build")
    staged.replace(binary)
    binary.chmod(0o700)
    compiler = subprocess.run(["xcrun", "swiftc", "--version"], capture_output=True,
                              text=True, check=True).stdout.strip()
    receipt = {
        "schema": "test124-mode4-helper-build/v1", "candidate": BUILD_ID,
        "status": "built_offline", "installed": False, "rf_tested": False,
        "binary_path": str(binary), "binary_sha256": sha(binary),
        "source_path": HELPER_SOURCES[0], "source_sha256": sources[HELPER_SOURCES[0]],
        "source_hashes": sources, "commands": commands, "compiler": compiler,
        "builder_sha256": sha(Path(__file__)), "build_log_sha256": sha(log_path),
    }
    receipt_path = output_dir / "test124-helper-build-private.json"
    receipt_path.write_text(json.dumps(receipt, ensure_ascii=False, indent=2) + "\n")
    receipt_path.chmod(0o600)
    print(json.dumps({"status": "built_offline", "receipt": str(receipt_path),
                      "binary_sha256": receipt["binary_sha256"], "rf_tested": False}))


if __name__ == "__main__":
    main()
