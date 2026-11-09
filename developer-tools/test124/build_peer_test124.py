#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Cross-compile the exact controlled echo peer; never upload or execute it."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess

from coordinate_directed_test124 import BUILD_ID, PEER_SOURCES, PRIVATE_DIR, REPO_ROOT


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compiler", type=Path, required=True, help="local Zig executable")
    args = parser.parse_args()
    compiler = args.compiler.resolve(strict=True)
    os.umask(0o077)
    output_dir = PRIVATE_DIR / "tools"
    output_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    sources = {name: sha(REPO_ROOT / name) for name in PEER_SOURCES}
    output = output_dir / "openwrt_echo124-aarch64-linux-musl"
    staged = output.with_suffix(".building")
    command = [str(compiler), "c++", "-target", "aarch64-linux-musl", "-static",
               "-std=c++17", "-Os", "-Wall", "-Wextra", "-Werror", "-fno-exceptions", "-fno-rtti",
               str(REPO_ROOT / PEER_SOURCES[0]), str(REPO_ROOT / "native/awdl_data_frame.cpp"),
               "-o", str(staged)]
    log_path = output_dir / "peer-build.log"
    with log_path.open("w") as log:
        log.write(json.dumps(command) + "\n"); log.flush()
        subprocess.run(command, cwd=REPO_ROOT, stdout=log, stderr=subprocess.STDOUT, check=True)
    if sources != {name: sha(REPO_ROOT / name) for name in PEER_SOURCES}:
        raise RuntimeError("peer inputs changed during cross-build")
    raw = staged.read_bytes()
    if raw[:6] != b"\x7fELF\x02\x01" or int.from_bytes(raw[18:20], "little") != 183:
        raise RuntimeError("cross-built peer is not little-endian ELF64 AArch64")
    staged.replace(output); output.chmod(0o700)
    receipt = {
        "schema": "test124-mode4-peer-build/v1", "candidate": BUILD_ID,
        "status": "built_offline", "uploaded": False, "rf_tested": False,
        "target": "aarch64-linux-musl", "wire_contract": "mode4-peer-unicast-ff02-allnodes/v1",
        "binary_path": str(output), "binary_sha256": sha(output),
        "source_hashes": sources, "command": command,
        "compiler_sha256": sha(compiler),
        "compiler_version": subprocess.run([str(compiler), "version"], text=True,
                                             capture_output=True, check=True).stdout.strip(),
        "builder_sha256": sha(Path(__file__)), "build_log_sha256": sha(log_path),
    }
    path = output_dir / "test124-peer-build-private.json"
    path.write_text(json.dumps(receipt, indent=2) + "\n"); path.chmod(0o600)
    print(json.dumps({"status": "built_offline", "receipt": str(path),
                      "binary_sha256": receipt["binary_sha256"], "uploaded": False, "rf_tested": False}))


if __name__ == "__main__":
    main()
