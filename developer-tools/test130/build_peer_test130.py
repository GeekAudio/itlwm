#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Cross-compile the ordered Test130 echo peer offline; never run or upload it."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess

REPO_ROOT = Path(__file__).resolve().parents[2]
PRIVATE_DIR = REPO_ROOT.parent.parent / "RuntimeTest130" / "research" / "preparation-private"
SOURCES = (
    "developer-tools/test110/openwrt_echo_peer.cpp",
    "developer-tools/test110/openwrt_echo_core.hpp",
    "developer-tools/test110/openwrt_echo_channel.hpp",
    "native/awdl_data_frame.cpp",
    "native/awdl_data_frame.hpp",
)
BUILD_ID = "25G416-Test130"


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compiler", type=Path, required=True,
                        help="existing local Zig executable")
    args = parser.parse_args()
    compiler = args.compiler.resolve(strict=True)
    if not compiler.is_file() or not os.access(compiler, os.X_OK):
        raise ValueError("compiler must be an existing executable")
    os.umask(0o077)
    output_dir = PRIVATE_DIR / "tools"
    output_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    if output_dir.is_symlink():
        raise ValueError("peer output directory may not be a symlink")
    output_dir.chmod(0o700)
    sources = {name: sha(REPO_ROOT / name) for name in SOURCES}
    output = output_dir / "openwrt_echo130-aarch64-linux-musl"
    staged = output_dir / "openwrt_echo130-aarch64-linux-musl.building"
    command = [str(compiler), "c++", "-target", "aarch64-linux-musl", "-static",
               "-std=c++17", "-Os", "-Wall", "-Wextra", "-Werror",
               "-fno-exceptions", "-fno-rtti",
               str(REPO_ROOT / SOURCES[0]),
               str(REPO_ROOT / "native/awdl_data_frame.cpp"), "-o", str(staged)]
    log_path = output_dir / "peer-build.log"
    with log_path.open("w") as log:
        log.write(json.dumps(command) + "\n")
        log.flush()
        subprocess.run(command, cwd=REPO_ROOT, stdout=log,
                       stderr=subprocess.STDOUT, check=True)
    if sources != {name: sha(REPO_ROOT / name) for name in SOURCES}:
        raise RuntimeError("peer sources changed during cross-build")
    raw = staged.read_bytes()
    if raw[:6] != b"\x7fELF\x02\x01" or int.from_bytes(raw[18:20], "little") != 183:
        raise RuntimeError("cross-built peer is not little-endian ELF64 AArch64")
    staged.replace(output)
    output.chmod(0o700)
    compiler_version = subprocess.run([str(compiler), "version"], text=True,
                                      capture_output=True, check=True).stdout.strip()
    receipt = {
        "schema": "test130-two-packet-peer-build/v1",
        "candidate": BUILD_ID,
        "status": "built_offline",
        "uploaded": False,
        "rf_tested": False,
        "target": "aarch64-linux-musl",
        "wire_contract": "test130-ordered-two-nonce-echo/v1",
        "binary_path": str(output),
        "binary_sha256": sha(output),
        "source_hashes": sources,
        "command": command,
        "compiler_path": str(compiler),
        "compiler_sha256": sha(compiler),
        "compiler_version": compiler_version,
        "builder_sha256": sha(Path(__file__)),
        "build_log_sha256": sha(log_path),
    }
    receipt_path = output_dir / "test130-peer-build-private.json"
    receipt_path.write_text(json.dumps(receipt, ensure_ascii=False, indent=2) + "\n")
    receipt_path.chmod(0o600)
    print(json.dumps({"status": "built_offline", "receipt": str(receipt_path),
                      "binary_sha256": receipt["binary_sha256"],
                      "uploaded": False, "rf_tested": False}))


if __name__ == "__main__":
    main()
