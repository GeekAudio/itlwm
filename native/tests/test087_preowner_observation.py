#!/usr/bin/env python3
"""Build and execute Test087's bounded pre-owner RX observation host tests."""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[2]
HEADER = ROOT / "native/rx_preowner_observation.hpp"
SOURCE = Path(__file__).with_name("rx_preowner_observation_test.cpp")


def main() -> None:
    header = HEADER.read_text()
    assert "std::atomic" not in header
    assert "std::mutex" not in header
    assert "new " not in header
    assert "void *" not in header
    assert "kWindowUs = 4000000ULL" in header
    assert "lockContentionLoss" in header

    compiler = shutil.which("clang++") or shutil.which("g++")
    if not compiler:
        raise RuntimeError("need clang++ or g++ to run the host test")

    with tempfile.TemporaryDirectory(prefix="test087-preowner-") as temp:
        binary = Path(temp) / "rx_preowner_observation_test"
        command = [
            compiler,
            "-std=c++17",
            "-O1",
            "-g",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-pedantic",
            "-pthread",
            "-fsanitize=address,undefined",
            "-fno-omit-frame-pointer",
            "-I",
            str(ROOT),
            str(SOURCE),
            "-o",
            str(binary),
        ]
        subprocess.run(command, check=True, cwd=ROOT)
        environment = os.environ.copy()
        # Apple Clang's ASan runtime does not ship LeakSanitizer on every host.
        environment["ASAN_OPTIONS"] = "detect_leaks=0:halt_on_error=1"
        environment.setdefault("UBSAN_OPTIONS", "halt_on_error=1:print_stacktrace=1")
        subprocess.run([str(binary)], check=True, cwd=ROOT, env=environment)


if __name__ == "__main__":
    main()
