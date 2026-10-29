#!/usr/bin/env python3
"""Compile and run the fixed-size TX progress observer under host sanitizers."""

from pathlib import Path
import shutil
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "native/tests/iwx_tx_progress_observation_test.cpp"
XCRUN = shutil.which("xcrun")
if XCRUN:
    CXX = [XCRUN, "clang++"]
    CC = [XCRUN, "clang"]
else:
    CXX = [shutil.which("clang++") or "clang++"]
    CC = [shutil.which("clang") or "clang"]

with tempfile.TemporaryDirectory(prefix="iwx-tx-progress-") as temporary:
    directory = Path(temporary)
    c_probe = directory / "c-layout-probe.c"
    c_probe.write_text(
        '#include "native/iwx_tx_progress_observation.hpp"\n'
        'int main(void) { struct iwx_tx_progress_observation_state s = {0}; '
        'return sizeof(s) > 480; }\n',
        encoding="utf-8",
    )
    subprocess.run(
        CC + ["-std=c11", "-Wall", "-Wextra", "-Werror", "-I", str(ROOT),
              str(c_probe), "-o", str(directory / "c-layout-probe")],
        check=True,
    )
    subprocess.run([str(directory / "c-layout-probe")], check=True)

    asan_binary = directory / "tx-progress-asan"
    subprocess.run(
        CXX + ["-std=c++14", "-O1", "-Wall", "-Wextra", "-Werror",
               "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
               "-pthread", "-I", str(ROOT), str(SOURCE), "-o", str(asan_binary)],
        check=True,
    )
    subprocess.run([str(asan_binary)], check=True)

    tsan_binary = directory / "tx-progress-tsan"
    subprocess.run(
        CXX + ["-std=c++14", "-O1", "-Wall", "-Wextra", "-Werror",
               "-fsanitize=thread", "-fno-omit-frame-pointer", "-pthread",
               "-I", str(ROOT), str(SOURCE), "-o", str(tsan_binary)],
        check=True,
    )
    tsan = subprocess.run([str(tsan_binary)], text=True,
                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if tsan.returncode:
        known_runtime_limits = (
            "ThreadSanitizer: unsupported" in tsan.stdout or
            "FATAL: ThreadSanitizer: unexpected memory mapping" in tsan.stdout or
            "dyld: Symbol not found" in tsan.stdout
        )
        if not known_runtime_limits:
            raise subprocess.CalledProcessError(
                tsan.returncode, [str(tsan_binary)], output=tsan.stdout)
        print("SKIP: ThreadSanitizer runtime unavailable in this environment")
    else:
        print("PASS: ThreadSanitizer concurrent try-lock/drop/snapshot stress")

print("PASS: C-compatible layout, ASan/UBSan, bounded snapshot, explicit drops and full-width values")
