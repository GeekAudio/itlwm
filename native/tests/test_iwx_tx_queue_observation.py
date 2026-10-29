#!/usr/bin/env python3
"""Compile and run the bounded queue identity observer host tests."""

from pathlib import Path
import shutil
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "native/tests/iwx_tx_queue_observation_test.cpp"
XCRUN = shutil.which("xcrun")
if XCRUN:
    CXX = [XCRUN, "clang++"]
    CC = [XCRUN, "clang"]
else:
    CXX = [shutil.which("clang++") or "clang++"]
    CC = [shutil.which("clang") or "clang"]

with tempfile.TemporaryDirectory(prefix="iwx-tx-queue-observation-") as temporary:
    directory = Path(temporary)
    c_probe = directory / "c-layout-probe.c"
    c_probe.write_text(
        '#include "native/iwx_tx_queue_observation.hpp"\n'
        'int main(void) { return sizeof(struct iwx_txq_obs_snapshot) > 1024 || '
        'sizeof(struct iwx_tx_queue_observation_state) < '
        'sizeof(((struct iwx_tx_queue_observation_state *)0)->queues); }\n',
        encoding="utf-8",
    )
    subprocess.run(
        CC + ["-std=c11", "-Wall", "-Wextra", "-Werror", "-I", str(ROOT),
              str(c_probe), "-o", str(directory / "c-layout-probe")],
        check=True,
    )
    subprocess.run([str(directory / "c-layout-probe")], check=True)

    binary = directory / "queue-observation-asan-ubsan"
    subprocess.run(
        CXX + ["-std=c++14", "-O1", "-Wall", "-Wextra", "-Werror",
               "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
               "-pthread", "-I", str(ROOT), str(SOURCE), "-o", str(binary)],
        check=True,
    )
    subprocess.run([str(binary)], check=True)

    tsan_binary = directory / "queue-observation-tsan"
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
        print("PASS: ThreadSanitizer concurrent invalidation/reset/free/snapshot stress")

print("PASS: C-compatible layout, ASan/UBSan, queue incarnation/config races, "
      "exact submit-arm identity, incomplete/drop behavior, and bounded snapshot")
