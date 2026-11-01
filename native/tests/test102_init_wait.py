#!/usr/bin/env python3
"""Execute the firmware-init wait helper and verify its driver integration."""
from __future__ import annotations

import os
from pathlib import Path
import shlex
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "itlwm/hal_iwx/ItlIwx.cpp"
TEST_CPP = ROOT / "native/tests/iwx_init_wait_test.cpp"


def function_body(source: str, marker: str) -> str:
    start = source.index(marker)
    opening = source.index("{", start)
    depth = 0
    state = "code"
    escaped = False
    index = opening
    while index < len(source):
        char = source[index]
        following = source[index + 1] if index + 1 < len(source) else ""
        if state == "line_comment":
            if char == "\n":
                state = "code"
        elif state == "block_comment":
            if char == "*" and following == "/":
                state = "code"
                index += 1
        elif state in ("string", "char"):
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif (state == "string" and char == '"') or (
                state == "char" and char == "'"
            ):
                state = "code"
        else:
            if char == "/" and following == "/":
                state = "line_comment"
                index += 1
            elif char == "/" and following == "*":
                state = "block_comment"
                index += 1
            elif char == '"':
                state = "string"
            elif char == "'":
                state = "char"
            elif char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    return source[opening + 1:index]
        index += 1
    raise AssertionError(f"unclosed function: {marker}")


def main() -> None:
    compiler = shlex.split(os.environ.get("CXX", "c++"))
    with tempfile.TemporaryDirectory(prefix="test102-init-wait-") as temp:
        executable = Path(temp) / "iwx_init_wait_test"
        subprocess.run(
            compiler + [
                "-std=c++14", "-Wall", "-Wextra", "-Werror",
                "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
                str(TEST_CPP), "-o", str(executable),
            ],
            cwd=ROOT,
            check=True,
        )
        subprocess.run([str(executable)], cwd=ROOT, check=True)

    source = SOURCE.read_text()
    load_firmware = function_body(source, "iwx_load_firmware(struct iwx_softc *sc)")
    load_pnvm = function_body(source, "iwx_load_pnvm(struct iwx_softc *sc)")
    run_init = function_body(source, "iwx_run_init_mvm_ucode(struct iwx_softc *sc, int readnvm)")
    receive = function_body(
        source,
        "iwx_rx_pkt(struct iwx_softc *sc, struct iwx_rx_data *data,",
    )

    assert '#include "../../native/iwx_init_wait.hpp"' in source
    assert load_firmware.count("IwxInitWait::waitFor") == 1
    assert "__atomic_store_n(&sc->sc_uc.uc_ok, 0, __ATOMIC_RELAXED)" in load_firmware
    assert "__atomic_store_n(&sc->sc_uc.uc_intr, 0, __ATOMIC_RELEASE)" in load_firmware
    assert "__ATOMIC_ACQUIRE" in load_firmware and "iwxMonotonicNs" in load_firmware
    assert "SEC_TO_NSEC(1), kIwxFirmwareInitWaitPollNs" in load_firmware
    assert "sc->sc_generation != initGeneration" in load_firmware
    assert "firmware ALIVE wait failed outcome=%u error=%d observed=0x%x" in load_firmware
    assert load_firmware.index("ic_tahoe_init_stage = kTahoeInitStageAliveWait") < load_firmware.index("IwxInitWait::waitFor")
    assert load_firmware.index("ic_tahoe_init_stage = 3") > load_firmware.index("IwxInitWait::waitFor")

    assert load_pnvm.count("IwxInitWait::waitFor") == 1
    assert "__atomic_fetch_and(&sc->sc_init_complete" in load_pnvm
    assert load_pnvm.index("initGeneration ||") < load_pnvm.index("iwx_nic_lock(sc)")
    assert "SEC_TO_NSEC(2), kIwxFirmwareInitWaitPollNs" in load_pnvm
    assert "PNVM_INIT_COMPLETE wait failed outcome=%u error=%d flags=0x%x" in load_pnvm
    assert "iwx_pnvm_free(&sc->sc_fw)" in load_pnvm
    assert load_pnvm.index("iwx_pnvm_free(&sc->sc_fw)") > load_pnvm.index("IwxInitWait::waitFor")
    assert load_pnvm.index("ic_tahoe_init_stage = kTahoeInitStagePnvmWait") < load_pnvm.index("IwxInitWait::waitFor")
    assert load_pnvm.index("ic_tahoe_init_stage = 3") > load_pnvm.index("IwxInitWait::waitFor")

    assert run_init.count("IwxInitWait::waitFor") == 1
    assert "__atomic_store_n(&sc->sc_init_complete, 0, __ATOMIC_RELEASE)" in run_init
    assert "(observedFlags & wait_flags)" not in run_init
    assert "SEC_TO_NSEC(2), kIwxFirmwareInitWaitPollNs" in run_init
    assert "INIT_COMPLETE wait failed outcome=%u error=%d flags=0x%x" in run_init
    assert "sc->sc_generation != initGeneration" in run_init
    assert run_init.index("ic_tahoe_init_stage = kTahoeInitStageCompleteWait") < run_init.index("IwxInitWait::waitFor")
    assert run_init.index("ic_tahoe_init_stage = 3") > run_init.index("IwxInitWait::waitFor")

    # Firmware error cleanup records ic_tahoe_init_stage/error in the reset
    # trace before stop clears soft state. Substages remain on the failure path;
    # each successful wait restores the ordinary stage 3.
    assert "kTahoeInitStageAliveWait = 31" in source
    assert "kTahoeInitStagePnvmWait = 32" in source
    assert "kTahoeInitStageCompleteWait = 33" in source
    assert load_firmware.count("ic_tahoe_init_stage = 3") == 1
    assert load_pnvm.count("ic_tahoe_init_stage = 3") == 1
    assert run_init.count("ic_tahoe_init_stage = 3") == 1
    assert "ic->ic_tahoe_init_stage,\n        static_cast<uint32_t>(ic->ic_tahoe_init_error)" in source
    init_error = source.index('ic->ic_tahoe_init_error = err;')
    cleanup = source.index("iwx_stop(ifp,", init_error)
    assert init_error < cleanup

    alive_case = receive.index("case IWX_ALIVE:")
    pnvm_case = receive.index("IWX_PNVM_INIT_COMPLETE_NTFY")
    init_case = receive.index("case IWX_INIT_COMPLETE_NOTIF:")
    assert alive_case < pnvm_case < init_case
    alive_handler = receive[alive_case:pnvm_case]
    pnvm_handler = receive[pnvm_case:init_case]
    init_handler = receive[init_case:]
    assert "__atomic_store_n(&sc->sc_uc.uc_intr, 1, __ATOMIC_RELEASE)" in alive_handler
    assert "__atomic_store_n(&sc->sc_uc.uc_ok, 1, __ATOMIC_RELAXED)" in alive_handler
    assert "short PNVM_INIT_COMPLETE notification" in pnvm_handler
    assert pnvm_handler.index("__atomic_fetch_or(&sc->sc_init_complete") < pnvm_handler.index("wakeupOn(&sc->sc_init_complete)")
    assert "__atomic_fetch_or(&sc->sc_init_complete, IWX_INIT_COMPLETE" in init_handler

    print("PASS: bounded ALIVE/PNVM/INIT_COMPLETE predicate waits, lost/spurious wake, cancellation, cleanup and persistent reset-trace substages")


if __name__ == "__main__":
    main()
