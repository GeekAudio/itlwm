#!/usr/bin/env python3
"""Compile the atomic retry-token fixture and enforce TX/lifecycle call order."""

from pathlib import Path
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[2]
DRIVER = (ROOT / "itlwm/hal_iwx/ItlIwx.cpp").read_text()
HEADER = (ROOT / "itlwm/hal_iwx/ItlIwx.hpp").read_text()
SOFTC = (ROOT / "itlwm/hal_iwx/if_iwxvar.h").read_text()
KICK = (ROOT / "native/iwx_output_kick.hpp").read_text()
TRACE = (ROOT / "native/iwx_reset_trace.hpp").read_text()
PUBLISHER = (ROOT / "itlwm/hal_iwx/ItlIwxP2PRx.cpp").read_text()
AIRPORT = (ROOT / "AirportItlwm/AirportItlwmV2.cpp").read_text()
AIRPORT_HEADER = (ROOT / "AirportItlwm/AirportItlwmV2.hpp").read_text()


def function_body(source: str, marker: str) -> str:
    start = source.index(marker)
    opening = source.index("{", start)
    depth = 0
    for index in range(opening, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[opening + 1 : index]
    raise AssertionError(f"unterminated function: {marker}")


start_task = function_body(DRIVER, "_iwx_start_task(OSObject *target,")
drain = function_body(DRIVER, "IwxOutputKick::DrainResult ItlIwx::iwx_start_drain(")
start = function_body(DRIVER, "iwx_start(struct _ifnet *ifp)")
watchdog_action = function_body(DRIVER, "ItlIwx::_iwx_watchdog_task(")
watchdog = function_body(DRIVER, "iwx_watchdog(struct _ifnet *ifp)")
stop = function_body(DRIVER, "iwx_stop(struct _ifnet *ifp, IwxResetTrace::ResetReason reason)")
init = function_body(DRIVER, "iwx_init(struct _ifnet *ifp)")
tahoe_start_task = start_task.split("#else", 1)[0]

# The normal queue is dequeued only in the bounded routine, whose preflight
# checks gate/epoch/lifecycle state before either management or data dequeue.
assert "TahoeLifecycleGuard lifecycle(that, true, false," in tahoe_start_task
assert tahoe_start_task.index("TahoeLifecycleGuard lifecycle") < tahoe_start_task.index(
    "iwx_start_drain(ifp, epoch"
)
assert "if (!lifecycle)" in tahoe_start_task
assert "result->retryOutput = true;" in tahoe_start_task
assert "ifq_dequeue" not in tahoe_start_task
assert "mq_dequeue" not in tahoe_start_task
for condition in (
    "that->tahoeP2pOnMainGate()",
    "sc->sc_tx_output_epoch",
    "IWX_FLAG_SHUTDOWN",
    "IFF_UP | IFF_RUNNING",
):
    assert condition in drain
assert drain.index("tahoeP2pOnMainGate()") < drain.index("mq_dequeue(&ic->ic_mgtq)")
assert drain.index("IFF_UP | IFF_RUNNING") < drain.index("ifq_dequeue(&ifp->if_snd)")
assert "kTahoeOutputDrainBatch = 64" in DRIVER
assert "IwxOutputKick::classifyDrain(" in drain
assert "IwxOutputKick::DrainResult drain" in tahoe_start_task
assert "IwxOutputDrainResult" not in DRIVER
assert drain.count("++dequeued;") == 2
assert "drainResult = IwxOutputKick::DrainResult::kTemporarilyBlocked" in drain
assert "IwxOutputKick::shouldContinueImmediately(drain)" in start_task
assert drain.index("++dequeued;", drain.index("m = mq_dequeue")) < drain.index(
    "goto sendit;"
)
assert drain.index("++dequeued;", drain.index("m = ifq_dequeue")) < drain.index(
    "mbuf_len(m)"
)
assert "IwxOutputKick::classifyDrain(" in drain

# A failed nonblocking gate attempt or a bounded-batch continuation publishes
# only after attemptAction returned. Epoch-bound CAS cannot revive old work.
attempt = start.index("gate->attemptAction(_iwx_start_task")
publish = start.index("IwxOutputKick::requestAtEpoch")
assert attempt < publish
assert "dispatch.outputEpoch" in start
assert "batch < 4" in start
assert "!alreadyInMainGate" in start
assert "dispatch.flushDeferredTasks && !alreadyInMainGate" in start
assert "dispatch.flushDeferredTasks && !alreadyInMainGate" in watchdog
assert "const bool alreadyInMainGate = loop && loop->inGate();" in watchdog
assert "reentrant case the outer owner still holds the gate" in start
assert "requestAtEpoch" in KICK
assert "__atomic_load_n(currentEpoch" in KICK
assert "__atomic_compare_exchange_n(state, &published, uint64_t(0)" in KICK
assert "epoch - tagEpoch(previous)" in KICK
assert "finite" in KICK and "request serial can eventually wrap" in KICK
assert "IwxOutputKick::takeForEpoch" in watchdog_action
assert watchdog_action.index("TahoeLifecycleGuard lifecycle") < watchdog_action.index(
    "IwxOutputKick::takeForEpoch"
)
assert watchdog_action.index("outputActive") < watchdog_action.index(
    "IwxOutputKick::takeForEpoch"
)
assert watchdog_action.index("takeForEpoch") < watchdog_action.index(
    "iwx_start_drain("
)
assert "IwxOutputKick::requestAtEpoch" in watchdog
assert watchdog.index("attemptAction(_iwx_watchdog_task") < watchdog.index(
    "that->iwx_start(ifp)"
)
assert "dispatch.continueImmediately" in watchdog
assert "kWatchDogTimerPeriod 1000" in AIRPORT_HEADER

# Lifecycle generation mirror changes are published at both actual Tahoe
# generation boundaries; stop clears stale tokens before touching rings.
assert "sc->sc_generation++" in stop
assert stop.index("sc->sc_generation++") < stop.index("sc_tx_output_epoch")
assert "IwxOutputKick::clearOlderEpoch" in stop
assert "generation = ++sc->sc_generation" in init
assert "sc_tx_output_epoch" in init
assert "sc_tx_output_kick_tag" in SOFTC

# Producer timestamps are scalar-only under a try-lock; queue identity remains
# unavailable in the watchdog snapshot and publication happens from the
# existing serialized publisher.
observed_tx = drain.index(
    "that->iwx_tx(sc, m, ni, ac, &observedSubmitSerial)"
)
tx_watchdog_arm = drain.index("IwxTxWatchdog::arm(&sc->sc_tx_timer)")
tx_timer_observation = drain.index(
    "recordTxTimerArm(sc, epoch, observedSubmitSerial)"
)
assert observed_tx < tx_watchdog_arm < tx_timer_observation
assert drain.index("if (that->iwx_tx(sc, m, ni, ac, &observedSubmitSerial) != 0)") < tx_watchdog_arm
assert drain.index("continue;", observed_tx) < tx_watchdog_arm
assert "recordTxTimerClear(sc" in DRIVER
assert "kTxTimerClearFirmwareResponse = 1" in DRIVER
assert "does not\n    // prove a specific queue drained" in DRIVER
assert "sc_tx_timer_arm_output_epoch" in SOFTC
assert "sc_tx_timer_clear_output_epoch" in SOFTC
assert "sample->armOutputEpoch" in DRIVER
assert "sample->clearOutputEpoch" in DRIVER
assert "queueSnapshotAvailable = 0" in function_body(
    DRIVER, "ItlIwx::tahoeRecordTxWatchdogSnapshot(struct iwx_softc *sc,"
)
assert "txWatchdogProducerSnapshotAvailable" in TRACE
for name in (
    "NativeResetTraceResetMonotonicNs",
    "NativeResetTraceResetPublishAtMonotonicNs",
    "NativeResetTraceTxWatchdogArmMonotonicNs",
    "NativeResetTraceTxWatchdogArmOutputEpoch",
    "NativeResetTraceTxWatchdogClearOutputEpoch",
    "NativeResetTraceTxWatchdogClearMonotonicNs",
    "NativeResetTraceTxWatchdogExpiryMonotonicNs",
    "NativeResetTraceTxWatchdogExpiryPublishAtMonotonicNs",
):
    assert name in PUBLISHER
assert '"NativeResetTraceTxWatchdogArmGeneration"' not in PUBLISHER
assert '"NativeResetTraceTxWatchdogClearGeneration"' not in PUBLISHER

with tempfile.TemporaryDirectory(prefix="iwx-output-kick-") as directory:
    binary = Path(directory) / "iwx-output-kick-test"
    subprocess.run(
        [
            "xcrun",
            "clang++",
            "-std=c++14",
            "-O1",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-fsanitize=address,undefined",
            "-fno-omit-frame-pointer",
            "-pthread",
            "-I",
            str(ROOT),
            str(ROOT / "native/tests/iwx_output_kick_test.cpp"),
            "-o",
            str(binary),
        ],
        check=True,
    )
    subprocess.run([str(binary)], check=True)

print("PASS: deferred STA output kick remains epoch-bound and lifecycle-fenced")
