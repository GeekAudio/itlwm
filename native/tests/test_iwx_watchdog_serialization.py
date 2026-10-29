from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
DRIVER = (ROOT / "itlwm/hal_iwx/ItlIwx.cpp").read_text()
HEADER = (ROOT / "itlwm/hal_iwx/ItlIwx.hpp").read_text()
RX = (ROOT / "itlwm/hal_iwx/ItlIwxP2PRx.cpp").read_text()
TRACE = (ROOT / "native/iwx_reset_trace.hpp").read_text()
AIRPORT = (ROOT / "AirportItlwm/AirportItlwmV2.cpp").read_text()
TASKQ = (ROOT / "itl80211/openbsd/sys/_task.cpp").read_text()


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


watchdog = function_body(DRIVER, "iwx_watchdog(struct _ifnet *ifp)")
tahoe_watchdog = watchdog.split("#else", 1)[0]
watchdog_action = function_body(DRIVER, "ItlIwx::_iwx_watchdog_task(")
snapshot = function_body(
    DRIVER, "ItlIwx::tahoeRecordTxWatchdogSnapshot(struct iwx_softc *sc,")

# Tahoe hands the timer decision to the command gate without a blocking runAction
# and defers only TX countdown when admission fails; IEEE housekeeping remains.
assert "attemptAction(_iwx_watchdog_task, ifp, &dispatch)" in watchdog
assert "if (actionResult == kIOReturnSuccess && dispatch.timedOut)" in watchdog
assert watchdog.rindex("ieee80211_watchdog(ifp)") > watchdog.index(
    "attemptAction(_iwx_watchdog_task, ifp, &dispatch)"
)
assert "IwxTxWatchdog::advance(&sc->sc_tx_timer, true)" not in tahoe_watchdog
assert "--sc->sc_tx_timer" not in tahoe_watchdog
assert "sc->sc_tx_timer > 0" not in tahoe_watchdog

# The callback is allowed to run on the watchdog caller while holding the main
# gate. Require inGate, not onThread, and defer if the lifecycle try-lock fails.
assert "tahoeP2pOnMainGate()" in watchdog_action
assert "TahoeLifecycleGuard lifecycle(that, true, false," in watchdog_action
assert "&result->flushDeferredTasks" in watchdog_action
assert "if (!lifecycle)" in watchdog_action
assert "IwxTxWatchdog::advance(&sc->sc_tx_timer, true)" in watchdog_action
assert "task_add(systq, &sc->init_task)" in watchdog_action
assert watchdog_action.index("tick == IwxTxWatchdog::TickResult::kExpired") < watchdog_action.index(
    "task_add(systq, &sc->init_task)"
)
assert "IwxTxWatchdog::shouldEnqueueRecovery(tick, shutdown)" in watchdog_action
assert watchdog_action.index("(sc->sc_flags & IWX_FLAG_SHUTDOWN) != 0") < watchdog_action.index(
    "task_add(systq, &sc->init_task)"
)
assert "tahoeReleaseLifecycleFence(bool flushDeferredTasks)" in DRIVER
assert "outermost && flushDeferredTasks" in DRIVER
assert "if (dispatch.flushDeferredTasks && !alreadyInMainGate)" in watchdog
assert "const bool alreadyInMainGate = loop && loop->inGate();" in watchdog
assert watchdog.index("attemptAction(_iwx_watchdog_task, ifp, &dispatch)") < watchdog.index(
    "if (dispatch.flushDeferredTasks && !alreadyInMainGate)"
)
assert "task_add(systq, &sc->init_task)" not in tahoe_watchdog
# The enqueue is part of the same gate+fence epoch as the timeout decision;
# stop cannot advance generation and task_del before it. The non-Tahoe branch
# retains its original shutdown guard.
assert "the same main-gate and" in watchdog_action
assert "lifecycle-fence epoch as the expiry decision" in watchdog_action
assert "sc->txq" not in watchdog_action
assert "ic_bss" not in watchdog_action
assert "taskq_try_pause" not in watchdog_action
assert "if (!sc || !tahoeP2pOnMainGate())" in snapshot
assert "queueSnapshotAvailable = 0" in snapshot
assert "const uint32_t sequence = nativeResetTrace_.recordTxWatchdog(sample);" in snapshot
assert "sc->sc_tx_progress_pending = sample.txProgress;" in snapshot
assert "sc->sc_tx_progress_pending_watchdog_sequence = sequence;" in snapshot
assert "sc->sc_tx_progress_pending_present = 1;" in snapshot
assert "setProperty(" not in snapshot
assert "publishTxProgress" not in snapshot
assert "sc->txq" not in snapshot
assert "ic_bss" not in snapshot

# Large IORegistry batches run on the existing periodic main-gate publisher,
# after the expiry callback has returned and queued recovery. A failed publish
# remains pending for retry; the owner sequence lets readers reject stale rows.
progress_publisher = function_body(
    DRIVER, "ItlIwx::tahoePublishTxProgressSnapshot(")
reset_publisher = function_body(RX, "void ItlIwx::tahoePublishResetTrace(")
assert "tahoeP2pOnMainGate()" in progress_publisher
assert "publishTxProgressSnapshot(controller," in progress_publisher
assert "if (publishTxProgressSnapshot" in progress_publisher
assert "nativeResetTracePublishedTxProgressWatchdogSequence_ = ownerSequence;" in progress_publisher
assert "NativeResetTraceTxProgressOwnerWatchdogSequence" in DRIVER
assert "NativeResetTraceTxProgressOwnerGeneration" in DRIVER
assert "txProgressNeedsPublish" in reset_publisher
assert "!txProgressNeedsPublish" in reset_publisher
assert reset_publisher.index("nativeResetTracePublishedOnce_ = true;") < reset_publisher.index(
    "tahoePublishTxProgressSnapshot(controller, &com);")

gate_check = function_body(HEADER, "bool tahoeP2pOnMainGate()")
assert "loop && loop->inGate()" in gate_check
assert "onThread" not in gate_check

# Preserve the established non-Tahoe shutdown check around init_task posting.
assert "if ((sc->sc_flags & IWX_FLAG_SHUTDOWN) == 0)\n            task_add(systq, &sc->init_task);" in watchdog

# The taskq worker releases tq_mtx before calling a task body. This lock-order
# property makes an enqueue from the command gate safe from a tq_mtx->gate cycle.
taskq_pop = function_body(TASKQ, "taskq_next_work(struct taskq *tq,")
taskq_worker = function_body(TASKQ, "taskq_thread(void *xtq)")
assert taskq_pop.index("IORecursiveLockUnlock(tq->tq_mtx)") < taskq_pop.index("return (1)")
assert taskq_worker.index("while (taskq_next_work(tq, &work))") < taskq_worker.index(
    "(*work.t_func)(work.t_arg)"
)
task_add_body = function_body(TASKQ, "task_add(struct taskq *tq, struct task *w)")
assert task_add_body.index("IORecursiveLockLock(tq->tq_mtx)") < task_add_body.index(
    "IORecursiveLockUnlock(tq->tq_mtx)"
)

# Every sc_tx_timer write uses the shared atomic helper; the only timer read is
# an atomic diagnostic value inside the lifecycle-guarded gate action.
assert "sc_tx_timer =" not in DRIVER
assert "--sc->sc_tx_timer" not in DRIVER
assert "&sc->sc_tx_timer, __ATOMIC_ACQUIRE" in watchdog_action
assert "txWatchdogQueueSnapshotAvailable" in TRACE

# Parent stop/failure drains the existing watchdog source before HAL teardown;
# releaseAll also detaches it before freeing the HAL/workloop owner.
stop = function_body(AIRPORT, "void AirportItlwm::stop(IOService *provider)")
assert stop.index("detachWatchdogTimer()") < stop.index("fHalService->detach(pciNub)")
release_all = function_body(AIRPORT, "void AirportItlwm::releaseAll()")
assert release_all.index("detachWatchdogTimer()") < release_all.index("releaseNativeCapture()")
assert release_all.index("detachWatchdogTimer()") < release_all.index("fHalService->release()")

