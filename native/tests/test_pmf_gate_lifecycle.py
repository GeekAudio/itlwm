#!/usr/bin/env python3
"""Source-level regression for the production PMF gate and teardown paths."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
DRIVER = (ROOT / "itlwm/hal_iwx/ItlIwx.cpp").read_text()
NODE = (ROOT / "itl80211/openbsd/net80211/ieee80211_node.c").read_text()
IOCTL = (ROOT / "itl80211/openbsd/net80211/ieee80211_ioctl.c").read_text()


def body(source: str, marker: str) -> str:
    start = source.index(marker)
    opening = source.index("{", start)
    depth = 0
    for offset in range(opening, len(source)):
        if source[offset] == "{":
            depth += 1
        elif source[offset] == "}":
            depth -= 1
            if depth == 0:
                return source[opening + 1 : offset]
    raise AssertionError(f"unterminated function body: {marker}")


gate_action = body(DRIVER, "iwx_pmf_gate_action(OSObject *")
assert "static_cast<ItlIwx *>(ownerArg)" in gate_action
assert "sc != &that->com" in gate_action
assert "that->tahoeP2pOnMainGate()" in gate_action
assert "IWX_PMF_GATE_COMPLETE" in gate_action
assert "IWX_PMF_GATE_SET_KEY" in gate_action

timer_callback = body(DRIVER, "iwx_pmf_reset_retry_timeout(void *arg)")
assert timer_callback.index("sc_pmf_reset_timeout_active") < timer_callback.index(
    "nativeLifecycleTearingDown_")
assert "sc_pmf_reset_task" in timer_callback
assert "sc->init_task" not in timer_callback
assert "sc_pmf_key_cmd" not in timer_callback
assert timer_callback.count("sc_pmf_reset_timeout_active") >= 3

retry_task = body(DRIVER, "iwx_pmf_reset_task(void *arg)")
assert "sc_pmf_reset_task_active" in retry_task
assert "iwx_pmf_run_gate(sc, &request)" in retry_task
assert "request.result != 0" in retry_task
assert "that->iwx_init_task(sc)" in retry_task
assert "iwx_pmf_reset_retry(sc, EBUSY)" in retry_task
assert "IWX_PMF_GATE_RESET_COMPLETE" in retry_task

retry_policy = body(DRIVER, "iwx_pmf_reset_retry(struct iwx_softc *sc, int stopError)")
assert "itl_pmf_reset_identity_valid" in retry_policy
assert "itl_pmf_reset_deadline_expired" in retry_policy
assert "itl_pmf_reset_busy_retry_allowed" in retry_policy
assert "ITL_PMF_RESET_RETRY_DELAY_MS" in retry_policy
assert "sc_pmf_reset_attempt_inflight" in retry_policy

invalidate = body(DRIVER, "iwx_pmf_invalidate_generation_gated(struct iwx_softc *sc)")
assert "keepResetAttempt" in invalidate
assert "sc_pmf_reset_generation = static_cast<uint32_t>(sc->sc_generation)" in invalidate

init_entry = body(DRIVER, "iwx_init_task(void *arg1)")
assert "iwx_init_task_execute(arg1, nullptr, nullptr)" in init_entry
init_task = body(DRIVER, "iwx_init_task_execute(void *arg1,")
assert "IWX_PMF_GATE_RESET_VALIDATE" in init_task
assert "|| pmfResetAttempt" in init_task

stop = body(DRIVER, "iwx_stop(struct _ifnet *ifp, IwxResetTrace::ResetReason reason)")
assert "TASKQ_PAUSE_DIAG_PAUSED" in stop
assert "pmfResetOwnsPausedQueue" in stop

completion = body(DRIVER, "iwx_pmf_key_completion_task(struct iwx_softc *sc)")
assert "tahoeP2pOnMainGate()" in completion
assert "iwx_pmf_schedule_reset(sc)" in completion
assert "RNSA_SUPP_PTKDONE" in completion
assert "IEEE80211_NODE_RXMGMTPROT" in completion
assert "IEEE80211_NODE_TXMGMTPROT" in completion

detach = body(DRIVER, "detach(IOPCIDevice *device)")
assert "taskq_try_pause_with_diagnostics" in detach
assert "sc_pmf_reset_task_active" in detach
assert "sc_pmf_reset_timeout_active" in detach
assert "sc_pmf_gate_waiters" in detach
assert "iwx_pmf_clear_responses(sc)" in detach
assert "__atomic_exchange_n(&nativePmfDetachRetainHeld_" in detach
assert detach.count("retain();") == 1
assert "releasePmfDetachRetain" in detach
assert detach.index("quiesceRxInterruptSource();") < detach.index("iwx_free_tx_ring")

rx = body(DRIVER, "iwx_rx_pkt(struct iwx_softc *sc")
assert "tahoeP2pOnMainGate()" in rx

assert "ieee80211_pmf_keys_cancel(ic, ic->ic_bss)" in body(
    IOCTL, "ieee80211_disable_rsn(struct ieee80211com *ic)")
assert "ieee80211_pmf_keys_cancel(ic, ni)" in body(
    NODE, "ieee80211_node_leave_rsn(struct ieee80211com *ic,")

print("PMF main-gate, timeout, reset-retry, and detach source checks passed")
