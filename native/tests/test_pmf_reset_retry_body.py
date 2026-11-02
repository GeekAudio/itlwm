#!/usr/bin/env python3
"""Compile and execute the production PMF reset-retry function body."""

from pathlib import Path
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[2]
DRIVER = (ROOT / "itlwm/hal_iwx/ItlIwx.cpp").read_text()


def function_body(source: str, marker: str) -> str:
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


body = function_body(DRIVER, "iwx_pmf_reset_retry(struct iwx_softc *sc, int stopError)")
prefix = r"""
#define AIRPORT_TAHOE 1
#include <cassert>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include "native/pmf_crypto_policy.h"

#define IEEE80211_NODE_MFP 0x01U
#define IEEE80211_F_RSNON 0x01U
#define IWX_PMF_GATE_RESET 1
#define IOLog(...) ((void)0)

using CTimeout = int;
struct ieee80211_node {
    uint32_t ni_pmf_key_epoch;
    uint32_t ni_flags;
};
struct ieee80211com {
    ieee80211_node *ic_bss;
    uint32_t ic_flags;
};
struct iwx_softc {
    ieee80211com sc_ic;
    int sc_generation;
    uint8_t sc_pmf_reset_requested;
    uint8_t sc_pmf_reset_attempt_inflight;
    uint8_t sc_pmf_reset_attempts;
    uint8_t sc_pmf_force_closed;
    uint32_t sc_pmf_reset_attempt_token;
    uint32_t sc_pmf_reset_attempt_node_epoch;
    uint32_t sc_pmf_reset_token;
    uint32_t sc_pmf_reset_generation;
    uint32_t sc_pmf_reset_node_epoch;
    uint64_t sc_pmf_reset_deadline_ns;
    ieee80211_node *sc_pmf_reset_node;
    CTimeout *sc_pmf_reset_retry_timeout;
    uint8_t sc_pmf_reset_retry_timeout_initialized;
};
struct iwx_pmf_gate_request {
    int operation;
    int result;
};

static uint64_t now_ns;
static int timeout_add_calls;
static int timeout_delete_calls;
static int last_timeout_ms;
static uint64_t iwx_pmf_monotonic_ns() { return now_ns; }
static int timeout_add_msec(CTimeout **, int delay) {
    ++timeout_add_calls;
    last_timeout_ms = delay;
    return 1;
}
static int timeout_del(CTimeout **) {
    ++timeout_delete_calls;
    return 1;
}

class ItlIwx {
public:
    bool tahoeP2pOnMainGate() const { return true; }
    int iwx_pmf_run_gate(iwx_softc *, iwx_pmf_gate_request *) { return 0; }
    void iwx_pmf_cancel_reset(iwx_softc *sc) {
        sc->sc_pmf_reset_requested = 0;
        sc->sc_pmf_reset_attempt_inflight = 0;
        sc->sc_pmf_reset_attempt_token = 0;
        sc->sc_pmf_reset_attempt_node_epoch = 0;
        sc->sc_pmf_reset_attempts = 0;
        sc->sc_pmf_reset_generation = 0;
        sc->sc_pmf_reset_node_epoch = 0;
        sc->sc_pmf_reset_deadline_ns = 0;
        sc->sc_pmf_reset_node = nullptr;
    }
    int iwx_pmf_reset_retry(iwx_softc *, int);
};
"""

tests = r"""
static void initialize(iwx_softc &sc, ieee80211_node &ni) {
    sc = {};
    ni = {};
    ni.ni_pmf_key_epoch = 9;
    ni.ni_flags = IEEE80211_NODE_MFP;
    sc.sc_ic.ic_bss = &ni;
    sc.sc_ic.ic_flags = IEEE80211_F_RSNON;
    sc.sc_generation = 4;
    sc.sc_pmf_reset_requested = 1;
    sc.sc_pmf_reset_generation = 4;
    sc.sc_pmf_reset_node_epoch = 9;
    sc.sc_pmf_reset_deadline_ns = 1000000000ULL;
    sc.sc_pmf_reset_node = &ni;
    sc.sc_pmf_reset_retry_timeout_initialized = 1;
}

int main() {
    ItlIwx driver;
    iwx_softc sc{};
    ieee80211_node ni{};

    /* EBUSY re-arms one bounded delay and leaves the attempt uncommitted. */
    initialize(sc, ni);
    now_ns = 900000000ULL;
    timeout_add_calls = timeout_delete_calls = 0;
    assert(driver.iwx_pmf_reset_retry(&sc, EBUSY) == 0);
    assert(timeout_add_calls == 1 && last_timeout_ms == ITL_PMF_RESET_RETRY_DELAY_MS);
    assert(sc.sc_pmf_reset_attempts == 0);
    assert(sc.sc_pmf_reset_attempt_inflight == 0);
    assert(sc.sc_pmf_reset_deadline_ns ==
        now_ns + uint64_t(ITL_PMF_RESET_RETRY_DELAY_MS) * 1000000ULL);

    /* A premature timer is rearmed only for the remaining deadline. */
    initialize(sc, ni);
    now_ns = 950000000ULL;
    timeout_add_calls = timeout_delete_calls = 0;
    assert(driver.iwx_pmf_reset_retry(&sc, 0) == 0);
    assert(timeout_add_calls == 1 && last_timeout_ms == 50);
    assert(sc.sc_pmf_reset_attempts == 0);
    assert(sc.sc_pmf_reset_attempt_inflight == 0);

    /* At the deadline, the real production function authorizes one reset. */
    initialize(sc, ni);
    now_ns = 1000000000ULL;
    timeout_add_calls = timeout_delete_calls = 0;
    assert(driver.iwx_pmf_reset_retry(&sc, 0) == 1);
    assert(sc.sc_pmf_reset_attempts == 1);
    assert(sc.sc_pmf_reset_attempt_inflight == 1);

    /* Stale generation and stale node epoch cancel without touching timers. */
    initialize(sc, ni);
    sc.sc_generation++;
    timeout_add_calls = timeout_delete_calls = 0;
    assert(driver.iwx_pmf_reset_retry(&sc, EBUSY) == 0);
    assert(sc.sc_pmf_reset_requested == 0 && timeout_add_calls == 0);
    initialize(sc, ni);
    ni.ni_pmf_key_epoch++;
    assert(driver.iwx_pmf_reset_retry(&sc, EBUSY) == 0);
    assert(sc.sc_pmf_reset_requested == 0 && timeout_add_calls == 0);

    /* Retry exhaustion and non-Busy errors fail closed and cancel the batch. */
    initialize(sc, ni);
    sc.sc_pmf_reset_attempts = ITL_PMF_RESET_RETRY_LIMIT;
    assert(driver.iwx_pmf_reset_retry(&sc, EBUSY) == 0);
    assert(sc.sc_pmf_reset_requested == 0);
    assert(sc.sc_pmf_force_closed == 1);
    initialize(sc, ni);
    assert(driver.iwx_pmf_reset_retry(&sc, EIO) == 0);
    assert(sc.sc_pmf_reset_requested == 0);
    assert(sc.sc_pmf_force_closed == 1);

    std::puts("PMF reset retry production body test passed");
}
"""

source = prefix + "\nint ItlIwx::iwx_pmf_reset_retry(iwx_softc *sc, int stopError) {" + body + "}\n" + tests
with tempfile.TemporaryDirectory(prefix="itlwm-pmf-reset-test-") as directory:
    cpp = Path(directory) / "pmf_reset_retry.cpp"
    binary = Path(directory) / "pmf_reset_retry"
    cpp.write_text(source)
    subprocess.run(
        ["clang++", "-std=c++14", "-Wall", "-Wextra", "-Werror",
         "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
         "-I", str(ROOT), str(cpp), "-o", str(binary)],
        check=True,
    )
    subprocess.run([str(binary)], check=True)
