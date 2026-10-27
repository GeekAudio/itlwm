#!/usr/bin/env python3
"""Extract and exercise the production iwx_newstate() with a host-side taskq shim."""
from pathlib import Path
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "itlwm/hal_iwx/ItlIwx.cpp"


def production_function(source: str) -> str:
    marker = "int ItlIwx::\niwx_newstate("
    start = source.find(marker)
    if start < 0:
        raise RuntimeError("production iwx_newstate definition not found")
    brace = source.find("{", start)
    if brace < 0:
        raise RuntimeError("production iwx_newstate body not found")

    # Match the C++ function braces while ignoring comments and string literals.
    depth = 0
    i = brace
    state = "code"
    while i < len(source):
        ch = source[i]
        nxt = source[i + 1] if i + 1 < len(source) else ""
        if state == "code":
            if ch == "/" and nxt == "/":
                state = "line_comment"
                i += 2
                continue
            if ch == "/" and nxt == "*":
                state = "block_comment"
                i += 2
                continue
            if ch == '"':
                state = "string"
            elif ch == "'":
                state = "char"
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    return source[start:i + 1]
        elif state == "line_comment":
            if ch == "\n":
                state = "code"
        elif state == "block_comment":
            if ch == "*" and nxt == "/":
                state = "code"
                i += 2
                continue
        elif state in ("string", "char"):
            if ch == "\\":
                i += 2
                continue
            if (state == "string" and ch == '"') or (state == "char" and ch == "'"):
                state = "code"
        i += 1
    raise RuntimeError("unterminated production iwx_newstate body")


HARNESS = r'''
#include <assert.h>
#include <stddef.h>
#include <stdint.h>

enum ieee80211_state {
    IEEE80211_S_INIT = 0,
    IEEE80211_S_SCAN = 1,
    IEEE80211_S_AUTH = 2,
    IEEE80211_S_ASSOC = 3,
    IEEE80211_S_RUN = 4,
};

constexpr int EBUSY = 16;
constexpr int ENXIO = 6;
constexpr int IWX_FLAG_SHUTDOWN = 0x800;

struct task {
    bool onQueue = false;
};

struct taskq {
    bool paused = false;
    int enterError = 0;
    int lockDepth = 0;
    unsigned active = 0;
    unsigned scheduled = 0;
};

struct iwx_softc;
struct _ifnet {
    iwx_softc *if_softc = nullptr;
};

struct ieee80211_node {
    uint32_t ni_tx_rate_generation = 0;
    uint32_t ni_tx_rate_sequence = 0;
    uint64_t ni_tx_rate_sample = 0;
    uint32_t ni_tx_rate_flags_raw = 0;
    uint32_t ni_tx_rate_sample_generation = 0;
    uint32_t ni_tx_rate_update_count = 0;
    uint32_t ni_tx_rate_single_count = 0;
    uint32_t ni_tx_rate_aggregate_count = 0;
    uint64_t ni_tx_rate_tlc_sample = 0;
    uint32_t ni_tx_rate_tlc_flags_raw = 0;
};

struct ieee80211com {
    _ifnet ic_if;
    enum ieee80211_state ic_state = IEEE80211_S_INIT;
    ieee80211_node *ic_bss = nullptr;
};

struct taskq;
struct iwx_softc {
    uint32_t sc_flags = 0;
    uint32_t sc_generation = 1;
    uint32_t sc_tx_rate_generation = 0;
    enum ieee80211_state ns_nstate = IEEE80211_S_INIT;
    int ns_arg = 0;
    taskq *sc_nswq = nullptr;
    task newstate_task;
    task ba_task;
    task mac_ctxt_task;
    task chan_ctxt_task;
};

struct ItlIwx {
    iwx_softc com;
    uint32_t tahoe_newstate_generation_ = 0;
    unsigned addCalls = 0;
    unsigned delBaCalls = 0;
    unsigned delMacCalls = 0;
    unsigned delChanCalls = 0;
    unsigned ampduStops = 0;
    unsigned baDeletes = 0;

    int iwx_newstate(ieee80211com *, enum ieee80211_state, int);
    void iwx_add_task(iwx_softc *, taskq *, task *);
    void iwx_del_task(iwx_softc *, taskq *, task *);
};

static int g_splDepth = 0;
static unsigned g_clearSnapshotCalls = 0;
static taskq g_systemTaskq;
static taskq *const systq = &g_systemTaskq;

static int splnet() { return g_splDepth++; }
static void splx(int old) { g_splDepth = old; }

static int taskq_enter_unpaused(taskq *q)
{
    if (q->enterError) return q->enterError;
    if (q->paused) return EBUSY;
    ++q->lockDepth;
    return 0;
}

static void taskq_leave(taskq *q)
{
    assert(q->lockDepth > 0);
    --q->lockDepth;
}

static int taskq_try_pause(taskq *q)
{
    if (q->lockDepth || q->active || q->paused) return EBUSY;
    q->paused = true;
    return 0;
}

static void taskq_pop(taskq *q, task *t)
{
    assert(t->onQueue);
    t->onQueue = false;
    ++q->active;
}

static void taskq_work_done(taskq *q)
{
    assert(q->active > 0);
    --q->active;
}

static void ieee80211_stop_ampdu_tx(ieee80211com *, ieee80211_node *, int)
{
    // The calling driver's counter is incremented by the fixture wrapper.
}

static void ieee80211_ba_del(ieee80211_node *)
{
}

struct IwxTxRate {
    template <typename... Args>
    static bool clearSnapshot(Args...)
    {
        ++g_clearSnapshotCalls;
        return true;
    }
};

#define IC2IFP(ic) (&((ic)->ic_if))
#define container_of(ptr, type, member) \
    reinterpret_cast<type *>(reinterpret_cast<char *>(ptr) - offsetof(type, member))

static unsigned g_ampduStopCalls = 0;
static unsigned g_baDeleteCalls = 0;

static void ieee80211_stop_ampdu_tx_counted(ieee80211com *ic,
                                             ieee80211_node *ni, int tid)
{
    ++g_ampduStopCalls;
    ieee80211_stop_ampdu_tx(ic, ni, tid);
}

static void ieee80211_ba_del_counted(ieee80211_node *ni)
{
    ++g_baDeleteCalls;
    ieee80211_ba_del(ni);
}

void ItlIwx::iwx_add_task(iwx_softc *, taskq *q, task *t)
{
    ++addCalls;
    if (!q->paused && !t->onQueue) {
        t->onQueue = true;
        ++q->scheduled;
    }
}

void ItlIwx::iwx_del_task(iwx_softc *, taskq *, task *t)
{
    if (t == &com.ba_task) ++delBaCalls;
    if (t == &com.mac_ctxt_task) ++delMacCalls;
    if (t == &com.chan_ctxt_task) ++delChanCalls;
    t->onQueue = false;
}

// Redirect only the two net80211 cleanup calls to observable fixture counters.
#define ieee80211_stop_ampdu_tx ieee80211_stop_ampdu_tx_counted
#define ieee80211_ba_del ieee80211_ba_del_counted

@@PRODUCTION_FUNCTION@@

#undef ieee80211_stop_ampdu_tx
#undef ieee80211_ba_del

struct Fixture {
    ItlIwx driver;
    taskq queue;
    ieee80211com ic;
    ieee80211_node node;

    Fixture()
    {
        driver.com.sc_nswq = &queue;
        ic.ic_if.if_softc = &driver.com;
        ic.ic_bss = &node;
        driver.com.ns_nstate = IEEE80211_S_RUN;
        driver.com.ns_arg = 71;
        ic.ic_state = IEEE80211_S_RUN;
    }
};

static void assert_balanced(const Fixture &f)
{
#ifdef AIRPORT_TAHOE
    assert(f.queue.lockDepth == 0);
    assert(g_splDepth == 0);
#else
    (void)f;
    assert(g_splDepth == 0);
#endif
}

static void test_duplicate_run_is_coalesced_while_worker_active()
{
    Fixture f;
    f.driver.com.newstate_task.onQueue = true;
    taskq_pop(&f.queue, &f.driver.com.newstate_task);
    f.driver.com.ns_nstate = IEEE80211_S_RUN;
    f.driver.com.ns_arg = 71;
    f.driver.com.sc_tx_rate_generation = 19;
    f.driver.tahoe_newstate_generation_ = 23;
    const int result = f.driver.iwx_newstate(&f.ic, IEEE80211_S_RUN, 99);
    assert(result == 0);
    assert(f.driver.com.ns_nstate == IEEE80211_S_RUN);
    assert(f.driver.com.ns_arg == 71);
    assert(f.driver.com.sc_tx_rate_generation == 19);
    assert(f.driver.tahoe_newstate_generation_ == 23);
    assert(f.driver.addCalls == 0 && f.queue.scheduled == 0);
    assert(!f.driver.com.newstate_task.onQueue);
    assert(f.driver.delBaCalls == 0 && f.driver.delMacCalls == 0 &&
           f.driver.delChanCalls == 0);
    assert(g_ampduStopCalls == 0 && g_baDeleteCalls == 0);
    assert(g_clearSnapshotCalls == 0);
    assert(taskq_try_pause(&f.queue) == EBUSY); // Active worker remains counted.
    taskq_work_done(&f.queue);
    assert(taskq_try_pause(&f.queue) == 0); // Stop can now pause the idle queue.
    assert_balanced(f);
}

static void test_scan_and_auth_repeat_exceptions()
{
    {
        Fixture f;
        f.ic.ic_state = IEEE80211_S_SCAN;
        f.driver.com.ns_nstate = IEEE80211_S_SCAN;
        assert(f.driver.iwx_newstate(&f.ic, IEEE80211_S_SCAN, 4) == 0);
        assert(f.driver.com.ns_arg == 4);
        assert(f.driver.addCalls == 1 && f.queue.scheduled == 1);
#ifdef AIRPORT_TAHOE
        assert(g_clearSnapshotCalls == 1);
#else
        assert(g_clearSnapshotCalls == 0);
#endif
        assert_balanced(f);
    }
    {
        Fixture f;
        f.ic.ic_state = IEEE80211_S_AUTH;
        f.driver.com.ns_nstate = IEEE80211_S_AUTH;
        g_clearSnapshotCalls = 0;
        assert(f.driver.iwx_newstate(&f.ic, IEEE80211_S_AUTH, 5) == 0);
        assert(f.driver.com.ns_arg == 5);
        assert(f.driver.addCalls == 1 && f.queue.scheduled == 1);
#ifdef AIRPORT_TAHOE
        assert(g_clearSnapshotCalls == 1);
#else
        assert(g_clearSnapshotCalls == 0);
#endif
        assert_balanced(f);
    }
}

static void test_different_state_transition_still_cleans_and_queues()
{
    Fixture f;
    f.ic.ic_state = IEEE80211_S_RUN;
    f.driver.com.ns_nstate = IEEE80211_S_RUN;
    assert(f.driver.iwx_newstate(&f.ic, IEEE80211_S_AUTH, 6) == 0);
    assert(f.driver.com.ns_nstate == IEEE80211_S_AUTH);
    assert(f.driver.com.ns_arg == 6);
    assert(f.driver.delBaCalls == 1 && f.driver.delMacCalls == 1 &&
           f.driver.delChanCalls == 1);
    assert(f.driver.addCalls == 1 && f.queue.scheduled == 1);
#ifdef AIRPORT_TAHOE
    assert(f.driver.com.sc_tx_rate_generation == 1);
    assert(g_clearSnapshotCalls == 1);
#else
    assert(f.driver.com.sc_tx_rate_generation == 0);
    assert(g_clearSnapshotCalls == 0);
#endif
    assert_balanced(f);
}

static void test_unpaused_gate_failure_and_shutdown_release()
{
#ifdef AIRPORT_TAHOE
    {
        Fixture f;
        f.queue.paused = true;
        assert(f.driver.iwx_newstate(&f.ic, IEEE80211_S_AUTH, 7) == EBUSY);
        assert(f.driver.addCalls == 0 && f.queue.scheduled == 0);
        assert(f.queue.lockDepth == 0 && g_splDepth == 0);
    }
    {
        Fixture f;
        f.queue.enterError = EBUSY; // Simulate queue-lock acquisition failure.
        assert(f.driver.iwx_newstate(&f.ic, IEEE80211_S_AUTH, 9) == EBUSY);
        assert(f.driver.addCalls == 0 && f.queue.scheduled == 0);
        assert(f.queue.lockDepth == 0 && g_splDepth == 0);
    }
    {
        Fixture f;
        f.driver.com.sc_flags = IWX_FLAG_SHUTDOWN;
        assert(f.driver.iwx_newstate(&f.ic, IEEE80211_S_AUTH, 8) == ENXIO);
        assert(f.driver.addCalls == 0 && f.queue.scheduled == 0);
        assert(f.queue.lockDepth == 0 && g_splDepth == 0);
    }
#endif
}

int main()
{
    test_duplicate_run_is_coalesced_while_worker_active();
    g_ampduStopCalls = g_baDeleteCalls = g_clearSnapshotCalls = 0;
    test_scan_and_auth_repeat_exceptions();
    g_ampduStopCalls = g_baDeleteCalls = g_clearSnapshotCalls = 0;
    test_different_state_transition_still_cleans_and_queues();
    g_ampduStopCalls = g_baDeleteCalls = g_clearSnapshotCalls = 0;
    test_unpaused_gate_failure_and_shutdown_release();
}
'''


def compile_and_run(function: str, tahoe: bool) -> None:
    program = HARNESS.replace("@@PRODUCTION_FUNCTION@@", function)
    with tempfile.TemporaryDirectory(prefix="iwx-newstate-") as directory:
        source = Path(directory) / "iwx_newstate.cpp"
        binary = Path(directory) / "iwx_newstate"
        source.write_text(program)
        command = ["clang++", "-std=c++17", "-Wall", "-Wextra", "-Werror"]
        if tahoe:
            command.append("-DAIRPORT_TAHOE=1")
        else:
            command += ["-Wno-unused-function", "-Wno-unused-const-variable"]
        subprocess.run(command + [str(source), "-o", str(binary)], check=True)
        subprocess.run([str(binary)], check=True)


if __name__ == "__main__":
    body = production_function(SOURCE.read_text())
    compile_and_run(body, tahoe=True)
    compile_and_run(body, tahoe=False)
    print("PASS: production iwx_newstate duplicate filtering, queue cleanup, and SCAN/AUTH repeat rules (Tahoe and non-Tahoe)")
