#!/usr/bin/env python3
"""Check production STA RUN-retirement helper and its two bypass call sites."""
from __future__ import annotations

import pathlib
import subprocess
import tempfile


ROOT = pathlib.Path(__file__).resolve().parents[2]
SOURCE = ROOT / "itlwm/hal_iwx/ItlIwx.cpp"


def extract_function(source: str, marker: str) -> str:
    start = source.find(marker)
    if start < 0:
        raise AssertionError(f"production function not found: {marker}")
    brace = source.find("{", start)
    if brace < 0:
        raise AssertionError(f"body not found: {marker}")
    depth = 0
    state = "code"
    index = brace
    while index < len(source):
        char = source[index]
        next_char = source[index + 1] if index + 1 < len(source) else ""
        if state == "code":
            if char == "/" and next_char == "/":
                state = "line"
                index += 2
                continue
            if char == "/" and next_char == "*":
                state = "block"
                index += 2
                continue
            if char == '"':
                state = "string"
            elif char == "'":
                state = "char"
            elif char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    return source[start : index + 1]
        elif state == "line":
            if char == "\n":
                state = "code"
        elif state == "block":
            if char == "*" and next_char == "/":
                state = "code"
                index += 2
                continue
        elif state in ("string", "char"):
            if char == "\\":
                index += 2
                continue
            if (state == "string" and char == '"') or (
                state == "char" and char == "'"
            ):
                state = "code"
        index += 1
    raise AssertionError(f"unterminated function: {marker}")


HARNESS = r"""
#include <cassert>
#include <cstdint>
#include "native/iwx_sta_auth_trace.h"

enum { IEEE80211_S_INIT = 0, IEEE80211_S_SCAN = 1, IEEE80211_S_RUN = 4 };
static uint64_t tahoeMonotonicNs() { return 9000000ULL; }
struct ieee80211com { IwxStaAuthTrace ic_tahoe_auth_trace; };
struct iwx_softc { ieee80211com sc_ic; int sc_generation = 0; };

@@RECORD_AT_GENERATION@@
@@END_HELPER@@
@@RETIRE_HELPER@@

static const IwxStaAuthTraceEvent *lastEvent(IwxStaAuthTraceSnapshot &snapshot)
{
    assert(snapshot.live_count > 0);
    /* Each fixture below records one retirement event into a fresh trace. */
    return &snapshot.live[0];
}

int main()
{
    iwx_softc scan{};
    scan.sc_generation = 12;
    auto &scanTrace = scan.sc_ic.ic_tahoe_auth_trace;
    iwx_sta_auth_trace_init(&scanTrace, 1);
    assert(iwx_sta_auth_trace_begin_run(&scanTrace) == 1);
    assert(tahoeRetireStaRunAssociation(&scan, 12, IEEE80211_S_RUN,
        IEEE80211_S_SCAN, 0));
    IwxStaAuthTraceSnapshot snapshot{};
    assert(iwx_sta_auth_trace_snapshot(&scanTrace, &snapshot));
    const auto *event = lastEvent(snapshot);
    assert(event->kind == IWX_STA_TRACE_ASSOC_LOSS);
    assert(event->stage == IWX_STA_STAGE_STATE_COMPLETED);
    assert(event->driver_generation == 12 && event->association_id == 1);
    assert(event->detail == ((IEEE80211_S_RUN << 16) | IEEE80211_S_SCAN));
    assert(snapshot.association_id == 0 && snapshot.first_state == 2);
    const uint32_t sequence = event->sequence;
    assert(!tahoeRetireStaRunAssociation(&scan, 12, IEEE80211_S_RUN,
        IEEE80211_S_SCAN, 0));
    assert(iwx_sta_auth_trace_snapshot(&scanTrace, &snapshot));
    assert(lastEvent(snapshot)->sequence == sequence); // no duplicate close

    /* stop() records the pre-increment generation, not sc_generation now. */
    iwx_softc stopped{};
    stopped.sc_generation = 20;
    auto &stopTrace = stopped.sc_ic.ic_tahoe_auth_trace;
    iwx_sta_auth_trace_init(&stopTrace, 2);
    assert(iwx_sta_auth_trace_begin_run(&stopTrace) == 1);
    const uint32_t preStopGeneration = stopped.sc_generation;
    ++stopped.sc_generation;
    assert(tahoeRetireStaRunAssociation(&stopped, preStopGeneration,
        IEEE80211_S_RUN, IEEE80211_S_INIT, 0));
    assert(iwx_sta_auth_trace_snapshot(&stopTrace, &snapshot));
    event = lastEvent(snapshot);
    assert(event->driver_generation == 20 && stopped.sc_generation == 21);
    assert(event->association_id == 1 && snapshot.association_id == 0);

    /* A stale close must not clear a later association ID. */
    IwxStaAuthTrace replaced{};
    iwx_sta_auth_trace_init(&replaced, 4);
    assert(iwx_sta_auth_trace_begin_run(&replaced) == 1);
    assert(iwx_sta_auth_trace_begin_run(&replaced) == 2);
    assert(!tahoeEndStaRunAssociationIfCurrent(&replaced, 1));
    assert(__atomic_load_n(&replaced.association_id, __ATOMIC_ACQUIRE) == 2);

    /* Writer contention drops the event and only clears the expected run. */
    IwxStaAuthTrace contended{};
    iwx_sta_auth_trace_init(&contended, 5);
    assert(iwx_sta_auth_trace_begin_run(&contended) == 1);
    __atomic_store_n(&contended.writer, 1u, __ATOMIC_RELEASE);
    assert(!tahoeEndStaRunAssociationIfCurrent(&contended, 1));
    assert(__atomic_load_n(&contended.association_id, __ATOMIC_ACQUIRE) == 0);
    assert(__atomic_load_n(&contended.dropped_count, __ATOMIC_RELAXED) == 1);

    /* Non-RUN/background state and missing association are not invented. */
    iwx_softc noRun{};
    noRun.sc_generation = 5;
    iwx_sta_auth_trace_init(&noRun.sc_ic.ic_tahoe_auth_trace, 3);
    assert(iwx_sta_auth_trace_begin_run(&noRun.sc_ic.ic_tahoe_auth_trace) == 1);
    assert(!tahoeRetireStaRunAssociation(&noRun, 5, IEEE80211_S_SCAN,
        IEEE80211_S_INIT, 0));
    assert(!tahoeRetireStaRunAssociation(&noRun, 5, IEEE80211_S_RUN,
        IEEE80211_S_RUN, 0));
    assert(__atomic_load_n(&noRun.sc_ic.ic_tahoe_auth_trace.association_id,
                            __ATOMIC_ACQUIRE) == 1);
    iwx_softc noAssociation{};
    assert(!tahoeRetireStaRunAssociation(&noAssociation, 5,
        IEEE80211_S_RUN, IEEE80211_S_INIT, 0));
    return 0;
}
"""


def main() -> None:
    source = SOURCE.read_text(encoding="utf-8")
    scan = extract_function(source, "iwx_scan(struct iwx_softc *sc)")
    stop = extract_function(source, "iwx_stop(struct _ifnet *ifp,")
    bgscan = extract_function(source, "iwx_bgscan(struct ieee80211com *ic)")

    assert scan.index("scanRetiredRunLink = true") < scan.index(
        "ic->ic_state = IEEE80211_S_SCAN"
    )
    assert scan.index("ic->ic_state = IEEE80211_S_SCAN") < scan.index(
        "tahoeRetireStaRunAssociation"
    ) < scan.index("tahoeCommitScanStart")
    assert "stateBeforeScan == IEEE80211_S_RUN" in scan
    assert "ic->ic_state == IEEE80211_S_SCAN" in scan
    assert "generation == sc->sc_generation" in scan
    assert "tahoeRetireStaRunAssociation" not in bgscan

    assert stop.index("linkResetOldGeneration") < stop.index("sc->sc_generation++")
    assert stop.index("sc->sc_newstate(ic, IEEE80211_S_INIT, -1)") < stop.index(
        "tahoeRetireStaRunAssociation"
    )
    assert "linkResetOldState == IEEE80211_S_RUN" in stop
    assert "ic->ic_state == IEEE80211_S_INIT" in stop
    assert "linkResetOldGeneration" in stop.split(
        "tahoeRetireStaRunAssociation", 1
    )[1]

    record = extract_function(source, "static int tahoeRecordStaAuthAtGeneration(")
    end = extract_function(source, "static bool tahoeEndStaRunAssociationIfCurrent(")
    retire = extract_function(source, "static bool tahoeRetireStaRunAssociation(")
    generated = HARNESS.replace("@@RECORD_AT_GENERATION@@", record).replace(
        "@@END_HELPER@@", end
    ).replace("@@RETIRE_HELPER@@", retire)
    with tempfile.TemporaryDirectory(prefix="test091-run-retirement-") as directory:
        source_file = pathlib.Path(directory) / "retirement.cpp"
        binary = pathlib.Path(directory) / "retirement"
        source_file.write_text(generated, encoding="utf-8")
        subprocess.run(
            [
                "clang++", "-std=c++17", "-Wall", "-Wextra", "-Werror",
                "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
                "-I", str(ROOT), str(source_file), "-o", str(binary),
            ],
            check=True,
        )
        subprocess.run([str(binary)], check=True)

    print("PASS: RUN->SCAN/INIT retirement is attributed once to the old association generation")


if __name__ == "__main__":
    main()
