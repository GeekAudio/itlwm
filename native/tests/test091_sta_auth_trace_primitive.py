#!/usr/bin/env python3
"""Exercise the production fixed-capacity STA auth trace helper."""
from __future__ import annotations

import pathlib
import subprocess
import tempfile


ROOT = pathlib.Path(__file__).resolve().parents[2]
HEADER = ROOT / "native/iwx_sta_auth_trace.h"

HARNESS = r"""
#include <cassert>
#include <cstdint>
#include <thread>
#include <vector>
#include "native/iwx_sta_auth_trace.h"

static IwxStaAuthTraceInput event(uint32_t id, bool freeze = false) {
    IwxStaAuthTraceInput input{};
    input.monotonic_us = 0x100000000ULL + id;
    input.driver_generation = 5;
    input.attempt_id = id;
    input.kind = IWX_STA_TRACE_GROUP1_VALIDATION;
    input.stage = IWX_STA_STAGE_VALIDATED;
    input.source = IWX_STA_SOURCE_RX_PEER;
    input.result = 0;
    input.detail = id;
    input.freeze_first_failure = freeze ? 1 : 0;
    return input;
}

int main() {
    IwxStaAuthTrace trace{};
    iwx_sta_auth_trace_init(&trace, 77);
    assert(iwx_sta_auth_trace_begin_run(&trace) == 1);
    for (uint32_t i = 1; i <= 12; ++i) {
        auto input = event(i);
        assert(iwx_sta_auth_trace_record(&trace, &input) == 1);
    }
    auto trigger = event(13, true);
    trigger.kind = IWX_STA_TRACE_GROUP1_LOCAL_FAILURE;
    trigger.stage = IWX_STA_STAGE_GROUP1_TERMINAL;
    trigger.result = 11;
    assert(iwx_sta_auth_trace_record(&trace, &trigger) == 1);

    IwxStaAuthTraceSnapshot snapshot{};
    assert(iwx_sta_auth_trace_snapshot(&trace, &snapshot) == 1);
    assert(snapshot.magic == IWX_STA_AUTH_TRACE_MAGIC);
    assert(snapshot.schema == 1 && snapshot.header_bytes == 56);
    assert(snapshot.record_bytes == 48 && sizeof(snapshot) == 1208);
    assert(snapshot.diagnostic_instance == 77);
    assert(snapshot.association_id == 1);
    assert(snapshot.first_state == 2 && snapshot.first_count == 8);
    assert(snapshot.first[7].kind == IWX_STA_TRACE_GROUP1_LOCAL_FAILURE);
    assert(snapshot.first[7].attempt_id == 13 && snapshot.first[7].result == 11);
    assert(snapshot.first[0].detail == 6);

    // The immutable first-failure bundle survives subsequent live-ring wrap.
    for (uint32_t i = 14; i < 80; ++i) {
        auto input = event(i);
        (void)iwx_sta_auth_trace_record(&trace, &input);
    }
    assert(iwx_sta_auth_trace_snapshot(&trace, &snapshot) == 1);
    assert(snapshot.first_count == 8 && snapshot.first[7].attempt_id == 13);
    assert(snapshot.live_count == IWX_STA_AUTH_TRACE_LIVE_CAPACITY);

    // A claimed trigger that cannot acquire the try-only writer becomes lost.
    IwxStaAuthTrace lost{};
    iwx_sta_auth_trace_init(&lost, 78);
    __atomic_store_n(&lost.writer, 1u, __ATOMIC_RELEASE);
    auto lostTrigger = event(1, true);
    assert(iwx_sta_auth_trace_record(&lost, &lostTrigger) == 0);
    __atomic_store_n(&lost.writer, 0u, __ATOMIC_RELEASE);
    assert(iwx_sta_auth_trace_snapshot(&lost, &snapshot) == 1);
    assert(snapshot.first_state == 3);
    assert(snapshot.flags & IWX_STA_SNAPSHOT_FIRST_TRIGGER_LOST);
    assert(snapshot.first_count == 0 && snapshot.dropped_count == 1);

    // A pending claim is exported as pending, never as a complete bundle.
    IwxStaAuthTrace pending{};
    iwx_sta_auth_trace_init(&pending, 79);
    __atomic_store_n(&pending.first_state, 1u, __ATOMIC_RELEASE);
    auto overtaking = event(9);
    assert(iwx_sta_auth_trace_record(&pending, &overtaking) == 0);
    assert(iwx_sta_auth_trace_snapshot(&pending, &snapshot) == 1);
    assert(snapshot.first_state == 1 && snapshot.first_count == 0);
    assert(snapshot.live_count == 0 && snapshot.dropped_count == 1);

    // Concurrent writers are try-only; successful snapshots are bounded and
    // always carry an even, self-consistent revision pair.
    IwxStaAuthTrace concurrent{};
    iwx_sta_auth_trace_init(&concurrent, 80);
    std::vector<std::thread> writers;
    for (uint32_t t = 0; t < 4; ++t) {
        writers.emplace_back([&, t] {
            for (uint32_t i = 0; i < 2000; ++i) {
                auto input = event((t << 20) | i);
                (void)iwx_sta_auth_trace_record(&concurrent, &input);
            }
        });
    }
    for (auto &writer : writers)
        writer.join();
    assert(iwx_sta_auth_trace_snapshot(&concurrent, &snapshot) == 1);
    assert(snapshot.revision_begin == snapshot.revision_end);
    assert((snapshot.revision_end & 1u) == 0);
    assert(snapshot.live_count <= IWX_STA_AUTH_TRACE_LIVE_CAPACITY);
    assert(snapshot.dropped_count > 0);
    return 0;
}
"""

with tempfile.TemporaryDirectory(prefix="test091-sta-auth-trace-") as directory:
    root = pathlib.Path(directory)
    source = root / "trace.cpp"
    binary = root / "trace"
    source.write_text(HARNESS)
    subprocess.run(
        [
            "clang++", "-std=c++17", "-Wall", "-Wextra", "-Werror",
            "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
            "-pthread", "-I", str(ROOT), str(source), "-o", str(binary),
        ],
        check=True,
    )
    subprocess.run([str(binary)], check=True)

print("STA auth trace primitive host checks passed (ASan/UBSan)")
