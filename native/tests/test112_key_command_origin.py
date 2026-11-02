from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]


HARNESS = r"""
#include <cassert>
#include <cstdint>
#include <cstring>
#include "native/iwx_sta_auth_trace.h"

static uint64_t serialFromEvent(const IwxStaAuthTraceEvent &event)
{
    uint32_t high = 0;
    std::memcpy(&high, &event.result, sizeof(high));
    return (static_cast<uint64_t>(high) << 32) | event.detail;
}

int main()
{
    static_assert(IWX_STA_AUTH_TRACE_SCHEMA == 1,
                  "the key origin event must preserve schema 1");
    static_assert(sizeof(IwxStaAuthTraceEvent) == 48,
                  "the key origin event must preserve the record ABI");
    static_assert(sizeof(IwxStaAuthTraceSnapshot) == 1208,
                  "the key origin event must preserve the snapshot ABI");

    IwxStaAuthTrace trace{};
    iwx_sta_auth_trace_init(&trace, 9);
    const uint32_t association = iwx_sta_auth_trace_begin_run(&trace);
    assert(association != 0);

    const uint64_t serial = 0xfedcba9876543210ULL;
    assert(iwx_sta_auth_trace_record_key_command_origin(
        &trace, 0x112233445566ULL, 17, 4, IWX_STA_COMPONENT_GTK,
        IWX_STA_SOURCE_HAL_COMMAND, IWX_STA_SUBMIT_LOCAL_ENQUEUE, serial));

    IwxStaAuthTraceSnapshot snapshot{};
    assert(iwx_sta_auth_trace_snapshot(&trace, &snapshot));
    assert(snapshot.schema == 1 && snapshot.record_bytes == 48);
    assert(snapshot.live_count == 1);
    const IwxStaAuthTraceEvent &event = snapshot.live[0];
    assert(event.kind == IWX_STA_TRACE_KEY_COMMAND_ORIGIN);
    assert(event.stage == IWX_STA_STAGE_KEY_COMMAND_ORIGIN);
    assert(event.driver_generation == 17);
    assert(event.association_id == association);
    assert(event.attempt_id == 4);
    assert(event.component == IWX_STA_COMPONENT_GTK);
    assert(event.source == IWX_STA_SOURCE_HAL_COMMAND);
    assert(event.flags == IWX_STA_FLAG_COMMAND_SUBMIT_SERIAL_PRESENT);
    assert(serialFromEvent(event) == serial);

    /* A non-enqueued result never advertises a serial, even if a caller
     * accidentally passes a stale serial value. */
    assert(iwx_sta_auth_trace_record_key_command_origin(
        &trace, 0x112233445566ULL, 17, 5, IWX_STA_COMPONENT_GTK,
        IWX_STA_SOURCE_HAL_COMMAND, IWX_STA_SUBMIT_OTHER_ERROR, serial));
    assert(iwx_sta_auth_trace_snapshot(&trace, &snapshot));
    assert(snapshot.live_count == 2);
    const IwxStaAuthTraceEvent &missing = snapshot.live[1];
    assert(missing.attempt_id == 5);
    assert(missing.flags == 0);
    assert(missing.result == 0 && missing.detail == 0);

    /* A locally enqueued command with a missing serial is explicitly
     * represented without turning zero into a valid origin. */
    assert(iwx_sta_auth_trace_record_key_command_origin(
        &trace, 0x112233445566ULL, 17, 6, IWX_STA_COMPONENT_GTK,
        IWX_STA_SOURCE_HAL_COMMAND, IWX_STA_SUBMIT_LOCAL_ENQUEUE, 0));
    assert(iwx_sta_auth_trace_snapshot(&trace, &snapshot));
    assert(snapshot.live_count == 3);
    const IwxStaAuthTraceEvent &zero = snapshot.live[2];
    assert(zero.attempt_id == 6);
    assert(zero.flags == 0);
    assert(zero.result == 0 && zero.detail == 0);

    /* A non-HAL source cannot claim a firmware submission serial. */
    assert(iwx_sta_auth_trace_record_key_command_origin(
        &trace, 0x112233445566ULL, 17, 7, IWX_STA_COMPONENT_GTK,
        IWX_STA_SOURCE_SOFTWARE_CRYPTO, IWX_STA_SUBMIT_LOCAL_ENQUEUE, serial));
    assert(iwx_sta_auth_trace_snapshot(&trace, &snapshot));
    assert(snapshot.live_count == 4);
    const IwxStaAuthTraceEvent &software = snapshot.live[3];
    assert(software.attempt_id == 7);
    assert(software.flags == 0);
    assert(software.result == 0 && software.detail == 0);
    return 0;
}
"""

C_HARNESS = r"""
#include <assert.h>
#include <stdint.h>
#include <string.h>
#include "native/iwx_sta_auth_trace.h"

int main(void)
{
    _Static_assert(IWX_STA_AUTH_TRACE_SCHEMA == 1,
                   "the key origin event must preserve schema 1");
    _Static_assert(sizeof(struct IwxStaAuthTraceEvent) == 48,
                   "the key origin event must preserve the record ABI");
    struct IwxStaAuthTrace trace = {0};
    iwx_sta_auth_trace_init(&trace, 4);
    uint32_t association = iwx_sta_auth_trace_begin_run(&trace);
    assert(association != 0);
    uint64_t serial = UINT64_C(0xfedcba9876543210);
    assert(iwx_sta_auth_trace_record_key_command_origin(
        &trace, 55, 8, 2, IWX_STA_COMPONENT_GTK,
        IWX_STA_SOURCE_HAL_COMMAND, IWX_STA_SUBMIT_LOCAL_ENQUEUE, serial));
    struct IwxStaAuthTraceSnapshot snapshot = {0};
    assert(iwx_sta_auth_trace_snapshot(&trace, &snapshot));
    assert(snapshot.live_count == 1);
    const struct IwxStaAuthTraceEvent *event = &snapshot.live[0];
    uint32_t high = 0;
    memcpy(&high, &event->result, sizeof(high));
    assert(event->kind == IWX_STA_TRACE_KEY_COMMAND_ORIGIN);
    assert(event->stage == IWX_STA_STAGE_KEY_COMMAND_ORIGIN);
    assert(event->association_id == association);
    assert(event->attempt_id == 2);
    assert(event->flags == IWX_STA_FLAG_COMMAND_SUBMIT_SERIAL_PRESENT);
    assert((((uint64_t)high << 32) | event->detail) == serial);
    return 0;
}
"""


class Test112KeyCommandOrigin(unittest.TestCase):
    def test_value_free_submit_serial_bridge(self):
        compiler = os.environ.get("CXX") or shutil.which("clang++") or shutil.which("c++")
        if not compiler:
            self.skipTest("no C++ compiler available")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "key_origin_test.cpp"
            binary = root / "key_origin_test"
            source.write_text(HARNESS)
            subprocess.run(
                [compiler, "-std=c++17", "-Wall", "-Wextra", "-Werror",
                 "-I", str(ROOT), str(source), "-o", str(binary)],
                check=True, capture_output=True, text=True)
            subprocess.run([str(binary)], check=True, capture_output=True, text=True)

    def test_c_header_profile_compiles_and_roundtrips_serial(self):
        compiler = os.environ.get("CC") or shutil.which("clang") or shutil.which("cc")
        if not compiler:
            self.skipTest("no C compiler available")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "key_origin_test.c"
            binary = root / "key_origin_test"
            source.write_text(C_HARNESS)
            subprocess.run(
                [compiler, "-std=c11", "-Wall", "-Wextra", "-Werror",
                 "-I", str(ROOT), str(source), "-o", str(binary)],
                check=True, capture_output=True, text=True)
            subprocess.run([str(binary)], check=True, capture_output=True, text=True)

    def test_driver_copies_this_command_serial_to_receipt(self):
        source = (ROOT / "itlwm/hal_iwx/ItlIwx.cpp").read_text()
        self.assertIn(
            "receipt->command_submit_serial = commandSubmitSerial", source)
        self.assertIn(
            "diagnosticEntry.command_id == IWX_ADD_STA_KEY", source)
        self.assertIn(
            "diagnosticEntry.group_id == IWX_LONG_GROUP", source)

    def test_group1_records_origin_without_replacing_submit_record(self):
        source = (ROOT / "itl80211/openbsd/net80211/ieee80211_pae_input.c").read_text()
        self.assertIn("IWX_STA_TRACE_KEY_SUBMIT", source)
        self.assertIn("iwx_sta_auth_trace_record_key_command_origin(", source)
        self.assertIn("receipt.command_submit_serial", source)
        self.assertIn("component == IWX_STA_COMPONENT_GTK", source)


if __name__ == "__main__":
    unittest.main()
