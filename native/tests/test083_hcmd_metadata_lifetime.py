#!/usr/bin/env python3
"""Execute the production HCMD metadata slice with a freed post-doorbell header."""

from __future__ import annotations

import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "itlwm/hal_iwx/ItlIwx.cpp"


def extract_braced_block(text: str, opening: int) -> tuple[str, int]:
    depth = 0
    state = "code"
    escaped = False
    index = opening
    while index < len(text):
        char = text[index]
        nxt = text[index + 1] if index + 1 < len(text) else ""
        if state == "line_comment":
            if char == "\n":
                state = "code"
        elif state == "block_comment":
            if char == "*" and nxt == "/":
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
            if char == "/" and nxt == "/":
                state = "line_comment"
                index += 1
            elif char == "/" and nxt == "*":
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
                    return text[opening:index + 1], index + 1
        index += 1
    raise AssertionError("unterminated C++ function")


def production_submission_slice() -> tuple[str, str]:
    source = SOURCE.read_text(encoding="utf-8")
    signature = re.search(r"int ItlIwx::\s*iwx_send_cmd\s*\(", source)
    if not signature:
        raise AssertionError("iwx_send_cmd definition missing")
    opening = source.find("{", signature.end())
    function, _ = extract_braced_block(source, opening)

    entry_marker = "IwxFirmwareDiagnostics::Entry diagnosticEntry{};"
    entry_start = function.find(entry_marker)
    if entry_start < 0:
        raise AssertionError("production command-submission Entry missing")
    doorbell_marker = "IWX_WRITE(sc, IWX_HBUS_TARG_WRPTR"
    doorbell = function.find(doorbell_marker, entry_start)
    if doorbell < 0:
        raise AssertionError("production command doorbell missing")
    record_marker = "tahoeRecordFirmwareMetadata(sc, diagnosticEntry);"
    record = function.find(record_marker, doorbell)
    if record < 0:
        raise AssertionError("production post-doorbell metadata record missing")

    # Keep the production C++ from Entry construction through ring submission
    # and the actual record call. The test's fake IWX_WRITE invalidates cmd at
    # the exact WRPTR boundary; any later cmd dereference faults under ASan.
    return function[entry_start:record + len(record_marker)], function[doorbell:record]


HARNESS_TEMPLATE = r'''#include <cassert>
#include <cstdint>
#include <cstring>
#include "native/iwx_fw_diagnostics.hpp"

using IwxFirmwareDiagnostics::Entry;
struct iwx_softc {};
struct iwx_host_cmd { uint32_t flags = 0; };
struct iwx_wide_header {
    uint32_t cmd, group_id, qid, idx, length, reserved, version;
};
struct iwx_device_cmd { iwx_wide_header hdr_wide; };
struct command_ring { uint32_t queued = 0, cur = 2, qid = 4; };

static iwx_device_cmd *cmd = nullptr;
static iwx_host_cmd *hcmd = nullptr;
static iwx_softc *sc = nullptr;
static command_ring *ring = nullptr;
static bool async = true;
static uint32_t hdrlen = 32, paylen = 200, group_id = 13;
static uint32_t captured_count = 0;
static Entry captured{};
static bool doorbell_seen = false;
static bool command_invalidated = false;

constexpr uint32_t IWX_CMD_WANT_RESP = 1U;
constexpr uint32_t IWX_HBUS_TARG_WRPTR = 0x100U;
static uint32_t getTxQueueSize() { return 64U; }
static void fakeWrite(iwx_softc *, uint32_t reg, uint32_t value) {
    assert(reg == IWX_HBUS_TARG_WRPTR);
    assert(cmd != nullptr);
    assert(value == ((ring->qid << 16) | ring->cur));
    std::memset(cmd, 0xa5, sizeof(*cmd));
    cmd = nullptr;
    command_invalidated = true;
    doorbell_seen = true;
}
#define IWX_WRITE(sc_, reg_, value_) fakeWrite((sc_), (reg_), (value_))
#define DPRINTF(args_) ((void)0)
static void tahoeRecordFirmwareMetadata(iwx_softc *, Entry value) {
    assert(doorbell_seen);
    assert(command_invalidated);
    assert(cmd == nullptr);
    captured = value;
    ++captured_count;
}

int main() {
    iwx_softc softc{};
    iwx_host_cmd hostCommand{};
    command_ring txRing{};
    iwx_device_cmd commandBuffer{};
    commandBuffer.hdr_wide.cmd = 0x5a;
    commandBuffer.hdr_wide.group_id = 13;
    commandBuffer.hdr_wide.qid = 4;
    commandBuffer.hdr_wide.idx = 7;
    commandBuffer.hdr_wide.version = 3;
    hostCommand.flags = IWX_CMD_WANT_RESP;
    sc = &softc;
    hcmd = &hostCommand;
    ring = &txRing;
    cmd = &commandBuffer;
    (void)group_id;

    @@PRODUCTION_SLICE@@

    assert(captured_count == 1U);
    assert(captured.phase == static_cast<uint32_t>(
        IwxFirmwareDiagnostics::Phase::CommandSubmitted));
    assert(captured.source == static_cast<uint32_t>(
        IwxFirmwareDiagnostics::Source::HostCommand));
    assert(captured.command_id == 0x5aU);
    assert(captured.group_id == 13U);
    assert(captured.version == 3U);
    assert(captured.qid == 4U && captured.index == 7U);
    assert(captured.header_sequence == ((4U << 8) | 7U));
    assert(captured.packet_length == 232U && captured.payload_length == 200U);
    assert((captured.flags & IwxFirmwareDiagnostics::kWantResponse) != 0U);
    assert(command_invalidated && cmd == nullptr);
    assert(ring->queued == 1U && ring->cur == 3U);
    return 0;
}
'''


class HcmdMetadataLifetimeTests(unittest.TestCase):
    def test_real_submission_metadata_survives_dynamic_buffer_release(self) -> None:
        production_slice, doorbell_to_record = production_submission_slice()
        doorbell_in_slice = production_slice.find("IWX_WRITE(sc, IWX_HBUS_TARG_WRPTR")
        self.assertGreaterEqual(doorbell_in_slice, 0)
        self.assertLess(
            doorbell_in_slice,
            production_slice.find("tahoeRecordFirmwareMetadata(sc, diagnosticEntry);"),
        )
        self.assertNotIn("cmd->", doorbell_to_record)

        compile_slice = re.sub(
            r"(?m)^\s*#(?:ifdef|endif)\b[^\n]*\n", "", production_slice
        )
        source = HARNESS_TEMPLATE.replace("@@PRODUCTION_SLICE@@", compile_slice)
        compiler = shutil.which("clang++") or shutil.which("g++")
        if not compiler:
            self.skipTest("C++ compiler unavailable")
        with tempfile.TemporaryDirectory(prefix="test083-hcmd-lifetime-") as tmp:
            tmp_path = Path(tmp)
            cpp = tmp_path / "hcmd_lifetime.cpp"
            binary = tmp_path / "hcmd_lifetime"
            cpp.write_text(source, encoding="utf-8")
            build = subprocess.run(
                [compiler, "-std=c++17", "-O1", "-g", "-Wall", "-Wextra",
                 "-Werror", "-fsanitize=address,undefined",
                 "-fno-omit-frame-pointer", "-I", str(ROOT), str(cpp),
                 "-o", str(binary)],
                text=True, capture_output=True,
            )
            self.assertEqual(build.returncode, 0, build.stdout + build.stderr)
            env = dict(os.environ)
            env.setdefault("ASAN_OPTIONS", "detect_leaks=0")
            result = subprocess.run(
                [str(binary)], text=True, capture_output=True, env=env
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
