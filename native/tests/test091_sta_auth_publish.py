#!/usr/bin/env python3
"""Run the production Tahoe STA-auth publisher against small host stubs.

This extracts the actual C++ publisher and checks its cache key when mutable
snapshot-only status changes without a revision/drop-count change.
"""

from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "itlwm/hal_iwx/ItlIwx.cpp"


def extract_function(source: str, marker: str) -> str:
    start = source.find(marker)
    if start < 0:
        raise AssertionError(f"production function not found: {marker}")
    brace = source.find("{", start)
    if brace < 0:
        raise AssertionError(f"function body not found: {marker}")
    depth = 0
    index = brace
    state = "code"
    while index < len(source):
        char = source[index]
        next_char = source[index + 1] if index + 1 < len(source) else ""
        if state == "code":
            if char == "/" and next_char == "/":
                state = "line_comment"
                index += 2
                continue
            if char == "/" and next_char == "*":
                state = "block_comment"
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
        elif state == "line_comment":
            if char == "\n":
                state = "code"
        elif state == "block_comment":
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


HARNESS = r'''
#include <cassert>
#include <cstdint>
#include <cstring>
#include <cstdio>
#include "native/iwx_sta_auth_trace.h"

static uint16_t htole16(uint16_t value) { return value; }
static uint32_t htole32(uint32_t value) { return value; }

class OSData {
public:
    static OSData *withBytes(const void *bytes, unsigned int length)
    {
        auto *data = new OSData;
        data->bytes = new uint8_t[length];
        std::memcpy(data->bytes, bytes, length);
        data->length = length;
        return data;
    }
    void release() { delete[] bytes; delete this; }
    uint8_t *bytes = nullptr;
    unsigned int length = 0;
};

class IOEthernetController {
public:
    bool setProperty(const char *key, OSData *value)
    {
        assert(std::strcmp(key, "NativeGroupKeyForensicSnapshot") == 0);
        assert(value && value->length == sizeof(IwxStaAuthTraceSnapshot));
        ++writes;
        return true;
    }
    unsigned writes = 0;
};

struct ieee80211com { IwxStaAuthTrace ic_tahoe_auth_trace; };
struct iwx_softc { ieee80211com sc_ic; };

class ItlIwx {
public:
    bool tahoeP2pOnMainGate() const { return true; }
    bool tahoePublishStaAuthTrace(IOEthernetController *, struct iwx_softc *);
    uint32_t nativeStaAuthTracePublishedRevision_ {0};
    uint32_t nativeStaAuthTracePublishedDropped_ {0};
    uint32_t nativeStaAuthTracePublishedDiagnostic_ {0};
    uint32_t nativeStaAuthTracePublishedAssociation_ {0};
    uint32_t nativeStaAuthTracePublishedAttempt_ {0};
    uint32_t nativeStaAuthTracePublishedFirstState_ {0};
    uint32_t nativeStaAuthTracePublishedFirstCount_ {0};
    bool nativeStaAuthTracePublishedOnce_ {false};
};

@@EVENT_HELPER@@
@@PUBLISHER@@

int main()
{
    ItlIwx owner;
    IOEthernetController controller;
    iwx_softc sc{};
    iwx_sta_auth_trace_init(&sc.sc_ic.ic_tahoe_auth_trace, 9u);

    auto &trace = sc.sc_ic.ic_tahoe_auth_trace;
    assert(owner.tahoePublishStaAuthTrace(&controller, &sc));
    assert(controller.writes == 1u); // initial empty snapshot

    /* first_state is sampled outside revision; pending is publishable. */
    __atomic_store_n(&trace.first_state, 1u, __ATOMIC_RELEASE);
    assert(owner.tahoePublishStaAuthTrace(&controller, &sc));
    assert(controller.writes == 2u);

    /* Reproduce pending -> lost with no revision/drop-count movement. */
    const uint32_t revision = __atomic_load_n(&trace.revision, __ATOMIC_RELAXED);
    const uint32_t dropped = __atomic_load_n(&trace.dropped_count, __ATOMIC_RELAXED);
    __atomic_store_n(&trace.first_state, 3u, __ATOMIC_RELEASE);
    assert(__atomic_load_n(&trace.revision, __ATOMIC_RELAXED) == revision);
    assert(__atomic_load_n(&trace.dropped_count, __ATOMIC_RELAXED) == dropped);
    assert(owner.tahoePublishStaAuthTrace(&controller, &sc));
    assert(controller.writes == 3u);
    assert(owner.tahoePublishStaAuthTrace(&controller, &sc));
    assert(controller.writes == 3u); // unchanged snapshot deduplicates

    /* The publisher also compares attempt/association snapshot scalars. */
    __atomic_add_fetch(&trace.next_attempt_id, 1u, __ATOMIC_RELAXED);
    assert(owner.tahoePublishStaAuthTrace(&controller, &sc));
    assert(controller.writes == 4u);
    __atomic_store_n(&trace.association_id, 7u, __ATOMIC_RELEASE);
    assert(owner.tahoePublishStaAuthTrace(&controller, &sc));
    assert(controller.writes == 5u);
    std::puts("PASS: production STA-auth publisher republishes pending->lost, attempt, and association changes");
}
'''


def main() -> None:
    source = SOURCE.read_text(encoding="utf-8")
    event_helper = extract_function(
        source,
        "static void iwxStaAuthTraceEventToLE(IwxStaAuthTraceEvent *dst,",
    )
    publisher = extract_function(
        source, "bool ItlIwx::tahoePublishStaAuthTrace("
    )
    generated = HARNESS.replace("@@EVENT_HELPER@@", event_helper).replace(
        "@@PUBLISHER@@", publisher
    )

    with tempfile.TemporaryDirectory(prefix="iwx-sta-publish-") as temp:
        source_path = Path(temp) / "publisher_host.cpp"
        binary_path = Path(temp) / "publisher_host"
        source_path.write_text(generated, encoding="utf-8")
        subprocess.run(
            [
                "clang++",
                "-std=c++17",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-I",
                str(ROOT),
                str(source_path),
                "-o",
                str(binary_path),
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        result = subprocess.run(
            [str(binary_path)], check=True, capture_output=True, text=True
        )
        print(result.stdout, end="")


if __name__ == "__main__":
    main()
