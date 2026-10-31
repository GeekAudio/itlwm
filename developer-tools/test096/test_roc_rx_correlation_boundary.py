#!/usr/bin/env python3
"""Execute the production ROC boundary block with host-only event shims.

The test extracts tahoeRxRocCorrelationSync and the exact diagnostic ROC
boundary block from tahoeP2pTapSessionEvent. It drives the real
IntelROCEvent::SessionTracker implementation, but does not instantiate the
whole IOKit tap method, workloop, or firmware transport.
"""

from pathlib import Path
import os
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[2]
TAP_PATH = ROOT / "itlwm/hal_iwx/ItlIwxP2PProbe.cpp"
SYNC_PATH = ROOT / "itlwm/hal_iwx/ItlIwx.cpp"
TRACKER_CPP = ROOT / "native/intel_roc_event_state.cpp"


def extract_function(source: str, signature: str) -> str:
    start = source.index(signature)
    opening = source.index("{", start)
    depth = 0
    state = "code"
    escaped = False
    index = opening
    while index < len(source):
        char = source[index]
        next_char = source[index + 1] if index + 1 < len(source) else ""
        if state == "line-comment":
            if char == "\n":
                state = "code"
        elif state == "block-comment":
            if char == "*" and next_char == "/":
                state = "code"
                index += 1
        elif state in ("string", "char"):
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif (state == "string" and char == '"') or (
                    state == "char" and char == "'"):
                state = "code"
        else:
            if char == "/" and next_char == "/":
                state = "line-comment"
                index += 1
            elif char == "/" and next_char == "*":
                state = "block-comment"
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
                    return source[start:index + 1]
        index += 1
    raise AssertionError(f"unterminated production function: {signature}")


def extract_preprocessor_block(function: str, marker: str) -> str:
    marker_at = function.index(marker)
    begin = function.rfind("#if", 0, marker_at)
    if begin < 0:
        raise AssertionError("production ROC block has no feature guard")
    line_start = function.rfind("\n", 0, begin) + 1
    lines = function[line_start:].splitlines(keepends=True)
    depth = 0
    consumed = []
    for line in lines:
        directive = line.lstrip()
        if directive.startswith("#if"):
            depth += 1
        elif directive.startswith("#endif"):
            depth -= 1
        consumed.append(line)
        if depth == 0:
            return "".join(consumed)
    raise AssertionError("unterminated production ROC feature guard")


PREAMBLE = r"""
#include <assert.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include "native/intel_roc_event_state.hpp"
#include "native/iwx_roc_rx_correlation.hpp"
#include "native/iwx_completion_observer.hpp"

#define IWX_SESSION_PROTECT_CONF_P2P_DEVICE_DISCOV 2
namespace NativeRxPreOwner { static const uint32_t kCaptureSerial = 1; }
namespace NativeAwdlRxTrace {
struct Epochs {
    uint32_t contextGeneration;
    uint32_t powerGeneration;
    uint32_t stationGeneration;
    uint32_t rocGeneration;
};
}

struct FakeWorkLoop { bool inGate() const { return true; } };
struct FakeLease {
    bool active = true;
    uint32_t contextGeneration = 6;
    uint32_t currentContextGeneration = 6;
    uint32_t powerGeneration = 11;
    uint32_t stationGeneration = 23;
};
struct FakeSoftc {
    uint32_t sc_device_family = NativeIwxCompletionObserver::kObservedFamily;
    uint32_t sc_generation = 11;
    uint32_t sc_tx_rate_generation = 23;
};
struct FakePreOwner {
    bool active = true;
    bool enabled() const { return active; }
};
struct FakeRocTracker {
    IntelROCEvent::SessionTracker tracker;
    IntelROCEvent::SessionSnapshot snapshot() const { return tracker.snapshot(); }
};

class ItlIwx {
public:
    bool tahoeP2pOnMainGate() const { return gate.inGate(); }
    FakeWorkLoop *getMainWorkLoop() { return &gate; }
    void tahoeRxRocCorrelationSync(uint64_t nowUs);
    void applyProductionRocBoundary(uint64_t hostUs,
        const NativeAwdlRxTrace::Epochs &epochs, bool reducerReturnedTrue,
        const IntelROCEvent::SessionSnapshot &after,
        bool canonicalStart, bool canonicalEnd);

    bool beginSession()
    {
        return nativeP2pRocEvents_.tracker.begin(
                   nativeP2pRocGeneration_, 1, 2) &&
            nativeP2pRocEvents_.tracker.noteCommandResult(
                nativeP2pRocGeneration_, 0);
    }

    void armAt(uint64_t armUs, uint32_t stopSerial = 4)
    {
        nativeRxRocArmUs_ = armUs;
        nativeRxRocArmGeneration_ = com.sc_generation;
        nativeRxRocArmStopSerial_ = stopSerial;
        nativeRxRocArmReady_ = 1;
        nativeRxPreOwnerStopSerial_ = stopSerial;
        tahoeRxRocCorrelationSync(armUs);
        assert(nativeRxRocCorrelation_.state() ==
               NativeIwxRocRxCorrelation::State::kArmed);
    }

    bool notify(uint32_t status, uint32_t start, uint32_t configuration,
                uint64_t timeUs, uint32_t macId = 1)
    {
        uint8_t raw[16] = {};
        put32(raw, 0, macId);
        put32(raw, 4, status);
        put32(raw, 8, start);
        put32(raw, 12, configuration);
        return noteRaw(raw, sizeof(raw), timeUs);
    }

    bool notifyMalformed(uint64_t timeUs)
    {
        uint8_t raw[15] = {};
        return noteRaw(raw, sizeof(raw), timeUs);
    }

    static void put32(uint8_t *raw, size_t offset, uint32_t value)
    {
        for (unsigned i = 0; i < 4; ++i)
            raw[offset + i] = static_cast<uint8_t>(value >> (i * 8));
    }

    bool noteRaw(const uint8_t *raw, size_t length, uint64_t timeUs)
    {
        const auto before = nativeP2pRocEvents_.snapshot();
        const bool returnedTrue = nativeP2pRocEvents_.tracker.noteNotification(
            nativeP2pRocGeneration_, raw, length, timeUs);
        const auto after = nativeP2pRocEvents_.snapshot();
        const bool canonicalStart = !before.startSeen && after.startSeen;
        const bool canonicalEnd = !before.endSeen && after.endSeen;
        const NativeAwdlRxTrace::Epochs epochs {
            tahoe_p2p_rx_lease_.contextGeneration,
            tahoe_p2p_rx_lease_.powerGeneration,
            tahoe_p2p_rx_lease_.stationGeneration,
            nativeP2pRocGeneration_
        };
        applyProductionRocBoundary(timeUs, epochs, returnedTrue,
            after, canonicalStart, canonicalEnd);
        return returnedTrue;
    }

    FakeWorkLoop gate;
    FakeLease tahoe_p2p_rx_lease_;
    FakeSoftc com;
    FakePreOwner nativeRxPreOwner_;
    FakeRocTracker nativeP2pRocEvents_;
    uint32_t nativeP2pRocGeneration_ = 6;
    uint32_t nativeP2pRocDurationMs_ = 100;
    uint64_t nativeRxPreOwnerStopSerial_ = 4;
    uint32_t nativeRxPreOwnerStopDepth_ = 0;
    NativeIwxRocRxCorrelation::Recorder nativeRxRocCorrelation_;
    NativeIwxRocRxCorrelation::RocEpoch nativeRxRocEpoch_;
    uint64_t nativeRxRocDeadlineUs_ = 0;
    uint64_t nativeRxRocArmUs_ = 0;
    uint64_t nativeRxRocArmStopSerial_ = 0;
    uint32_t nativeRxRocArmGeneration_ = 0;
    uint32_t nativeRxRocArmReady_ = 0;
};
"""


def main() -> int:
    tap = TAP_PATH.read_text(encoding="utf-8")
    sync_source = SYNC_PATH.read_text(encoding="utf-8")
    actual_tap = extract_function(
        tap, "void ItlIwx::tahoeP2pTapSessionEvent(")
    actual_sync = extract_function(
        sync_source, "void ItlIwx::tahoeRxRocCorrelationSync(")
    boundary = extract_preprocessor_block(
        actual_tap,
        "// Observe actual reducer boundaries independently of per-MPDU owner,",
    )
    trace_owner_at = actual_tap.index("const auto traceOwner =")
    assert actual_tap.index(boundary.strip().splitlines()[1].strip()) < trace_owner_at
    assert "traceOwner" not in boundary
    assert "beginRoc(correlationEpoch" in boundary
    assert "endRoc(correlationEpoch" in boundary

    cpp = PREAMBLE + "\n" + actual_sync + "\n" + r"""
void ItlIwx::applyProductionRocBoundary(uint64_t hostUs,
    const NativeAwdlRxTrace::Epochs &epochs, bool reducerReturnedTrue,
    const IntelROCEvent::SessionSnapshot &after,
    bool canonicalStart, bool canonicalEnd)
{
    const uint32_t generation = nativeP2pRocGeneration_;
    const bool traceOwnerMatches = false;
    assert(!traceOwnerMatches);
""" + boundary + "\n}\n" + r"""
using NativeIwxCompletionObserver::CopyResult;
using NativeIwxCompletionObserver::CopyStatus;
using namespace NativeIwxRocRxCorrelation;

static Token beginKnownSlot(ItlIwx &owner, uint32_t slotIndex, uint64_t timeUs)
{
    SlotInput input;
    input.captureSerial = 1;
    input.driverGeneration = owner.com.sc_generation;
    input.ring = 0;
    input.slot = slotIndex;
    input.head = (slotIndex + 1) % 512;
    input.copyTimeUs = timeUs;
    input.copySequence = slotIndex + 1;
    input.epoch = owner.nativeRxRocEpoch_;
    CopyResult copied;
    copied.status = CopyStatus::kCopied;
    copied.snapshot.incarnation = 1;
    copied.snapshot.bytes[4] = static_cast<uint8_t>(slotIndex);
    return owner.nativeRxRocCorrelation_.beginSlot(input, copied);
}

static void testTraceMismatchDoesNotGateSuccessfulBoundaries()
{
    ItlIwx owner;
    assert(owner.beginSession());
    owner.armAt(100);
    // The extracted production block is placed before traceOwner sampling in
    // the real tap method; the false trace-owner setting is not an input here.
    assert(owner.notify(1, 1, 2, 120));
    assert(owner.nativeRxRocCorrelation_.state() == State::kActive);
    Token token = beginKnownSlot(owner, 188, 130);
    assert(token.valid);
    assert(owner.notify(1, 0, 2, 140));
    assert(owner.nativeRxRocCorrelation_.state() == State::kClosed);
    assert(owner.nativeRxRocCorrelation_.closeReason() == CloseReason::kEnd);
    assert(owner.nativeRxRocCorrelation_.finishSlot(token));
    assert(owner.nativeRxRocCorrelation_.coverageComplete());
}

static void testFailedStartAndEndCannotComplete()
{
    {
        ItlIwx owner;
        assert(owner.beginSession());
        owner.armAt(100);
        assert(owner.notify(0, 1, 2, 120));
        assert(owner.nativeRxRocCorrelation_.state() == State::kClosed);
        assert(owner.nativeRxRocCorrelation_.closeReason() == CloseReason::kInvalidBoundary);
        assert(!owner.nativeRxRocCorrelation_.coverageComplete());
    }
    {
        ItlIwx owner;
        assert(owner.beginSession());
        owner.armAt(100);
        assert(owner.notify(1, 1, 2, 120));
        Token token = beginKnownSlot(owner, 12, 130);
        assert(token.valid);
        assert(owner.notify(0, 0, 2, 140));
        assert(owner.nativeRxRocCorrelation_.state() == State::kClosed);
        assert(owner.nativeRxRocCorrelation_.closeReason() == CloseReason::kInvalidBoundary);
        assert(owner.nativeRxRocCorrelation_.finishSlot(token));
        assert(!owner.nativeRxRocCorrelation_.coverageComplete());
    }
}

static void testEndBeforeStartMalformedAndForeignDoNotComplete()
{
    {
        ItlIwx owner;
        assert(owner.beginSession());
        owner.armAt(100);
        assert(owner.notify(1, 0, 2, 120)); // END first
        assert(owner.nativeRxRocCorrelation_.state() == State::kClosed);
        assert(!owner.nativeRxRocCorrelation_.coverageComplete());
        assert(owner.notify(1, 1, 2, 130)); // Must not retroactively open.
        assert(owner.nativeRxRocCorrelation_.state() == State::kClosed);
    }
    {
        ItlIwx owner;
        assert(owner.beginSession());
        owner.armAt(100);
        assert(owner.notify(1, 1, 2, 120));
        assert(!owner.notifyMalformed(130));
        assert(owner.nativeRxRocCorrelation_.state() == State::kClosed);
        assert(owner.nativeRxRocCorrelation_.closeReason() == CloseReason::kInvalidBoundary);
        assert(!owner.nativeRxRocCorrelation_.coverageComplete());
        assert(owner.notify(1, 0, 2, 140)); // Cannot revive after malformed close.
        assert(owner.nativeRxRocCorrelation_.state() == State::kClosed);
    }
    {
        ItlIwx owner;
        assert(owner.beginSession());
        owner.armAt(100);
        assert(!owner.notify(1, 1, 2, 120, 7)); // foreign MAC id
        assert(owner.nativeRxRocCorrelation_.state() == State::kArmed);
        owner.nativeRxPreOwner_.active = false;
        owner.tahoeRxRocCorrelationSync(130);
        assert(owner.nativeRxRocCorrelation_.state() == State::kClosed);
        assert(owner.nativeRxRocCorrelation_.closeReason() == CloseReason::kNoStart);
        owner.nativeRxPreOwner_.active = true;
        assert(owner.notify(1, 1, 2, 140));
        assert(owner.nativeRxRocCorrelation_.closeReason() == CloseReason::kNoStart);
        assert(!owner.nativeRxRocCorrelation_.coverageComplete());
    }
}

static void testBadDurationOverflowEpochAndStaleStopCannotRevive()
{
    {
        ItlIwx owner;
        assert(owner.beginSession());
        owner.nativeP2pRocDurationMs_ = 0;
        owner.armAt(100);
        assert(owner.notify(1, 1, 2, 120));
        assert(owner.nativeRxRocCorrelation_.state() == State::kClosed);
        assert(owner.nativeRxRocCorrelation_.closeReason() == CloseReason::kInvalidBoundary);
        assert(owner.notify(1, 0, 2, 130));
        assert(owner.nativeRxRocCorrelation_.state() == State::kClosed);
    }
    {
        ItlIwx owner;
        assert(owner.beginSession());
        owner.nativeP2pRocDurationMs_ = 1;
        owner.armAt(100);
        assert(owner.notify(1, 1, 2, UINT64_MAX - 999));
        assert(owner.nativeRxRocCorrelation_.state() == State::kClosed);
        assert(owner.nativeRxRocCorrelation_.closeReason() == CloseReason::kInvalidBoundary);
        assert(owner.notify(1, 0, 2, UINT64_MAX - 900));
        assert(owner.nativeRxRocCorrelation_.state() == State::kClosed);
    }
    {
        ItlIwx owner;
        assert(owner.beginSession());
        owner.armAt(100);
        assert(owner.notify(1, 1, 2, 120));
        owner.tahoe_p2p_rx_lease_.powerGeneration++;
        owner.tahoeRxRocCorrelationSync(130);
        assert(owner.nativeRxRocCorrelation_.closeReason() == CloseReason::kGenerationChanged);
        assert(!owner.nativeRxRocCorrelation_.coverageComplete());
        assert(owner.notify(1, 0, 2, 140));
        assert(owner.nativeRxRocCorrelation_.state() == State::kClosed);
    }
    {
        ItlIwx owner;
        assert(owner.beginSession());
        owner.armAt(100, 4);
        owner.nativeRxPreOwnerStopSerial_ = 5; // Stale stop fence.
        owner.tahoeRxRocCorrelationSync(110);
        assert(owner.nativeRxRocCorrelation_.closeReason() == CloseReason::kStop);
        owner.nativeRxPreOwnerStopSerial_ = 4;
        assert(owner.notify(1, 1, 2, 120));
        assert(owner.nativeRxRocCorrelation_.state() == State::kClosed);
        assert(owner.nativeRxRocCorrelation_.closeReason() == CloseReason::kStop);
    }
}

int main()
{
    static_assert(kWireBytes < 16 * 1024, "bounded diagnostic publication");
    testTraceMismatchDoesNotGateSuccessfulBoundaries();
    testFailedStartAndEndCannotComplete();
    testEndBeforeStartMalformedAndForeignDoNotComplete();
    testBadDurationOverflowEpochAndStaleStopCannotRevive();
    puts("PASS extracted production ROC start/end and sync boundaries; SessionTracker exercised");
}
"""

    with tempfile.TemporaryDirectory(prefix="iwx-roc-boundary-") as tmp:
        source = Path(tmp) / "test_roc_boundary.cpp"
        binary = Path(tmp) / "test_roc_boundary"
        source.write_text(cpp, encoding="utf-8")
        subprocess.run([
            os.environ.get("CXX", "clang++"), "-std=c++14",
            "-Wall", "-Wextra", "-Werror", "-pedantic",
            "-DITL_NATIVE_RX_PREOWNER_OBSERVATION_25G332=1",
            "-fsanitize=address,undefined", "-fno-sanitize-recover=all",
            "-fno-omit-frame-pointer", "-I", str(ROOT), str(source),
            str(TRACKER_CPP), "-o", str(binary),
        ], check=True)
        subprocess.run([str(binary)], check=True, env={
            **os.environ,
            "ASAN_OPTIONS": "halt_on_error=1",
            "UBSAN_OPTIONS": "halt_on_error=1:print_stacktrace=1",
        })
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
