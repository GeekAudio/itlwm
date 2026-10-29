#!/usr/bin/env python3
"""Test076 Probe telemetry serialization and fail-closed publication."""

from __future__ import annotations

from pathlib import Path
import shutil
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[2]
PROBE = ROOT / "itlwm/hal_iwx/ItlIwxP2PProbe.cpp"


def braced_source(source: str, marker: str) -> str:
    start = source.index(marker)
    opening = source.index("{", start)
    depth = 0
    for end in range(opening, len(source)):
        if source[end] == "{":
            depth += 1
        elif source[end] == "}":
            depth -= 1
            if depth == 0:
                return source[start : end + 1]
    raise AssertionError(f"unterminated block: {marker}")


def check_schema(source: str) -> None:
    plan_publisher = braced_source(
        source, "static bool publishDiscoveryCurrentAwPlan("
    )
    trace_publisher = braced_source(
        source, "static void publishDiscoveryCurrentAwTrace("
    )
    describe = braced_source(
        source, "static CurrentAwPublishedPlan describeDiscoveryCurrentAwPlan("
    )

    for key in (
        "OffsetMagnitudeUs",
        "RelationValid",
        "ForwardDeltaValid",
        "BeforeRxUs",
        "RecordedStatus",
        "RecordedRejectReason",
        "LegacyStatus26",
        "ReconstructedGeometryEquivalent",
        "ReconstructedReasonEquivalent",
    ):
        assert f'setChecked("{key}"' in plan_publisher
    assert 'setChecked("SignedOffsetUs"' not in plan_publisher
    assert 'setChecked("OffsetMagnitudeUs", relationValid ? offsetMagnitudeUs : 0);' in plan_publisher
    assert "return controller->setProperty(key, value, 64);" in plan_publisher
    assert "if (writesOk)" in plan_publisher
    assert "writesOk = set(suffix, value);" in plan_publisher

    assert 'setChecked("Schema", 1);' in trace_publisher
    assert 'setChecked("Complete", 0);' in trace_publisher
    assert '!set("Complete", 1)' in trace_publisher
    assert 'set("SnapshotVersionBegin", writingVersion)' in trace_publisher
    assert '!set("SnapshotVersionEnd", evenVersion)' in trace_publisher
    assert '!set("SnapshotVersionBegin", evenVersion)' in trace_publisher
    assert "NativeAwdlMifCurrentAw::describe(record.input)" in describe
    assert "if (!quiet || !record.recorded)" in describe
    assert "describeDiscoveryCurrentAwPlan(trace.initial, true," in trace_publisher
    assert "describeDiscoveryCurrentAwPlan(trace.final, true," in trace_publisher
    assert "OSBoolean" not in plan_publisher + trace_publisher
    quiet_false = braced_source(trace_publisher, "if (!quiet)")
    assert "describeDiscoveryCurrentAwPlan" not in quiet_false
    assert 'set("Complete", 0)' in quiet_false
    assert 'set("Quiet", 0)' in quiet_false
    assert 'set("QuietBlockerMask", trace.quietBlockerMask)' in quiet_false
    assert "invalidateDiscoveryCurrentAwTrace(controller);" in quiet_false
    invalidator = braced_source(
        source, "static void invalidateDiscoveryCurrentAwTrace("
    )
    assert 'OSSymbol::existingSymbolForCString(key)' in invalidator
    assert 'controller->removeProperty(symbol)' in invalidator
    assert '"NativeP2PCurrentAwTraceComplete"' in invalidator
    assert '"NativeP2PCurrentAwTraceSnapshotVersionBegin"' in invalidator
    assert '"NativeP2PCurrentAwTraceSnapshotVersionEnd"' in invalidator
    assert '"NativeP2PCurrentAwTraceQuietBlockerMask"' in invalidator
    assert "controller->setProperty(" not in invalidator
    assert "withCString(" not in invalidator
    assert "trace.published = true;" in trace_publisher
    assert "if (!writesOk || !set(\"Complete\", 1)" in trace_publisher

    finish = braced_source(source, "IOReturn ItlIwx::tahoeP2pFinishAction(")
    reset_queue = finish.index("__atomic_store_n(&owner->nativeP2pProbeQueued_, 0u")
    publish_trace = finish.index("publishDiscoveryCurrentAwTrace(run, quiet);")
    assert reset_queue < publish_trace
    assert "uint32_t quietBlockerMask = 0;" in finish
    assert "run->currentAwTrace.quietBlockerMask = quietBlockerMask;" in finish
    assert "const bool quiet = quietBlockerMask == 0;" in finish
    for blocker in (
        "kCurrentAwQuietBlockerRxProducerOpen",
        "kCurrentAwQuietBlockerRxDrainIncomplete",
        "kCurrentAwQuietBlockerResourcesRetained",
        "kCurrentAwQuietBlockerProbeBusy",
        "kCurrentAwQuietBlockerNswqPaused",
        "kCurrentAwQuietBlockerProbeQueued",
        "kCurrentAwQuietBlockerOwnerPresent",
    ):
        assert blocker in finish


def check_offset_helper(source: str) -> None:
    helper = braced_source(
        source, "static uint64_t discoveryCurrentAwOffsetMagnitude("
    )
    compiler = shutil.which("clang++") or shutil.which("clang")
    if not compiler:
        raise RuntimeError("clang++ or clang is required for this pure helper test")
    harness = f"""
#include <assert.h>
#include <stdint.h>
#include <limits.h>
{helper}
int main() {{
    assert(discoveryCurrentAwOffsetMagnitude(0) == 0);
    assert(discoveryCurrentAwOffsetMagnitude(42) == 42);
    assert(discoveryCurrentAwOffsetMagnitude(-42) == 42);
    assert(discoveryCurrentAwOffsetMagnitude(INT32_MIN) == 2147483648ULL);
    return 0;
}}
"""
    with tempfile.TemporaryDirectory(prefix="test076-current-aw-schema-") as temp:
        binary = Path(temp) / "offset-magnitude-test"
        source_path = Path(temp) / "offset-magnitude-test.cpp"
        source_path.write_text(harness)
        subprocess.run(
            [compiler, "-std=c++14", "-Wall", "-Wextra", "-Werror",
             str(source_path), "-o", str(binary)],
            check=True,
        )
        subprocess.run([str(binary)], check=True)


def main() -> int:
    source = PROBE.read_text(encoding="utf-8")
    check_schema(source)
    check_offset_helper(source)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
