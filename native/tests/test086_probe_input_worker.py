#!/usr/bin/env python3
"""Extract and exercise Test086's production native-RX worker drain."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "itlwm/hal_iwx/ItlIwxP2PProbe.cpp"
DRAIN_MARKER = "static void drainRx149NativeDataOutsideMainGate("


def extract_function(source: str, marker: str) -> str:
    start = source.index(marker)
    opening = source.index("{", start)
    depth = 0
    for end in range(opening, len(source)):
        if source[end] == "{":
            depth += 1
        elif source[end] == "}":
            depth -= 1
            if depth == 0:
                return source[start:end + 1]
    raise AssertionError(f"unterminated production function: {marker}")


def extract_block(source: str, marker: str) -> str:
    start = source.index(marker)
    opening = source.index("{", start)
    depth = 0
    for end in range(opening, len(source)):
        if source[end] == "{":
            depth += 1
        elif source[end] == "}":
            depth -= 1
            if depth == 0:
                return source[opening + 1:end]
    raise AssertionError(f"unterminated production block: {marker}")


def require_order(text: str, *needles: str) -> None:
    positions = [text.find(needle) for needle in needles]
    assert all(position >= 0 for position in positions), (needles, positions)
    assert positions == sorted(positions), (needles, positions)


def check_source_contract(source: str) -> dict[str, str]:
    drain = extract_function(source, DRAIN_MARKER)
    assert "if (!owner || owner->tahoeP2pOnMainGate())" in drain
    assert "NativeAwdlBSD::poll(radioReady, uint32_t(sc.sc_generation)," in drain
    assert "&event.rx149DataLease" in drain
    require_order(
        drain,
        "if (!owner || owner->tahoeP2pOnMainGate())",
        "const auto &sc = owner->com;",
        "NativeAwdlBSD::poll(",
    )

    read_state = extract_function(
        source, "static int readRocState(P2PProbeRun *probe, RocEventRun *event,")
    assert "event->operation = kRocRead;" in read_state
    assert "gate->runAction(ItlIwx::tahoeP2pRocEventAction, event)" in read_state

    event_action = extract_function(
        source, "IOReturn ItlIwx::tahoeP2pRocEventAction(")
    read_branch_marker = "} else if (action->operation == kRocRead) {"
    read_branch = extract_block(event_action, read_branch_marker)
    assert "action->rx149DataLease = {};" in read_branch
    assert "owner->tahoeP2pRx149DataLease(&action->rx149DataLease)" in read_branch
    require_order(
        read_branch,
        "action->rx149DataLease = {};",
        "owner->tahoeP2pRx149DataLease(&action->rx149DataLease)",
    )
    require_order(
        event_action,
        "if (action->operation == kRocArm)",
        "action->snapshot = tracker.snapshot();",
        "storeRocSnapshot(owner, action->snapshot);",
        "if (action->operation == kRocCloseRx149) {",
        read_branch_marker,
    )

    exercise = extract_function(source, "static int exerciseRx149Observation(")
    loop = extract_block(exercise, "for (unsigned i = 0; i < 80; ++i)")
    require_order(
        loop,
        "error = readRocState(probe, &event, true);",
        "drainRx149NativeDataOutsideMainGate(probe, event);",
        "if (error)",
        "if (event.snapshot.endSeen || event.snapshot.outcomeUnknown)",
    )
    final_drain = exercise[exercise.index("if (!error && !ended) {", exercise.index(loop) + len(loop)):]
    require_order(
        final_drain,
        "error = readRocState(probe, &event, true);",
        "drainRx149NativeDataOutsideMainGate(probe, event);",
        "ended = !error && event.snapshot.endSeen;",
    )
    assert exercise.count("drainRx149NativeDataOutsideMainGate(probe, event);") == 2

    return {
        "drain": drain,
        "read_state": read_state,
        "event_action": event_action,
        "exercise": exercise,
    }


CPP_SUPPORT = r"""
#include <cassert>
#include <cstdint>
#include <initializer_list>
#include "native/p2p_rx149_data_input.hpp"

#define IEEE80211_S_RUN 3
#define IWX_FLAG_HW_ERR (1U << 3)
#define IWX_FLAG_SHUTDOWN (1U << 4)
#define IWX_FLAG_RFKILL (1U << 5)

#if defined(TEST_FEATURE_ON)
#define ITL_NATIVE_AWDL_RX149_DATA_INPUT_25G332 1
#endif

struct iwx_softc {
    struct { int ic_state = 0; } sc_ic;
    uint32_t sc_flags = 0;
    uint64_t sc_generation = 0;
};

namespace NativeAwdlBSD {
struct PollCall {
    bool radioReady = false;
    uint32_t powerGeneration = 0;
    const NativeP2PRx149DataInput::Lease *lease = nullptr;
};
static unsigned pollCalls = 0;
static unsigned pollCallsWhileMainGate = 0;
static bool observedMainGate = false;
static PollCall lastCall{};

void resetTestState() {
    pollCalls = 0;
    pollCallsWhileMainGate = 0;
    observedMainGate = false;
    lastCall = PollCall{};
}

void poll(bool radioReady, uint32_t powerGeneration,
          const NativeP2PRx149DataInput::Lease *lease) {
    ++pollCalls;
    if (observedMainGate)
        ++pollCallsWhileMainGate;
    lastCall = PollCall{radioReady, powerGeneration, lease};
}
}

struct ItlIwx {
    iwx_softc com{};
    bool onMainGate = false;
    bool tahoeP2pOnMainGate() {
        NativeAwdlBSD::observedMainGate = onMainGate;
        return onMainGate;
    }
};

struct P2PProbeRun { ItlIwx *owner = nullptr; };
struct RocEventRun {
    NativeP2PRx149DataInput::Lease rx149DataLease{};
};
"""


CPP_ON = r"""
int main() {
    ItlIwx driver{};
    P2PProbeRun probe{&driver};
    RocEventRun event{};
    event.rx149DataLease.ownerSerial = 0x123456789abcdef0ULL;

    NativeAwdlBSD::resetTestState();
    drainRx149NativeDataOutsideMainGate(nullptr, event);
    assert(NativeAwdlBSD::pollCalls == 0);

    P2PProbeRun ownerless{};
    drainRx149NativeDataOutsideMainGate(&ownerless, event);
    assert(NativeAwdlBSD::pollCalls == 0);

    driver.onMainGate = true;
    drainRx149NativeDataOutsideMainGate(&probe, event);
    assert(NativeAwdlBSD::pollCalls == 0);
    assert(NativeAwdlBSD::pollCallsWhileMainGate == 0);

    driver.onMainGate = false;
    driver.com.sc_ic.ic_state = IEEE80211_S_RUN;
    driver.com.sc_flags = 0;
    driver.com.sc_generation = 0x00000001abcdef01ULL;
    drainRx149NativeDataOutsideMainGate(&probe, event);
    assert(NativeAwdlBSD::pollCalls == 1);
    assert(NativeAwdlBSD::lastCall.radioReady);
    assert(NativeAwdlBSD::lastCall.powerGeneration == 0xabcdef01U);
    assert(NativeAwdlBSD::lastCall.lease == &event.rx149DataLease);
    assert(NativeAwdlBSD::lastCall.lease->ownerSerial ==
           0x123456789abcdef0ULL);
    assert(NativeAwdlBSD::pollCallsWhileMainGate == 0);

    NativeAwdlBSD::resetTestState();
    driver.com.sc_ic.ic_state = 0;
    drainRx149NativeDataOutsideMainGate(&probe, event);
    assert(NativeAwdlBSD::pollCalls == 1);
    assert(!NativeAwdlBSD::lastCall.radioReady);

    for (uint32_t flag : {IWX_FLAG_HW_ERR, IWX_FLAG_SHUTDOWN, IWX_FLAG_RFKILL}) {
        NativeAwdlBSD::resetTestState();
        driver.com.sc_ic.ic_state = IEEE80211_S_RUN;
        driver.com.sc_flags = flag;
        drainRx149NativeDataOutsideMainGate(&probe, event);
        assert(NativeAwdlBSD::pollCalls == 1);
        assert(!NativeAwdlBSD::lastCall.radioReady);
        assert(NativeAwdlBSD::lastCall.powerGeneration == 0xabcdef01U);
        assert(NativeAwdlBSD::lastCall.lease == &event.rx149DataLease);
    }
    return 0;
}
"""


CPP_OFF = r"""
int main() {
    ItlIwx driver{};
    P2PProbeRun probe{&driver};
    RocEventRun event{};
    driver.com.sc_ic.ic_state = IEEE80211_S_RUN;
    driver.com.sc_generation = 77;
    drainRx149NativeDataOutsideMainGate(&probe, event);
    driver.onMainGate = true;
    drainRx149NativeDataOutsideMainGate(&probe, event);
    drainRx149NativeDataOutsideMainGate(nullptr, event);
    assert(NativeAwdlBSD::pollCalls == 0);
    assert(NativeAwdlBSD::pollCallsWhileMainGate == 0);
    return 0;
}
"""


def compiler_command() -> list[str]:
    configured = os.environ.get("CXX")
    if configured:
        return shlex.split(configured)
    xcrun = shutil.which("xcrun")
    return [xcrun, "clang++"] if xcrun else ["clang++"]


def compile_and_run(temp: Path, function: str, enabled: bool) -> str:
    name = "feature-on" if enabled else "feature-off"
    source_path = temp / f"test086_probe_input_worker_{name}.cpp"
    binary_path = temp / f"test086_probe_input_worker_{name}"
    source_path.write_text(
        CPP_SUPPORT + "\n" + function + "\n" + (CPP_ON if enabled else CPP_OFF),
        encoding="utf-8",
    )
    command = compiler_command() + [
        "-std=c++17", "-O1", "-g", "-Wall", "-Wextra", "-Werror",
        "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
        "-I", str(ROOT),
    ]
    if enabled:
        command.append("-DTEST_FEATURE_ON=1")
    command += [str(source_path), "-o", str(binary_path)]
    compiled = subprocess.run(command, text=True, capture_output=True)
    if compiled.returncode:
        raise RuntimeError(
            f"{name} compile failed ({compiled.returncode})\n"
            f"command: {shlex.join(command)}\n{compiled.stdout}{compiled.stderr}"
        )
    env = os.environ.copy()
    env["ASAN_OPTIONS"] = "detect_leaks=0:halt_on_error=1"
    env["UBSAN_OPTIONS"] = "halt_on_error=1:print_stacktrace=1"
    ran = subprocess.run([str(binary_path)], text=True, capture_output=True, env=env)
    if ran.returncode:
        raise RuntimeError(
            f"{name} sanitizer harness failed ({ran.returncode})\n"
            f"{ran.stdout}{ran.stderr}"
        )
    return f"{name}: compile and ASan/UBSan execution passed"


def main() -> None:
    source = SOURCE.read_text(encoding="utf-8")
    pieces = check_source_contract(source)
    source_hash = hashlib.sha256(source.encode("utf-8")).hexdigest()
    drain_hash = hashlib.sha256(pieces["drain"].encode("utf-8")).hexdigest()
    print("PASS: kRocRead lease/snapshot remains in command-gate action")
    print("PASS: worker loop drains only after successful gated read")
    print(f"source_sha256={source_hash}")
    print(f"drain_function_sha256={drain_hash}")
    with tempfile.TemporaryDirectory(prefix="test086-probe-input-worker-") as directory:
        temp = Path(directory)
        print(compile_and_run(temp, pieces["drain"], True))
        print(compile_and_run(temp, pieces["drain"], False))
    print("PASS: Test086 production worker drain extraction")


if __name__ == "__main__":
    main()
