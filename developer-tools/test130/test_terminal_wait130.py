#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Exercise the production Test130 bounded terminal wait with a nanosecond clock."""
from __future__ import annotations

from pathlib import Path
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[2]
HELPER = ROOT / "developer-tools/test130/arm_directed_data130.swift"


def extract_function(source: str, name: str) -> str:
    marker = f"func {name}("
    start = source.find(marker)
    if start < 0:
        raise AssertionError(f"missing production function: {name}")
    brace = source.find("{", start)
    if brace < 0:
        raise AssertionError(f"missing function body: {name}")
    depth = 0
    for index in range(brace, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[start:index + 1]
    raise AssertionError(f"unterminated function body: {name}")


def render_harness() -> str:
    source = HELPER.read_text(encoding="utf-8")
    function = extract_function(source, "waitForTerminal130")
    if function.count("DispatchTime.now().uptimeNanoseconds") != 2:
        raise AssertionError("production wait must use its monotonic nanosecond clock")
    if function.count("usleep(10_000)") != 1:
        raise AssertionError("production wait polling interval changed unexpectedly")
    function = function.replace(
        "DispatchTime.now().uptimeNanoseconds", "testNowNanoseconds()")
    function = function.replace("usleep(10_000)", "testSleepUs(10_000)")

    prefix = r'''import Foundation

var clockNanoseconds: UInt64 = 0
var sleepCount = 0
var readCount = 0
var scriptedSnapshots: [[String: Any]] = []

func testNowNanoseconds() -> UInt64 { clockNanoseconds }
func testSleepUs(_ microseconds: UInt32) {
    clockNanoseconds += UInt64(microseconds) * 1_000
    sleepCount += 1
}
func properties130() -> [String: Any] {
    precondition(!scriptedSnapshots.isEmpty)
    let index = min(readCount, scriptedSnapshots.count - 1)
    readCount += 1
    return scriptedSnapshots[index]
}
func number130(_ object: [String: Any], _ key: String) -> UInt64? {
    object[key] as? UInt64
}
func expect(_ condition: Bool, _ message: String) {
    if !condition { fatalError(message) }
}
func snapshot(_ stage: UInt64, exactDelivered: UInt64 = 0,
              cleanup: UInt64 = 0, resourcesAbsent: UInt64 = 0)
    -> [String: Any] {
    ["NativeP2PDirectedDataStage": stage,
     "NativeP2PDirectedDataPacket1ExactReplyCaptured": exactDelivered,
     "NativeP2PDirectedDataPacket1ExactReplyDelivered": exactDelivered,
     "NativeP2PDirectedDataPacket1ExactReplyValid": exactDelivered,
     "NativeP2PDirectedDataCleanupAck": cleanup,
     "NativeP2PDirectedDataResourcesAbsent": resourcesAbsent,
     "NativeP2PProbeAttempted": UInt64(1),
     "NativeP2PProbeState": UInt64(7),
     "NativeP2PProbeRemoveResult": UInt64(0),
     "NativeP2PProbeResourceMayExist": UInt64(0),
     "NativeP2PProbeContextGeneration": UInt64(11),
     "NativeP2PProbePowerGeneration": UInt64(13),
     "NativeP2PProbeStationGeneration": UInt64(17)]
}
'''
    suffix = r'''

// Slot one exact return and cleanup become visible after two real 10 ms polls.
let start = UInt64(1_000_000_000)
clockNanoseconds = start
scriptedSnapshots = [
    snapshot(6),
    snapshot(6),
    snapshot(8, exactDelivered: 1, cleanup: 1, resourcesAbsent: 1)
]
expect(number130(scriptedSnapshots[0],
                 "NativeP2PDirectedDataPacket1ExactReplyDelivered") == 0 &&
       number130(scriptedSnapshots[1],
                 "NativeP2PDirectedDataPacket1ExactReplyDelivered") == 0,
       "packet one's exact return must still be unpublished in Stage 6")
let completed = waitForTerminal130()
expect(number130(completed, "NativeP2PDirectedDataStage") == 8,
       "Stage 6 must remain pending past the 10 ms intermediate snapshot")
expect(sleepCount == 2 && readCount == 3,
       "the delayed Stage 8 snapshot must be read after two polls")
expect(clockNanoseconds - start == 20_000_000,
       "10 ms polls must advance the fake clock in nanoseconds")
expect(number130(completed, "NativeP2PDirectedDataPacket1ExactReplyDelivered") == 1 &&
       number130(completed, "NativeP2PDirectedDataPacket1ExactReplyValid") == 1,
       "the returned snapshot must contain packet one's later exact receipt")
expect(number130(completed, "NativeP2PDirectedDataCleanupAck") == 1 &&
       number130(completed, "NativeP2PDirectedDataResourcesAbsent") == 1 &&
       number130(completed, "NativeP2PProbeState") == 7 &&
       number130(completed, "NativeP2PProbeRemoveResult") == 0 &&
       number130(completed, "NativeP2PProbeResourceMayExist") == 0,
       "the completed snapshot must retain cleanup, resource, and outer release proof")

// Quarantine and cleaned failure remain prompt terminal observations.
for terminalStage: UInt64 in [9, 10] {
    clockNanoseconds = 2_000_000_000
    sleepCount = 0
    readCount = 0
    scriptedSnapshots = [snapshot(terminalStage)]
    let terminal = waitForTerminal130()
    expect(number130(terminal, "NativeP2PDirectedDataStage") == terminalStage &&
           sleepCount == 0 && readCount == 1,
           "failure/quarantine stage must return immediately")
}

// With no terminal publication, the production default is bounded at 5 seconds.
let timeoutStart = UInt64(3_000_000_000)
clockNanoseconds = timeoutStart
sleepCount = 0
readCount = 0
scriptedSnapshots = [snapshot(6)]
let timedOut = waitForTerminal130()
expect(number130(timedOut, "NativeP2PDirectedDataStage") == 6,
       "a nonterminal snapshot must remain fail-closed at timeout")
expect(clockNanoseconds - timeoutStart == 5_000_000_000 && sleepCount == 500,
       "the default wait limit must be five seconds, measured in nanoseconds")
print("Test130 terminal wait: Stage 6→8, delayed exact receipt, cleanup, isolation, and 5 s bound passed")
'''
    return prefix + function + suffix


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="test130-terminal-wait-") as temporary:
        directory = Path(temporary)
        source = directory / "terminal_wait_test.swift"
        binary = directory / "terminal_wait_test"
        source.write_text(render_harness(), encoding="utf-8")
        subprocess.run(["xcrun", "swiftc", str(source), "-o", str(binary)],
                       cwd=ROOT, check=True)
        subprocess.run([str(binary)], cwd=ROOT, check=True)


if __name__ == "__main__":
    main()
