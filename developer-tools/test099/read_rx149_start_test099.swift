// SPDX-License-Identifier: GPL-2.0-only
// Read-only, low-latency START barrier for the bounded Test099 RX149 window.
// This helper never sets properties or triggers radio activity.
import Foundation
import IOKit
import Darwin

struct LiveStart {
    let revision: UInt32
    let valid: UInt32
    let token: String
    let profile: UInt32
    let channel: UInt32
    let durationMs: UInt32
    let configuration: UInt32
    let commandResult: Int32
    let startSeen: UInt32
    let startStatus: UInt32
    let endSeen: UInt32
    let outcomeUnknown: UInt32
    let ownerSerial: UInt64
    let contextGeneration: UInt32
    let powerGeneration: UInt32
    let stationGeneration: UInt32
    let rocGeneration: UInt32
    let startUs: UInt64
    let deadlineUs: UInt64
    let publishedUs: UInt64
}

func fail(_ code: String) -> Never {
    FileHandle.standardError.write(Data((code + "\n").utf8))
    exit(1)
}

func parseHexToken(_ value: String) -> [UInt8]? {
    guard value.range(of: "^[0-9a-f]{32}$", options: .regularExpression) != nil else {
        return nil
    }
    let bytes = Array(value.utf8)
    var result = [UInt8]()
    result.reserveCapacity(16)
    for index in stride(from: 0, to: bytes.count, by: 2) {
        func nibble(_ byte: UInt8) -> UInt8? {
            switch byte {
            case 48...57: return byte - 48
            case 97...102: return byte - 97 + 10
            default: return nil
            }
        }
        guard let high = nibble(bytes[index]), let low = nibble(bytes[index + 1]) else {
            return nil
        }
        result.append((high << 4) | low)
    }
    return result
}

func hexToken(_ bytes: [UInt8]) -> String {
    bytes.map { String(format: "%02x", $0) }.joined()
}

func readU32(_ bytes: [UInt8], _ offset: Int) -> UInt32 {
    UInt32(bytes[offset]) |
        (UInt32(bytes[offset + 1]) << 8) |
        (UInt32(bytes[offset + 2]) << 16) |
        (UInt32(bytes[offset + 3]) << 24)
}

func readU64(_ bytes: [UInt8], _ offset: Int) -> UInt64 {
    UInt64(readU32(bytes, offset)) |
        (UInt64(readU32(bytes, offset + 4)) << 32)
}

func parseSnapshot(_ data: Data) -> LiveStart? {
    guard data.count == 116 else { return nil }
    let bytes = [UInt8](data)
    guard readU32(bytes, 0) == 0x39584952,
          readU32(bytes, 4) == 1 else { return nil }
    let revision = readU32(bytes, 8)
    guard revision != 0 && revision & 1 == 0 else { return nil }
    let tokenBytes = Array(bytes[16..<32])
    let value = LiveStart(
        revision: revision,
        valid: readU32(bytes, 12),
        token: hexToken(tokenBytes),
        profile: readU32(bytes, 32),
        channel: readU32(bytes, 36),
        durationMs: readU32(bytes, 40),
        configuration: readU32(bytes, 44),
        commandResult: Int32(bitPattern: readU32(bytes, 48)),
        startSeen: readU32(bytes, 52),
        startStatus: readU32(bytes, 56),
        endSeen: readU32(bytes, 60),
        outcomeUnknown: readU32(bytes, 64),
        ownerSerial: readU64(bytes, 68),
        contextGeneration: readU32(bytes, 76),
        powerGeneration: readU32(bytes, 80),
        stationGeneration: readU32(bytes, 84),
        rocGeneration: readU32(bytes, 88),
        startUs: readU64(bytes, 92),
        deadlineUs: readU64(bytes, 100),
        publishedUs: readU64(bytes, 108))
    guard value.valid <= 1, value.startSeen <= 1, value.endSeen <= 1,
          value.outcomeUnknown <= 1 else { return nil }
    return value
}

func machUptimeUs() -> UInt64? {
    var info = mach_timebase_info_data_t()
    guard mach_timebase_info(&info) == KERN_SUCCESS,
          info.denom != 0 else { return nil }
    let ticks = mach_absolute_time()
    let (scaled, overflow) = ticks.multipliedReportingOverflow(by: UInt64(info.numer))
    guard !overflow else { return nil }
    let nanos = scaled / UInt64(info.denom)
    return nanos / 1000
}

func getProperty(_ service: io_service_t, _ name: String) -> Any? {
    IORegistryEntryCreateCFProperty(service, name as CFString,
        kCFAllocatorDefault, 0)?.takeRetainedValue()
}

func emitReady(_ build: String, _ expectedToken: String, _ value: LiveStart,
               _ nowUs: UInt64, _ minimumRemainingUs: UInt64) {
    let remaining = value.deadlineUs - nowUs
    let result: [String: Any] = [
        "event": "NATIVE_RX_READY",
        "schema": 1,
        "build": build,
        "run_token": expectedToken,
        "snapshot_run_token": value.token,
        "snapshot_revision": value.revision,
        "profile_mode": value.profile,
        "channel": value.channel,
        "duration_ms": value.durationMs,
        "configuration": value.configuration,
        "command_result": value.commandResult,
        "start_seen": value.startSeen,
        "start_status": value.startStatus,
        "end_seen": value.endSeen,
        "outcome_unknown": value.outcomeUnknown,
        "owner_serial": value.ownerSerial,
        "context_generation": value.contextGeneration,
        "power_generation": value.powerGeneration,
        "station_generation": value.stationGeneration,
        "roc_generation": value.rocGeneration,
        "start_observed_us": value.startUs,
        "hard_deadline_us": value.deadlineUs,
        "published_us": value.publishedUs,
        "observed_now_us": nowUs,
        "remaining_us": remaining,
        "minimum_remaining_us": minimumRemainingUs,
        "peer_receipt_proven": false,
        "native_awdl_reply_proven": false,
        "airdrop_proven": false,
        "retry_allowed": false,
    ]
    guard let encoded = try? JSONSerialization.data(withJSONObject: result,
                                                     options: [.sortedKeys]),
          let line = String(data: encoded, encoding: .utf8) else {
        fail("RX149_READY_SERIALIZATION_FAILED")
    }
    FileHandle.standardOutput.write(Data((line + "\n").utf8))
}

guard CommandLine.arguments.count == 9,
      CommandLine.arguments[1] == "--expect-build",
      CommandLine.arguments[2].range(of: "^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$",
                                     options: .regularExpression) != nil,
      CommandLine.arguments[3] == "--expect-run-token",
      let expectedTokenBytes = parseHexToken(CommandLine.arguments[4]),
      CommandLine.arguments[5] == "--minimum-remaining-us",
      let minimumRemainingUs = UInt64(CommandLine.arguments[6]),
      minimumRemainingUs >= 10000 && minimumRemainingUs <= 80000,
      CommandLine.arguments[7] == "--wait-ms",
      let waitMs = UInt64(CommandLine.arguments[8]),
      waitMs >= 10 && waitMs <= 10000 else {
    fail("USAGE")
}
let expectedBuild = CommandLine.arguments[2]
let expectedToken = CommandLine.arguments[4]
_ = expectedTokenBytes

var iterator: io_iterator_t = 0
guard IOServiceGetMatchingServices(kIOMainPortDefault,
        IOServiceMatching("AirportItlwm"), &iterator) == KERN_SUCCESS else {
    fail("RX149_CONTROLLER_ENUMERATION_FAILED")
}
var services = [io_service_t]()
while true {
    let service = IOIteratorNext(iterator)
    if service == 0 { break }
    services.append(service)
}
IOObjectRelease(iterator)
defer { for service in services { IOObjectRelease(service) } }
guard services.count == 1 else { fail("RX149_CONTROLLER_COUNT_INVALID") }
let service = services[0]
guard getProperty(service, "NativeTestBuild") as? String == expectedBuild,
      getProperty(service, "NativeP2PRx149RunToken") as? String == expectedToken else {
    fail("RX149_BUILD_OR_RUN_BINDING_MISMATCH")
}

guard let startedAt = machUptimeUs() else { fail("RX149_CLOCK_UNAVAILABLE") }
let (stopAt, overflow) = startedAt.addingReportingOverflow(waitMs * 1000)
guard !overflow else { fail("RX149_DEADLINE_OVERFLOW") }
while true {
    guard let data = getProperty(service, "NativeP2PRx149LiveStartSnapshot") as? Data,
          let value = parseSnapshot(data) else {
        // An absent/invalid snapshot is expected before START publication.
        if let now = machUptimeUs(), now >= stopAt {
            fail("RX149_LIVE_START_TIMEOUT")
        }
        usleep(1000)
        continue
    }
    guard let nowUs = machUptimeUs() else { fail("RX149_CLOCK_UNAVAILABLE") }
    guard getProperty(service, "NativeP2PRx149RunToken") as? String == expectedToken else {
        fail("RX149_BUILD_OR_RUN_BINDING_MISMATCH")
    }
    if value.token != expectedToken {
        if nowUs >= stopAt { fail("RX149_LIVE_START_TIMEOUT") }
        usleep(1000)
        continue
    }
    if value.endSeen == 1 || value.outcomeUnknown == 1 {
        fail("RX149_LIVE_SESSION_TERMINAL")
    }
    let durationUs = UInt64(value.durationMs) * 1000
    let deadlineMatches = value.startUs <= UInt64.max - durationUs &&
        value.deadlineUs == value.startUs + durationUs
    if value.valid == 1 && value.profile == 2 && value.channel == 149 &&
       value.durationMs == 100 && value.configuration == 2 &&
       value.commandResult == 0 && value.startSeen == 1 &&
       value.startStatus == 1 && value.endSeen == 0 &&
       value.outcomeUnknown == 0 && value.ownerSerial != 0 &&
       value.contextGeneration != 0 && value.powerGeneration != 0 &&
       value.stationGeneration != 0 && value.rocGeneration == value.contextGeneration &&
       value.startUs != 0 && deadlineMatches && value.publishedUs >= value.startUs &&
       nowUs >= value.publishedUs && nowUs < value.deadlineUs &&
       value.deadlineUs - nowUs >= minimumRemainingUs {
        emitReady(expectedBuild, expectedToken, value, nowUs, minimumRemainingUs)
        exit(0)
    }
    if nowUs >= stopAt { fail("RX149_LIVE_START_TIMEOUT") }
    usleep(1000)
}

