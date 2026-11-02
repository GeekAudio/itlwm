// SPDX-License-Identifier: GPL-2.0-only
import Foundation
import IOKit
import Darwin

// Argument-only by default. The explicit run sends exactly one native UDP
// datagram after the kernel publishes its matching 100 ms ROC START gate.
func matches(_ value: String, _ pattern: String) -> Bool {
    value.range(of: pattern, options: .regularExpression) != nil
}
func emit(_ object: [String: Any]) {
    if let bytes = try? JSONSerialization.data(withJSONObject: object, options: [.sortedKeys]) {
        FileHandle.standardOutput.write(bytes)
        FileHandle.standardOutput.write(Data("\n".utf8))
    }
}
var phase = "arguments"
var armMayHaveChanged = false
var accepted = false
var udpAttempted = false
var udpBytes = -1
func stop(_ text: String, _ code: Int32 = 1) -> Never {
    emit(["schema": 1, "phase": phase, "error": text,
          "arm_may_have_changed": armMayHaveChanged, "arm_accepted": accepted,
          "native_udp_attempted": udpAttempted, "native_udp_bytes": udpBytes,
          "peer_receipt_proven": false, "airdrop_proven": false,
          "automatic_retry_allowed": false])
    exit(code)
}
let args = Array(CommandLine.arguments.dropFirst())
let run = args.last == "--run"
let values = run ? Array(args.dropLast()) : args
guard values.count == 12, values[0] == "--expect-build", ["25G332-Test107", "25G332-Test108", "25G332-Test109"].contains(values[1]),
      values[2] == "--expect-uuid", values[4] == "--peer-mac",
      values[6] == "--local-ipv6", values[8] == "--nonce", values[10] == "--run-token",
      matches(values[3], "^[0-9A-F]{8}(-[0-9A-F]{4}){3}-[0-9A-F]{12}$"),
      matches(values[5], "^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}$"),
      matches(values[9], "^[0-9a-f]{16}$"), values[9].contains(where: { $0 != "0" }),
      matches(values[11], "^[0-9a-f]{32}$"), values[11].contains(where: { $0 != "0" }) else {
    stop("Usage: --expect-build 25G332-Test107|25G332-Test108|25G332-Test109 --expect-uuid UUID --peer-mac MAC --local-ipv6 fe80::ADDRESS --nonce 16hex --run-token 32hex [--run]")
}
let peer = values[5].split(separator: ":").map { UInt8($0, radix: 16)! }
guard peer[0] & 1 == 0, peer.contains(where: { $0 != 0 }) else { stop("Invalid unicast peer") }
let nonce = stride(from: 0, to: 16, by: 2).map { offset -> UInt8 in
    let a = values[9].index(values[9].startIndex, offsetBy: offset)
    return UInt8(values[9][a..<values[9].index(a, offsetBy: 2)], radix: 16)!
}
var sourceAddress = in6_addr()
guard inet_pton(AF_INET6, values[7], &sourceAddress) == 1 else { stop("Invalid canonical IPv6") }
let source = withUnsafeBytes(of: &sourceAddress) { Array($0) }
guard source[0] == 0xfe, source[1] == 0x80,
      source[2..<8].allSatisfy({ $0 == 0 }), source[8..<16].contains(where: { $0 != 0 }) else {
    stop("Source must be canonical fe80::/64 with nonzero interface identifier")
}
if !run {
    emit(["schema": 1, "mode": "plan", "build": values[1], "hardware_action": false,
          "arm_accepted": false, "channel_index": 6, "window_ms": 100,
          "native_udp_count": 1, "native_udp_payload_bytes": 8,
          "peer_receipt_proven": false, "airdrop_proven": false])
    exit(0)
}
guard geteuid() == 0 else { stop("Explicit run requires administrator privileges") }
phase = "loaded_identity"
let process = Process()
process.executableURL = URL(fileURLWithPath: "/usr/bin/kmutil")
process.arguments = ["showloaded", "--list-only", "--bundle-identifier", "org.geekaudio.AirportItlwm"]
let pipe = Pipe(); process.standardOutput = pipe; process.standardError = FileHandle.nullDevice
let done = DispatchSemaphore(value: 0); process.terminationHandler = { _ in done.signal() }
do { try process.run() } catch { stop("Cannot inspect loaded identity") }
if done.wait(timeout: .now() + 30) != .success {
    if process.isRunning { process.terminate() }
    if done.wait(timeout: .now() + 1) != .success && process.isRunning { kill(process.processIdentifier, SIGKILL) }
    stop("Loaded identity timeout")
}
let loaded = String(data: pipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
let rows = loaded.split(separator: "\n").filter { $0.contains("org.geekaudio.AirportItlwm ") }
let pattern = "org\\.geekaudio\\.AirportItlwm \\([^)]*\\) " + values[3] + "(?:\\s|$)"
guard process.terminationStatus == 0, rows.count == 1,
      matches(String(rows[0]), pattern) else { stop("Loaded UUID differs; no arm") }
var iterator: io_iterator_t = 0
guard IOServiceGetMatchingServices(kIOMainPortDefault, IOServiceMatching("AirportItlwm"), &iterator) == KERN_SUCCESS else { stop("No controller") }
var services: [io_service_t] = []
while true { let item = IOIteratorNext(iterator); if item == 0 { break }; services.append(item) }
IOObjectRelease(iterator)
defer { services.forEach { IOObjectRelease($0) } }
guard services.count == 1 else { stop("Expected one controller") }
let service = services[0]
func properties() -> [String: Any] {
    var all: Unmanaged<CFMutableDictionary>?
    guard IORegistryEntryCreateCFProperties(service, &all, kCFAllocatorDefault, 0) == KERN_SUCCESS,
          let dict = all?.takeRetainedValue() as? [String: Any] else { return [:] }
    return dict
}
func number(_ d: [String: Any], _ k: String) -> UInt64? { (d[k] as? NSNumber)?.uint64Value }
phase = "profile"
let before = properties()
guard before["NativeTestBuild"] as? String == values[1], number(before, "NativePowerReady") == 1,
      before["NativeP2PManualTrigger"] as? Bool == true,
      number(before, "NativeP2PDirectedDataEnabled") == 1,
      number(before, "NativeP2PDirectedDataCompiled") == 1,
      number(before, "NativeP2PProbeAttempted") == 0,
      number(before, "NativeP2PDirectedDataDoorbellIssued") ?? 0 == 0 else {
    stop("Profile not ready or one-shot already consumed")
}
phase = "native_socket"
let index = if_nametoindex("awdl0")
guard index != 0 else { stop("awdl0 is absent") }
let fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP)
guard fd >= 0 else { stop("Cannot create native UDP socket") }
defer { close(fd) }
var interface = index; var one: Int32 = 1; var zero: Int32 = 0
let optionsOK = setsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_IF, &interface, socklen_t(MemoryLayout.size(ofValue: interface))) == 0 &&
    setsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &one, socklen_t(MemoryLayout.size(ofValue: one))) == 0 &&
    setsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, &zero, socklen_t(MemoryLayout.size(ofValue: zero))) == 0
var local = sockaddr_in6(); local.sin6_len = UInt8(MemoryLayout<sockaddr_in6>.size)
local.sin6_family = sa_family_t(AF_INET6); local.sin6_port = UInt16(49153).bigEndian
local.sin6_addr = sourceAddress; local.sin6_scope_id = index
let bound = withUnsafePointer(to: &local) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in6>.size)) } }
guard optionsOK, bound == 0, fcntl(fd, F_SETFL, O_NONBLOCK) == 0 else { stop("Cannot bind exact native source/options") }
var destination = sockaddr_in6(); destination.sin6_len = UInt8(MemoryLayout<sockaddr_in6>.size)
destination.sin6_family = sa_family_t(AF_INET6); destination.sin6_port = UInt16(49152).bigEndian
_ = inet_pton(AF_INET6, "ff02::1", &destination.sin6_addr); destination.sin6_scope_id = index
phase = "arm"
armMayHaveChanged = true
let status = IORegistryEntrySetCFProperties(service, [
    "NativeP2PDirectedDataOnce": true,
    "NativeP2PDirectedDataPeerMAC": Data(peer),
    "NativeP2PDirectedDataLocalIPv6": Data(source),
    "NativeP2PDirectedDataNonce": Data(nonce),
    "NativeP2PDirectedDataRunToken": values[11]
] as CFDictionary)
guard status == KERN_SUCCESS else { stop(String(format: "Arm status 0x%08x; do not retry", UInt32(bitPattern: status))) }
var snapshot = properties()
guard snapshot["NativeP2PDirectedDataAcceptedRunToken"] as? String == values[11] else { stop("Arm receipt missing; do not retry") }
accepted = true
phase = "wait_roc_start"
let waitEnd = DispatchTime.now().uptimeNanoseconds + 5_000_000_000
while DispatchTime.now().uptimeNanoseconds < waitEnd {
    snapshot = properties()
    guard snapshot["NativeP2PDirectedDataAcceptedRunToken"] as? String == values[11],
          snapshot["NativeTestBuild"] as? String == values[1] else { stop("Arm identity changed") }
    if number(snapshot, "NativeP2PDirectedDataStage") == 4 && number(snapshot, "NativeP2PDirectedDataReady") == 1 { break }
    if (number(snapshot, "NativeP2PDirectedDataStage") ?? 0) >= 8 { stop("Kernel ended before native UDP") }
    usleep(500)
}
guard number(snapshot, "NativeP2PDirectedDataStage") == 4,
      number(snapshot, "NativeP2PDirectedDataReady") == 1 else { stop("No matching ROC START window") }
phase = "native_udp_once"
udpAttempted = true
udpBytes = nonce.withUnsafeBytes { bytes in
    withUnsafePointer(to: &destination) { ptr in
        ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) {
            sendto(fd, bytes.baseAddress, bytes.count, MSG_DONTWAIT, $0, socklen_t(MemoryLayout<sockaddr_in6>.size))
        }
    }
}
let sendError = udpBytes < 0 ? errno : 0
phase = "wait_cleanup"
let finishEnd = DispatchTime.now().uptimeNanoseconds + 5_000_000_000
while DispatchTime.now().uptimeNanoseconds < finishEnd {
    snapshot = properties()
    if (number(snapshot, "NativeP2PDirectedDataStage") ?? 0) >= 8 { break }
    usleep(10_000)
}
let keys = ["Stage", "Result", "HalState", "Reason", "StationAck", "QueueAck", "SessionSubmitted", "Ready", "Encoded", "NativePacketToken", "DoorbellIssued", "CompletionObserved", "RawTxStatus", "FirmwareAttemptSucceeded", "CleanupAck", "ResourcesAbsent", "QueueId", "StationId", "DescriptorIndex", "FrameControl", "SequenceControl", "ByteCount", "ExpectedNextSsn"]
var diagnostics: [String: Any] = [:]
for key in keys { if let n = number(snapshot, "NativeP2PDirectedData" + key) { diagnostics[key] = n } }
emit(["schema": 1, "mode": "explicit_run", "phase": phase, "build": values[1],
      "arm_may_have_changed": armMayHaveChanged, "arm_accepted": accepted,
      "native_udp_attempted": udpAttempted, "native_udp_bytes": udpBytes,
      "native_udp_errno": sendError, "diagnostics": diagnostics,
      "peer_receipt_proven": false, "radio_ack_proven": false, "airdrop_proven": false,
      "automatic_retry_allowed": false])
let complete = udpBytes == 8 && number(snapshot, "NativeP2PDirectedDataStage") == 8 &&
    number(snapshot, "NativeP2PDirectedDataResult") == 0 &&
    number(snapshot, "NativeP2PDirectedDataFirmwareAttemptSucceeded") == 1 &&
    number(snapshot, "NativeP2PDirectedDataResourcesAbsent") == 1
exit(complete ? 0 : 2)
