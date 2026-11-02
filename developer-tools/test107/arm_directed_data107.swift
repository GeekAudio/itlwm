// SPDX-License-Identifier: GPL-2.0-only
import Foundation
import IOKit
import Darwin
import CoreFoundation
import CryptoKit
import IORegistryBooleanFlag107
import Test114RxLease

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
var matchedPeerReturn = false
var ifnetDeliveryProven = false
var peerReturnStatus = "not_tested"
var peerReturnDatagramsSeen: UInt32 = 0
var peerReturnDatagramsRejected: UInt32 = 0
var peerReturnError: Int32 = 0
var peerReturnElapsedUs: UInt64 = 0
var rxLeasePollTrace = Test114RxLeasePollTrace()
func stop(_ text: String, _ code: Int32 = 1) -> Never {
    var result: [String: Any] = ["schema": 1, "phase": phase, "error": text,
                                "arm_may_have_changed": armMayHaveChanged, "arm_accepted": accepted,
                                "native_udp_attempted": udpAttempted, "native_udp_bytes": udpBytes,
                                "matched_peer_return_proven": false, "ifnet_delivery_proven": false,
                                "peer_return_status": "not_proven", "peer_receipt_proven": false,
                                "airdrop_proven": false,
                                "automatic_retry_allowed": false]
    if rxLeasePollTrace.checkCount > 0 {
        result["rx_lease_poll"] = rxLeasePollTrace.jsonObject
    }
    emit(result)
    exit(code)
}
@_silgen_name("t110_prepare_existing_socket")
func t110PrepareExistingSocket(_ fd: Int32, _ local: UnsafePointer<UInt8>,
                               _ ifindex: UInt32,
                               _ errorNumber: UnsafeMutablePointer<Int32>) -> Int32
@_silgen_name("t110_current_uptime_us")
func t110CurrentUptimeUs(_ nowUs: UnsafeMutablePointer<UInt64>) -> Int32
@_silgen_name("t110_wait_for_matching_return")
func t110WaitForMatchingReturn(
    _ fd: Int32, _ peer: UnsafePointer<UInt8>, _ local: UnsafePointer<UInt8>,
    _ ifindex: UInt32, _ nonce: UnsafePointer<UInt8>, _ kernelDeadlineUs: UInt64,
    _ timeoutMs: UInt32, _ seen: UnsafeMutablePointer<UInt32>,
    _ rejected: UnsafeMutablePointer<UInt32>, _ errorNumber: UnsafeMutablePointer<Int32>,
    _ elapsedUs: UnsafeMutablePointer<UInt64>) -> Int32

let arguments = Array(CommandLine.arguments.dropFirst())
let run = arguments.last == "--run"
let optionArguments = run ? Array(arguments.dropLast()) : arguments
let allowedOptions: Set<String> = ["--expect-build", "--expect-uuid", "--peer-mac",
                                   "--local-ipv6", "--nonce", "--run-token",
                                   "--peer-ipv6", "--peer-ready-file"]
var options: [String: String] = [:]
var optionIndex = 0
while optionIndex < optionArguments.count {
    let key = optionArguments[optionIndex]
    guard allowedOptions.contains(key), optionIndex + 1 < optionArguments.count,
          options[key] == nil else { break }
    options[key] = optionArguments[optionIndex + 1]
    optionIndex += 2
}
let requiredOptions: Set<String> = ["--expect-build", "--expect-uuid", "--peer-mac",
                                    "--local-ipv6", "--nonce", "--run-token"]
guard optionIndex == optionArguments.count,
      Set(options.keys).isSuperset(of: requiredOptions),
      let build = options["--expect-build"],
      ["25G332-Test107", "25G332-Test108", "25G332-Test109", "25G332-Test110", "25G332-Test111", "25G332-Test112", "25G332-Test113", "25G332-Test114"].contains(build),
      let expectedUUID = options["--expect-uuid"],
      matches(expectedUUID, "^[0-9A-F]{8}(-[0-9A-F]{4}){3}-[0-9A-F]{12}$"),
      let peerMACText = options["--peer-mac"],
      matches(peerMACText, "^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}$"),
      let sourceText = options["--local-ipv6"],
      let nonceText = options["--nonce"], matches(nonceText, "^[0-9a-f]{16}$"),
      nonceText.contains(where: { $0 != "0" }),
      let runToken = options["--run-token"], matches(runToken, "^[0-9a-f]{32}$"),
      runToken.contains(where: { $0 != "0" }) else {
    stop("Usage: --expect-build 25G332-Test107|25G332-Test108|25G332-Test109|25G332-Test110|25G332-Test111|25G332-Test112|25G332-Test113|25G332-Test114 --expect-uuid UUID --peer-mac MAC --local-ipv6 fe80::ADDRESS --nonce 16hex --run-token 32hex [--peer-ipv6 fe80::ADDRESS --peer-ready-file PRIVATE_JSON] [--run]")
}
let matchedReturnBuild = ["25G332-Test110", "25G332-Test111", "25G332-Test112", "25G332-Test113", "25G332-Test114"].contains(build)
guard matchedReturnBuild == (options["--peer-ipv6"] != nil),
      matchedReturnBuild == (options["--peer-ready-file"] != nil) else {
    stop("Test110-Test114 require peer IPv6 and fresh peer READY file; older identities do not accept them")
}
let peer = peerMACText.split(separator: ":").compactMap { UInt8($0, radix: 16) }
guard peer.count == 6, peer[0] & 1 == 0, peer.contains(where: { $0 != 0 }) else {
    stop("Invalid unicast peer")
}
let peerMACHex = peer.map { String(format: "%02x", $0) }.joined()
func canonicalLinkLocal(_ text: String) -> [UInt8]? {
    var address = in6_addr()
    guard inet_pton(AF_INET6, text, &address) == 1 else { return nil }
    let bytes = withUnsafeBytes(of: &address) { Array($0) }
    guard bytes.count == 16, bytes[0] == 0xfe, bytes[1] == 0x80,
          bytes[2..<8].allSatisfy({ $0 == 0 }),
          bytes[8..<16].contains(where: { $0 != 0 }) else { return nil }
    return bytes
}
guard let source = canonicalLinkLocal(sourceText) else {
    stop("Source must be canonical fe80::/64 with nonzero interface identifier")
}
let nonce = stride(from: 0, to: 16, by: 2).map { offset -> UInt8 in
    let a = nonceText.index(nonceText.startIndex, offsetBy: offset)
    return UInt8(nonceText[a..<nonceText.index(a, offsetBy: 2)], radix: 16)!
}
var sourceAddress = in6_addr()
guard inet_pton(AF_INET6, sourceText, &sourceAddress) == 1 else {
    stop("Invalid canonical source IPv6")
}
let peerIPv6 = matchedReturnBuild ? canonicalLinkLocal(options["--peer-ipv6"]!) : nil
if matchedReturnBuild && peerIPv6 == nil { stop("Peer must be canonical unicast link-local IPv6") }

struct PeerReadyEvidence {
    let windowExpiresAtUptimeNs: UInt64
}

func hex(_ bytes: [UInt8]) -> String {
    bytes.map { String(format: "%02x", $0) }.joined()
}

func awdl0HardwareAddress() -> [UInt8]? {
    var all: UnsafeMutablePointer<ifaddrs>?
    guard getifaddrs(&all) == 0, let first = all else { return nil }
    defer { freeifaddrs(all) }
    var cursor: UnsafeMutablePointer<ifaddrs>? = first
    while let current = cursor?.pointee {
        cursor = current.ifa_next
        guard let namePointer = current.ifa_name,
              String(cString: namePointer) == "awdl0",
              let address = current.ifa_addr,
              address.pointee.sa_family == sa_family_t(AF_LINK) else { continue }
        let link = address.withMemoryRebound(to: sockaddr_dl.self, capacity: 1) { $0.pointee }
        guard link.sdl_alen == 6 else { continue }
        var mac: [UInt8] = []
        withUnsafePointer(to: link.sdl_data) { data in
            let bytes = UnsafeRawPointer(data).assumingMemoryBound(to: UInt8.self)
            let start = Int(link.sdl_nlen)
            for offset in 0..<Int(link.sdl_alen) { mac.append(bytes[start + offset]) }
        }
        guard mac.count == 6, mac[0] & 1 == 0, mac.contains(where: { $0 != 0 }) else { continue }
        return mac
    }
    return nil
}

func peerWindowRemainingMs(_ evidence: PeerReadyEvidence) -> UInt64 {
    let now = DispatchTime.now().uptimeNanoseconds
    guard now < evidence.windowExpiresAtUptimeNs else { return 0 }
    return (evidence.windowExpiresAtUptimeNs - now) / 1_000_000
}

func privateJSONFile(_ path: String) -> Data? {
    let fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW)
    guard fd >= 0 else { return nil }
    defer { close(fd) }
    var info = stat()
    guard fstat(fd, &info) == 0,
          (info.st_mode & mode_t(S_IFMT)) == mode_t(S_IFREG),
          (info.st_mode & 0o077) == 0,
          info.st_size > 0, info.st_size <= 4096,
          info.st_uid == getuid() || info.st_uid == 0 else { return nil }
    var bytes = Data(count: Int(info.st_size))
    let complete = bytes.withUnsafeMutableBytes { buffer -> Bool in
        guard let baseAddress = buffer.baseAddress else { return false }
        var offset = 0
        while offset < buffer.count {
            let amount = read(fd, baseAddress.advanced(by: offset), buffer.count - offset)
            if amount <= 0 { return false }
            offset += Int(amount)
        }
        return true
    }
    guard complete else { return nil }
    return bytes
}

func numberField(_ object: [String: Any], _ key: String) -> UInt64? {
    guard let value = object[key] as? NSNumber,
          CFGetTypeID(value) != CFBooleanGetTypeID() else { return nil }
    let number = value.doubleValue
    guard number.isFinite, number >= 0, number.rounded(.towardZero) == number,
          number < 18_446_744_073_709_551_616.0 else { return nil }
    return value.uint64Value
}

func validatePeerReadyFile(_ path: String) -> PeerReadyEvidence? {
    guard path.hasPrefix("/"), let bytes = privateJSONFile(path),
          let object = (try? JSONSerialization.jsonObject(with: bytes)) as? [String: Any] else {
        return nil
    }
    let required: Set<String> = ["event", "schema", "run_token", "nonce", "created_utc",
                                 "window_ms", "channel", "peer_ipv6", "peer_mac", "local_mac",
                                 "local_ipv6", "request_source_port",
                                 "request_destination_port", "reply_source_port",
                                 "reply_destination_port", "hop_limit", "payload_bytes",
                                 "echo_mode", "contract_identity_digest",
                                 "router_ready_sha256"]
    guard Set(object.keys) == required,
          object["event"] as? String == "READY",
          object["schema"] as? String == "test110-openwrt-echo-coordinator-ready/v1",
          object["run_token"] as? String == runToken,
          object["nonce"] as? String == nonceText,
          object["peer_mac"] as? String == peerMACHex,
          let currentLocalMAC = awdl0HardwareAddress(),
          object["local_mac"] as? String == hex(currentLocalMAC),
          object["echo_mode"] as? String == "exact-request-payload-once",
          let evidencePeerText = object["peer_ipv6"] as? String,
          let evidenceLocalText = object["local_ipv6"] as? String,
          let evidencePeer = canonicalLinkLocal(evidencePeerText),
          let evidenceLocal = canonicalLinkLocal(evidenceLocalText),
          evidencePeer == peerIPv6, evidenceLocal == source,
          let timestamp = object["created_utc"] as? String,
          matches(timestamp, "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\\.[0-9]{1,9})?Z$"),
          let contractDigest = object["contract_identity_digest"] as? String,
          matches(contractDigest, "^[0-9a-f]{64}$"),
          let readyDigest = object["router_ready_sha256"] as? String,
          matches(readyDigest, "^[0-9a-f]{64}$"),
          let windowMs = numberField(object, "window_ms"),
          windowMs > 0, windowMs <= 16_000,
          numberField(object, "channel") == 6,
          numberField(object, "request_source_port") == 49_153,
          numberField(object, "request_destination_port") == 49_152,
          numberField(object, "reply_source_port") == 49_152,
          numberField(object, "reply_destination_port") == 49_153,
          numberField(object, "hop_limit") == 1,
          numberField(object, "payload_bytes") == 8 else { return nil }
    let formatter = ISO8601DateFormatter()
    formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
    let createdAt = formatter.date(from: timestamp) ?? {
        formatter.formatOptions = [.withInternetDateTime]
        return formatter.date(from: timestamp)
    }()
    guard let createdAt else { return nil }
    guard let peerBytes = peerIPv6, peerBytes.count == 16,
          source.count == 16 else { return nil }
    let contract = "test110-echo/v1\n\(runToken)\n\(nonceText)\n\(hex(currentLocalMAC))\n\(peerMACHex)\n\(hex(source))\n\(hex(peerBytes))\n6,49153,49152,49152,49153,1,8\n"
    let expectedDigest = SHA256.hash(data: Data(contract.utf8)).map { String(format: "%02x", $0) }.joined()
    guard contractDigest == expectedDigest else { return nil }
    let validatedAtUptimeNs = DispatchTime.now().uptimeNanoseconds
    let ageMs = Date().timeIntervalSince(createdAt) * 1000
    let remainingMs = Double(windowMs) - ageMs
    guard ageMs >= 0, ageMs <= 120_000, remainingMs >= 6_000,
          remainingMs.isFinite, remainingMs <= 16_000 else { return nil }
    let remainingNs = UInt64((remainingMs * 1_000_000).rounded(.down))
    let conservativeRemainingNs = remainingNs > 1_000_000 ?
        remainingNs - 1_000_000 : 0
    guard conservativeRemainingNs > 0,
          validatedAtUptimeNs <= UInt64.max - conservativeRemainingNs else { return nil }
    return PeerReadyEvidence(
        windowExpiresAtUptimeNs: validatedAtUptimeNs + conservativeRemainingNs)
}

if !run {
    emit(["schema": 1, "mode": "plan", "build": build, "hardware_action": false,
          "arm_accepted": false, "channel_index": 6, "roc_window_ms": 100,
          "native_udp_count": 1, "native_udp_payload_bytes": 8,
          "peer_ready_required": matchedReturnBuild, "peer_ready_file_read": false,
          "matched_return_capture_max_ms": matchedReturnBuild ? 100 : 0,
          "rx_lease_poll_within_original_window": build == "25G332-Test114",
          "rx_lease_max_checks": build == "25G332-Test114" ? 128 : (matchedReturnBuild ? 1 : 0),
          "peer_receipt_proven": false, "ifnet_delivery_proven": false,
          "airdrop_proven": false, "automatic_retry_allowed": false])
    exit(0)
}
guard geteuid() == 0 else { stop("Explicit run requires administrator privileges") }
let peerReady = matchedReturnBuild ? validatePeerReadyFile(options["--peer-ready-file"]!) : nil
if matchedReturnBuild && peerReady == nil { stop("Fresh matching OpenWrt echo READY receipt missing or invalid; no arm") }
if let peerReady, peerWindowRemainingMs(peerReady) < 6_000 {
    stop("OpenWrt echo READY window too short for the one-shot ROC wait; no arm")
}
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
let pattern = "org\\.geekaudio\\.AirportItlwm \\([^)]*\\) " + expectedUUID + "(?:\\s|$)"
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
func number(_ d: [String: Any], _ k: String) -> UInt64? {
    guard let value = d[k] as? NSNumber,
          CFGetTypeID(value) != CFBooleanGetTypeID() else { return nil }
    return value.uint64Value
}
func pollForTest114RxLease(initial: [String: Any]) -> Test114RxLeaseWindow? {
    let outcome = test114PollRxLease(
        initial: initial, expectedRunToken: runToken, expectedBuild: build,
        readProperties: { properties() },
        monotonicUs: {
            var nowUs: UInt64 = 0
            return t110CurrentUptimeUs(&nowUs) == 0 ? nowUs : nil
        },
        sleepMicroseconds: { usleep($0) })
    rxLeasePollTrace = outcome.trace
    return outcome.window
}
func checkPriorMatchedReturnLeaseOnce(_ initial: [String: Any]) -> Test114RxLeaseWindow? {
    let originalWindow = test114InitialWindow(initial)
    let originalIdentity = test114InitialIdentity(initial)
    var nowUs: UInt64 = 0
    let monotonicUs = t110CurrentUptimeUs(&nowUs) == 0 ? nowUs : nil
    let check = test114CheckRxLease(
        initial, originalWindow: originalWindow, originalIdentity: originalIdentity,
        monotonicUs: monotonicUs,
        bindOriginAccepted: initial["NativeP2PDirectedDataAcceptedRunToken"] as? String == runToken,
        buildMatches: initial["NativeTestBuild"] as? String == build,
        stageReady: number(initial, "NativeP2PDirectedDataStage") == 4 &&
                    number(initial, "NativeP2PDirectedDataReady") == 1)
    rxLeasePollTrace.record(check)
    return check.valid ? originalWindow : nil
}
phase = "profile"
let before = properties()
guard before["NativeTestBuild"] as? String == build, number(before, "NativePowerReady") == 1,
      IORegistryBooleanFlag107.read(before["NativeP2PManualTrigger"]) == true,
      IORegistryBooleanFlag107.read(before["NativeP2PDirectedDataEnabled"]) == true,
      IORegistryBooleanFlag107.read(before["NativeP2PDirectedDataCompiled"]) == true,
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
if matchedReturnBuild {
    var prepareError: Int32 = 0
    let prepareStatus = source.withUnsafeBufferPointer { localBytes in
        t110PrepareExistingSocket(fd, localBytes.baseAddress!, UInt32(index), &prepareError)
    }
    guard prepareStatus == 0 else { stop("Cannot prepare same-socket matched-return capture") }
}
var destination = sockaddr_in6(); destination.sin6_len = UInt8(MemoryLayout<sockaddr_in6>.size)
destination.sin6_family = sa_family_t(AF_INET6); destination.sin6_port = UInt16(49152).bigEndian
_ = inet_pton(AF_INET6, "ff02::1", &destination.sin6_addr); destination.sin6_scope_id = index
if matchedReturnBuild, let peerReady, peerWindowRemainingMs(peerReady) < 6_000 {
    stop("OpenWrt echo READY window too short before arm; no claim consumed")
}
phase = "arm"
armMayHaveChanged = true
let status = IORegistryEntrySetCFProperties(service, [
    "NativeP2PDirectedDataOnce": true,
    "NativeP2PDirectedDataPeerMAC": Data(peer),
    "NativeP2PDirectedDataLocalIPv6": Data(source),
    "NativeP2PDirectedDataNonce": Data(nonce),
    "NativeP2PDirectedDataRunToken": runToken
] as CFDictionary)
guard status == KERN_SUCCESS else { stop(String(format: "Arm status 0x%08x; do not retry", UInt32(bitPattern: status))) }
var snapshot = properties()
guard snapshot["NativeP2PDirectedDataAcceptedRunToken"] as? String == runToken else { stop("Arm receipt missing; do not retry") }
accepted = true
phase = "wait_roc_start"
let waitEnd = DispatchTime.now().uptimeNanoseconds + 5_000_000_000
var rocReadyObservedAt: UInt64 = 0
while DispatchTime.now().uptimeNanoseconds < waitEnd {
    snapshot = properties()
    guard snapshot["NativeP2PDirectedDataAcceptedRunToken"] as? String == runToken,
          snapshot["NativeTestBuild"] as? String == build else { stop("Arm identity changed") }
    if number(snapshot, "NativeP2PDirectedDataStage") == 4 && number(snapshot, "NativeP2PDirectedDataReady") == 1 {
        rocReadyObservedAt = DispatchTime.now().uptimeNanoseconds
        break
    }
    if (number(snapshot, "NativeP2PDirectedDataStage") ?? 0) >= 8 { stop("Kernel ended before native UDP") }
    usleep(500)
}
guard number(snapshot, "NativeP2PDirectedDataStage") == 4,
      number(snapshot, "NativeP2PDirectedDataReady") == 1,
      rocReadyObservedAt != 0 else { stop("No matching ROC START window") }
let rxLease = matchedReturnBuild ?
    (build == "25G332-Test114" ? pollForTest114RxLease(initial: snapshot) :
                                checkPriorMatchedReturnLeaseOnce(snapshot)) : nil
if matchedReturnBuild && rxLease == nil {
    stop("Matching channel 6 kernel RX lease did not become valid within its original 100 ms window; no native UDP sent; do not retry")
}
if let rxLease {
    var nowUs: UInt64 = 0
    guard t110CurrentUptimeUs(&nowUs) == 0,
          nowUs >= rxLease.startUs, nowUs < rxLease.deadlineUs else {
        stop("Kernel RX lease expired before the one-shot native UDP; no UDP sent; do not retry")
    }
}
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
if matchedReturnBuild {
    if udpBytes != 8 {
        peerReturnStatus = "native_udp_send_not_accepted"
    } else if let peerReady, let rxLease,
              let peerAddress = peerIPv6 {
        let now = DispatchTime.now().uptimeNanoseconds
        let observedElapsedMs = now >= rocReadyObservedAt ?
            (now - rocReadyObservedAt) / 1_000_000 : 101
        let observedRemainingMs = observedElapsedMs < 100 ? 100 - observedElapsedMs : 0
        let peerRemainingMs = peerWindowRemainingMs(peerReady)
        let timeoutMs = min(UInt64(100), min(observedRemainingMs, peerRemainingMs))
        if timeoutMs == 0 {
            peerReturnStatus = "bounded_window_elapsed"
        } else {
            phase = "wait_matching_return"
            var seen: UInt32 = 0
            var rejected: UInt32 = 0
            var receiveError: Int32 = 0
            var elapsedUs: UInt64 = 0
            let receiveStatus = peerAddress.withUnsafeBufferPointer { peerBytes in
                source.withUnsafeBufferPointer { localBytes in
                    nonce.withUnsafeBufferPointer { nonceBytes in
                        t110WaitForMatchingReturn(fd, peerBytes.baseAddress!,
                            localBytes.baseAddress!, UInt32(index), nonceBytes.baseAddress!,
                            rxLease.deadlineUs, UInt32(timeoutMs), &seen, &rejected,
                            &receiveError, &elapsedUs)
                    }
                }
            }
            peerReturnDatagramsSeen = seen
            peerReturnDatagramsRejected = rejected
            peerReturnError = receiveError
            peerReturnElapsedUs = elapsedUs
            if receiveStatus == 1 {
                matchedPeerReturn = true
                ifnetDeliveryProven = true
                peerReturnStatus = "matched_nonce_delivered_to_awdl0_udp"
            } else if receiveStatus == 0 {
                peerReturnStatus = seen == 0 ? "no_peer_return_observed" :
                                               "no_matching_peer_return"
            } else {
                peerReturnStatus = "receive_error"
            }
        }
    } else {
        peerReturnStatus = "peer_evidence_unavailable"
    }
}
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
emit(["schema": 1, "mode": "explicit_run", "phase": phase, "build": build,
      "arm_may_have_changed": armMayHaveChanged, "arm_accepted": accepted,
      "native_udp_attempted": udpAttempted, "native_udp_bytes": udpBytes,
      "native_udp_errno": sendError, "diagnostics": diagnostics,
      "matched_peer_return_proven": matchedPeerReturn,
      "ifnet_delivery_proven": ifnetDeliveryProven,
      "peer_return_status": peerReturnStatus,
      "peer_return_datagrams_seen": peerReturnDatagramsSeen,
      "peer_return_datagrams_rejected": peerReturnDatagramsRejected,
      "peer_return_error": peerReturnError,
      "peer_return_elapsed_us": peerReturnElapsedUs,
      "rx_lease_poll": rxLeasePollTrace.jsonObject,
      "peer_receipt_proven": false, "radio_ack_proven": false, "airdrop_proven": false,
      "automatic_retry_allowed": false])
let complete = udpBytes == 8 && number(snapshot, "NativeP2PDirectedDataStage") == 8 &&
    number(snapshot, "NativeP2PDirectedDataResult") == 0 &&
    number(snapshot, "NativeP2PDirectedDataFirmwareAttemptSucceeded") == 1 &&
    number(snapshot, "NativeP2PDirectedDataResourcesAbsent") == 1
exit(complete ? 0 : 2)
