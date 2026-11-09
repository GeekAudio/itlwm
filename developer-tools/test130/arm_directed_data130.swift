// SPDX-License-Identifier: GPL-2.0-only
// Test130: exactly two ordered native UDP datagrams inside one original ROC.
// Argument-only by default. No retry, no ROC renewal, no channel change.
import Foundation
import IOKit
import Darwin
import CoreFoundation
import CryptoKit
import IORegistryBooleanFlag107
import Test114RxLease
import Test130TwoPacketGate

func emit130(_ value: [String: Any]) {
    guard let bytes = try? JSONSerialization.data(withJSONObject: value,
                                                   options: [.sortedKeys]) else { return }
    FileHandle.standardOutput.write(bytes)
    FileHandle.standardOutput.write(Data("\n".utf8))
}
func fail130(_ message: String, _ code: Int32 = 1) -> Never {
    var result: [String: Any] = ["schema": 1, "build": options["--expect-build"] ?? "",
        "phase": phase, "error": message, "arm_may_have_changed": armMayHaveChanged,
        "arm_accepted": accepted, "packet_count": 2,
        "native_udp_attempts": [udpAttempts[0], udpAttempts[1]],
        "peer_socket_matched": peerMatched,
        "peer_receipt_proven": false, "radio_ack_proven": false,
        "airdrop_proven": false, "automatic_retry_allowed": false]
    if let transition = armTransitionFailureSnapshot130 {
        result["arm_transition_snapshot"] = transition
    }
    if armMayHaveChanged, let postArmFinalizer130 {
        result["post_arm_cleanup_observation"] = postArmFinalizer130()
    }
    emit130(result)
    exit(code)
}
func matches130(_ value: String, _ pattern: String) -> Bool {
    value.range(of: pattern, options: .regularExpression) != nil
}
func number130(_ object: [String: Any], _ key: String) -> UInt64? {
    guard let number = object[key] as? NSNumber,
          CFGetTypeID(number) != CFBooleanGetTypeID() else { return nil }
    let value = number.doubleValue
    guard value.isFinite, value >= 0, value.rounded(.towardZero) == value,
          value < 18_446_744_073_709_551_616.0 else { return nil }
    return number.uint64Value
}
func armObservedValue130(_ object: [String: Any],
                         _ key: String) -> Test130ArmObservedValue {
    guard object.keys.contains(key) else { return .missing }
    guard let value = number130(object, key) else { return .malformed }
    return .value(value)
}
func armObservedReport130(_ value: Test130ArmObservedValue,
                          _ valueKey: String) -> [String: Any] {
    switch value {
    case .missing:
        return ["presence": "missing"]
    case .malformed:
        return ["presence": "malformed"]
    case let .value(number):
        return ["presence": "present", valueKey: number]
    }
}
func armTransitionReport130(_ snapshot: [String: Any],
                            stageSeenBefore: Bool,
                            packetCountSeenBefore: Bool,
                            runTokenMatches: Bool,
                            buildMatches: Bool,
                            outcome: Test130ArmTransitionOutcome)
    -> [String: Any] {
    var report: [String: Any] = [
        "run_token_matches": runTokenMatches,
        "build_matches": buildMatches,
        "stage_seen_before": stageSeenBefore,
        "stage_seen": outcome.stageSeen,
        "packet_count_seen_before": packetCountSeenBefore,
        "packet_count_seen": outcome.packetCountSeen
    ]
    report["stage"] = armObservedReport130(
        armObservedValue130(snapshot, "NativeP2PDirectedDataStage"), "value")
    report["packet_count"] = armObservedReport130(
        armObservedValue130(snapshot, "NativeP2PDirectedDataPacketCount"), "value")
    report["ready"] = armObservedReport130(
        armObservedValue130(snapshot, "NativeP2PDirectedDataReady"), "value")
    switch outcome.action {
    case let .reject(reason): report["decision"] = reason
    case .ready: report["decision"] = "ready"
    case .wait: report["decision"] = "wait"
    }
    return report
}
func number32_130(_ object: [String: Any], _ key: String) -> UInt32? {
    guard let value = number130(object, key), value <= UInt64(UInt32.max) else { return nil }
    return UInt32(value)
}
func flag130(_ object: [String: Any], _ key: String) -> Bool? {
    guard let value = number32_130(object, key), value <= 1 else { return nil }
    return value == 1
}
func hexBytes130(_ text: String, count: Int) -> Data? {
    guard text.count == count * 2, text == text.lowercased() else { return nil }
    var data = Data(); data.reserveCapacity(count)
    var index = text.startIndex
    for _ in 0..<count {
        let next = text.index(index, offsetBy: 2)
        guard let byte = UInt8(text[index..<next], radix: 16) else { return nil }
        data.append(byte); index = next
    }
    return data
}
func colonMac130(_ text: String) -> [UInt8]? {
    guard matches130(text, "^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}$") else { return nil }
    let bytes = text.split(separator: ":").compactMap { UInt8($0, radix: 16) }
    guard bytes.count == 6, bytes[0] & 1 == 0, bytes.contains(where: { $0 != 0 }) else { return nil }
    return bytes
}
func canonicalLinkLocal130(_ text: String) -> [UInt8]? {
    var address = in6_addr()
    guard inet_pton(AF_INET6, text, &address) == 1 else { return nil }
    let bytes = withUnsafeBytes(of: &address) { Array($0) }
    guard bytes.count == 16, bytes[0] == 0xfe, bytes[1] == 0x80,
          bytes[2..<8].allSatisfy({ $0 == 0 }), bytes[8..<16].contains(where: { $0 != 0 }) else { return nil }
    return bytes
}
func dataHex130(_ data: Data) -> String { data.map { String(format: "%02x", $0) }.joined() }
func hex130(_ bytes: [UInt8]) -> String { bytes.map { String(format: "%02x", $0) }.joined() }
func privateJSON130(_ path: String) -> (object: [String: Any], bytes: Data)? {
    guard path.hasPrefix("/") else { return nil }
    let descriptor = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW)
    guard descriptor >= 0 else { return nil }
    defer { close(descriptor) }
    var info = stat()
    guard fstat(descriptor, &info) == 0,
          (info.st_mode & mode_t(S_IFMT)) == mode_t(S_IFREG),
          (info.st_mode & 0o077) == 0, info.st_size > 0, info.st_size <= 8192,
          info.st_uid == getuid() || info.st_uid == 0 else { return nil }
    var bytes = Data(count: Int(info.st_size))
    let complete = bytes.withUnsafeMutableBytes { raw -> Bool in
        guard let base = raw.baseAddress else { return false }
        var offset = 0
        while offset < raw.count {
            let amount = read(descriptor, base.advanced(by: offset), raw.count - offset)
            if amount <= 0 { return false }
            offset += Int(amount)
        }
        return true
    }
    guard complete,
          let object = (try? JSONSerialization.jsonObject(with: bytes)) as? [String: Any] else { return nil }
    return (object, bytes)
}

struct PeerWindow130 {
    let expiresAt: Date
    let readyHash: String
    let contractHash: String
}
func validatePeerReady130(path: String, runToken: String, nonce0: Data,
                          nonce1: Data, localMAC: [UInt8], peerMAC: [UInt8],
                          localIPv6: [UInt8], peerIPv6: [UInt8]) -> PeerWindow130? {
    guard let (object, bytes) = privateJSON130(path) else { return nil }
    let required: Set<String> = ["schema", "event", "run_token", "nonces", "local_mac",
        "peer_mac", "local_ipv6", "peer_ipv6", "channel", "packet_count",
        "request_source_port", "request_destination_port", "reply_source_port",
        "reply_destination_port", "hop_limit", "payload_bytes", "echo_mode", "packets",
        "window_ms", "created_utc", "contract_identity_digest", "router_ready_sha256"]
    guard Set(object.keys) == required,
          object["schema"] as? String == "test130-openwrt-echo-coordinator-ready/v1",
          object["event"] as? String == "READY",
          object["run_token"] as? String == runToken,
          object["local_mac"] as? String == hex130(localMAC),
          object["peer_mac"] as? String == hex130(peerMAC),
          let readyLocalIPv6 = object["local_ipv6"] as? String,
          canonicalLinkLocal130(readyLocalIPv6) == localIPv6,
          let readyPeerIPv6 = object["peer_ipv6"] as? String,
          canonicalLinkLocal130(readyPeerIPv6) == peerIPv6,
          number130(object, "channel") == 6, number130(object, "packet_count") == 2,
          number130(object, "request_source_port") == 49153,
          number130(object, "request_destination_port") == 49152,
          number130(object, "reply_source_port") == 49152,
          number130(object, "reply_destination_port") == 49153,
          number130(object, "hop_limit") == 1, number130(object, "payload_bytes") == 8,
          object["echo_mode"] as? String == "ordered-exact-payload-once-per-packet",
          let packets = object["packets"] as? [[String: Any]], packets.count == 2,
          let nonces = object["nonces"] as? [String], nonces.count == 2,
          hexBytes130(nonces[0], count: 8) == nonce0,
          hexBytes130(nonces[1], count: 8) == nonce1,
          nonce0 != nonce1,
          let windowMs = number130(object, "window_ms"), windowMs > 0, windowMs <= 16_000,
          let timestamp = object["created_utc"] as? String,
          matches130(timestamp, "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\\.[0-9]{1,3}Z$"),
          let digest = object["contract_identity_digest"] as? String,
          matches130(digest, "^[0-9a-f]{64}$"),
          let readyHash = object["router_ready_sha256"] as? String,
          matches130(readyHash, "^[0-9a-f]{64}$") else { return nil }
    let packetKeys: Set<String> = ["slot", "nonce", "run_token", "local_mac", "peer_mac",
        "local_ipv6", "peer_ipv6", "reply_wifi_sequence", "reply_awdl_sequence"]
    for slot in 0..<2 {
        let packet = packets[slot]
        guard Set(packet.keys) == packetKeys,
              number130(packet, "slot") == UInt64(slot),
              packet["nonce"] as? String == nonces[slot],
              packet["run_token"] as? String == runToken,
              packet["local_mac"] as? String == hex130(localMAC),
              packet["peer_mac"] as? String == hex130(peerMAC),
              packet["local_ipv6"] as? String == object["local_ipv6"] as? String,
              packet["peer_ipv6"] as? String == object["peer_ipv6"] as? String,
              number130(packet, "reply_wifi_sequence") == UInt64(0x110 + slot),
              number130(packet, "reply_awdl_sequence") == UInt64(0x110 + slot) else { return nil }
    }
    let localPacked = Data(localIPv6).map { String(format: "%02x", $0) }.joined()
    let peerPacked = Data(peerIPv6).map { String(format: "%02x", $0) }.joined()
    let contract = "test130-echo/v1\n\(runToken)\n\(dataHex130(nonce0))\n\(dataHex130(nonce1))\n\(hex130(localMAC))\n\(hex130(peerMAC))\n\(localPacked)\n\(peerPacked)\n6,49153,49152,49152,49153,1,8,272,273\n"
    let expectedDigest = SHA256.hash(data: Data(contract.utf8)).map { String(format: "%02x", $0) }.joined()
    guard digest == expectedDigest else { return nil }
    let formatter = ISO8601DateFormatter()
    formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
    guard let created = formatter.date(from: timestamp) else { return nil }
    let age = Date().timeIntervalSince(created) * 1000
    let remaining = Double(windowMs) - age
    guard age >= 0, age <= 120_000, remaining >= 1_000, remaining <= 16_000 else { return nil }
    _ = bytes // The complete bounded private receipt was parsed and identity-bound.
    return PeerWindow130(expiresAt: Date().addingTimeInterval(remaining / 1000),
                         readyHash: readyHash, contractHash: digest)
}

struct RawSlot130 {
    let identityPresent: Bool
    let ready: Bool
    let packetSerial: UInt64
    let wifiSequence: UInt16
    let awdlSequence: UInt16
    let descriptorIndex: UInt32
    let ssn: UInt16
    let context: UInt32
    let power: UInt32
    let station: UInt32
    let roc: UInt32
    let deadlineUs: UInt64
    let doorbellUs: UInt64
    let txRspSeen: Bool
    let txRspSuccess: Bool
    let rawTxStatus: UInt16
    let txRspUs: UInt64
    let exactReplyPresent: Bool
    let exactReplyCaptured: Bool
    let exactReplyDelivered: Bool
    let exactReplyValid: Bool
    let exactReplyCaptureUs: UInt64
    let exactReplyInputUs: UInt64
    let ifindexInput: UInt32
    let resourcesAbsent: Bool
    let originDoorbellRecorded: Bool
    let originCompletionRecorded: Bool
}
func readRawSlot130(_ slot: UInt32, _ properties: [String: Any]) -> RawSlot130? {
    guard slot < 2 else { return nil }
    let prefix = "NativeP2PDirectedDataPacket\(slot)"
    guard let present = flag130(properties, prefix + "IdentityPresent"), present,
          let ready = flag130(properties, prefix + "Ready"),
          let serial = number130(properties, prefix + "PacketSerial"), serial > 0,
          let wifi = number130(properties, prefix + "WifiSequence"), wifi <= 0x0fff,
          let awdl = number130(properties, prefix + "AwdlSequence"), awdl <= 0xffff,
          let descriptor = number32_130(properties, prefix + "DescriptorIndex"),
          let ssn = number130(properties, prefix + "ExpectedNextSsn"), ssn <= 0x0fff,
          let context = number32_130(properties, prefix + "ContextGeneration"), context > 0,
          let power = number32_130(properties, prefix + "PowerGeneration"), power > 0,
          let station = number32_130(properties, prefix + "StationGeneration"), station > 0,
          let roc = number32_130(properties, prefix + "RocGeneration"), roc > 0,
          let deadline = number130(properties, prefix + "DeadlineUs"), deadline > 0,
          let doorbell = number130(properties, prefix + "DoorbellUs"),
          let txSeen = flag130(properties, prefix + "TxRspSeen"),
          let txSuccess = flag130(properties, prefix + "TxRspSuccess"),
          let rawStatus = number130(properties, prefix + "RawTxStatus"), rawStatus <= 0xffff,
          let txRspUs = number130(properties, prefix + "TxRspUs"),
          let exactPresent = flag130(properties, prefix + "ExactReplyPresent"),
          let exactCaptured = flag130(properties, prefix + "ExactReplyCaptured"),
          let exactDelivered = flag130(properties, prefix + "ExactReplyDelivered"),
          let exactValid = flag130(properties, prefix + "ExactReplyValid"),
          let exactCaptureUs = number130(properties, prefix + "ExactReplyCaptureUs"),
          let exactInputUs = number130(properties, prefix + "ExactReplyInputUs"),
          let ifindexInput = number32_130(properties, prefix + "IfindexInput"),
          let resourcesAbsent = flag130(properties, prefix + "ResourcesAbsent"),
          let originDoorbell = flag130(properties, prefix + "OriginDoorbellRecorded"),
          let originCompletion = flag130(properties, prefix + "OriginCompletionRecorded") else { return nil }
    return RawSlot130(identityPresent: present, ready: ready, packetSerial: serial,
        wifiSequence: UInt16(wifi), awdlSequence: UInt16(awdl),
        descriptorIndex: descriptor, ssn: UInt16(ssn), context: context,
        power: power, station: station, roc: roc, deadlineUs: deadline,
        doorbellUs: doorbell, txRspSeen: txSeen, txRspSuccess: txSuccess,
        rawTxStatus: UInt16(rawStatus), txRspUs: txRspUs,
        exactReplyPresent: exactPresent, exactReplyCaptured: exactCaptured,
        exactReplyDelivered: exactDelivered, exactReplyValid: exactValid,
        exactReplyCaptureUs: exactCaptureUs, exactReplyInputUs: exactInputUs,
        ifindexInput: ifindexInput,
        resourcesAbsent: resourcesAbsent, originDoorbellRecorded: originDoorbell,
        originCompletionRecorded: originCompletion)
}
func exactReply130(_ slot: UInt32, _ properties: [String: Any]) -> Test130ExactReplyReceipt? {
    let packetPrefix = "NativeP2PDirectedDataPacket\(slot)"
    guard let raw = readRawSlot130(slot, properties),
          let begin = number130(properties, packetPrefix + "ExactReplySnapshotBegin"), begin > 0,
          let end = number130(properties, packetPrefix + "ExactReplySnapshotEnd"),
          end == begin, (begin & 1) == 0,
          flag130(properties, packetPrefix + "ExactReplyPresent") == true,
          let slotValue = number32_130(properties, packetPrefix + "ExactReplySlot"),
          let ifindex = number32_130(properties, packetPrefix + "ExactReplyIfindex"),
          let context = number32_130(properties, packetPrefix + "ExactReplyContextGeneration"),
          let power = number32_130(properties, packetPrefix + "ExactReplyPowerGeneration"),
          let station = number32_130(properties, packetPrefix + "ExactReplyStationGeneration"),
          let roc = number32_130(properties, packetPrefix + "ExactReplyRocGeneration"),
          let ticket = number130(properties, packetPrefix + "ExactReplyTicketSerial"),
          let packet = number130(properties, packetPrefix + "ExactReplyPacketSerial"),
          let owner = number130(properties, packetPrefix + "ExactReplyOwnerSerial"),
          let run = number130(properties, packetPrefix + "ExactReplyRunSerial"),
          let incarnation = number130(properties, packetPrefix + "ExactReplyInterfaceIncarnation"),
          let doorbell = number130(properties, packetPrefix + "ExactReplyDoorbellUs"),
          let capture = number130(properties, packetPrefix + "ExactReplyCaptureUs"),
          let input = number130(properties, packetPrefix + "ExactReplyInputUs"),
          let schema = number32_130(properties, packetPrefix + "ExactReplySchemaVersion"), schema == 1,
          let captured = flag130(properties, packetPrefix + "ExactReplyCaptured"),
          let delivered = flag130(properties, packetPrefix + "ExactReplyDelivered"),
          let valid = flag130(properties, packetPrefix + "ExactReplyValid"),
          raw.exactReplyPresent, raw.exactReplyCaptured == captured,
          raw.exactReplyDelivered == delivered, raw.exactReplyValid == valid,
          raw.exactReplyCaptureUs == capture, raw.exactReplyInputUs == input,
          raw.ifindexInput == ifindex else { return nil }
    return Test130ExactReplyReceipt(snapshotSequence: begin, ticketSerial: ticket,
        packetSerial: packet,
        slot: slotValue, ownerSerial: owner, runSerial: run, ifindex: ifindex,
        interfaceIncarnation: incarnation, contextGeneration: context,
        powerGeneration: power, stationEpoch: station, rocEpoch: roc,
        doorbellUs: doorbell,
        captureUs: capture, inputUs: input, captured: captured,
        delivered: delivered, valid: valid)
}
func packetReceipt130(_ slot: UInt32, nonce: Data,
                      _ properties: [String: Any]) -> Test130PacketReceipt? {
    guard let raw = readRawSlot130(slot, properties),
          let exact = exactReply130(slot, properties) else { return nil }
    let localIndex = if_nametoindex("awdl0")
    guard exact.slot == slot, exact.packetSerial == raw.packetSerial,
          exact.ifindex == UInt32(localIndex) else { return nil }
    return Test130PacketReceipt(slot: slot, packetSerial: raw.packetSerial,
        nonce: nonce, wifiSequence: raw.wifiSequence, awdlSequence: raw.awdlSequence,
        descriptorIndex: raw.descriptorIndex, ssn: raw.ssn,
        ownerSerial: exact.ownerSerial, runSerial: exact.runSerial,
        ifindex: exact.ifindex, interfaceIncarnation: exact.interfaceIncarnation,
        contextGeneration: raw.context, powerGeneration: raw.power,
        stationEpoch: raw.station,
        rocEpoch: raw.roc, deadlineUs: raw.deadlineUs,
        doorbellUs: raw.doorbellUs, txRspSeen: raw.txRspSeen,
        txRspSuccess: raw.txRspSuccess, rawTxStatus: raw.rawTxStatus,
        txRspUs: raw.txRspUs,
        originDoorbellRecorded: raw.originDoorbellRecorded,
        originCompletionRecorded: raw.originCompletionRecorded,
        exactReply: exact,
        resourcesAbsent: raw.resourcesAbsent)
}
func packet1PreSendReady130(_ properties: [String: Any],
                            _ lease: Test114RxLeaseIdentity,
                            _ window: Test114RxLeaseWindow) -> Test130PacketSlotReady? {
    guard flag130(properties, "NativeP2PDirectedDataPacket1PreSendReady") == true,
          lease.contextGeneration <= UInt64(UInt32.max),
          lease.powerGeneration <= UInt64(UInt32.max),
          lease.stationGeneration <= UInt64(UInt32.max),
          lease.rocGeneration <= UInt64(UInt32.max),
          lease.deadlineUs == window.deadlineUs else { return nil }
    // HAL publishes this one-way authorization only while the slot is still
    // before its doorbell. The packet descriptor, SSN and sequences are not
    // required until the terminal receipt.
    return Test130PacketSlotReady(slot: 1, ready: true,
        contextGeneration: UInt32(lease.contextGeneration),
        powerGeneration: UInt32(lease.powerGeneration),
        stationEpoch: UInt32(lease.stationGeneration),
        rocEpoch: UInt32(lease.rocGeneration),
        deadlineUs: window.deadlineUs, doorbellIssued: false)
}

func waitForSecondGate130(nonce0: Data, nonce1: Data,
                          expectedRunToken: String, expectedBuild: String,
                          expectedWindow: Test114RxLeaseWindow,
                          expectedIdentity: Test114RxLeaseIdentity,
                          peerWindow expectedPeerWindow: PeerWindow130)
    -> (snapshot: [String: Any], receipt: Test130PacketReceipt?, gate: Test130GateOutcome?) {
    var latest = properties130()
    var lastReceipt: Test130PacketReceipt?
    var lastGate: Test130GateOutcome?
    while let now = currentUs130(), now >= expectedWindow.startUs,
          now < expectedWindow.deadlineUs, expectedPeerWindow.expiresAt.timeIntervalSinceNow > 0 {
        latest = properties130()
        guard latest["NativeP2PDirectedDataAcceptedRunToken"] as? String == expectedRunToken,
              latest["NativeTestBuild"] as? String == expectedBuild,
              number130(latest, "NativeP2PDirectedDataPacketCount") == 2,
              number130(latest, "NativeP2PDirectedDataStage").map({ $0 < 8 }) == true,
              let currentLease = test114InitialIdentity(latest,
                  requireMccOriginWitness: test114RequiresMccOriginWitness(for: expectedBuild)),
              currentLease.ownerSerial == expectedIdentity.ownerSerial,
              currentLease.contextGeneration == expectedIdentity.contextGeneration,
              currentLease.powerGeneration == expectedIdentity.powerGeneration,
              currentLease.stationGeneration == expectedIdentity.stationGeneration,
              currentLease.rocGeneration == expectedIdentity.rocGeneration,
              currentLease.deadlineUs == expectedWindow.deadlineUs else { break }
        if let first = packetReceipt130(0, nonce: nonce0, latest),
           let exact = first.exactReply,
           first.ownerSerial == currentLease.ownerSerial,
           UInt64(first.contextGeneration) == currentLease.contextGeneration,
           UInt64(first.powerGeneration) == currentLease.powerGeneration,
           UInt64(first.stationEpoch) == currentLease.stationGeneration,
           UInt64(first.rocEpoch) == currentLease.rocGeneration,
           first.deadlineUs == expectedWindow.deadlineUs,
           first.doorbellUs >= expectedWindow.startUs,
           exact.ownerSerial == currentLease.ownerSerial,
           UInt64(exact.contextGeneration) == currentLease.contextGeneration,
           UInt64(exact.powerGeneration) == currentLease.powerGeneration,
           UInt64(exact.stationEpoch) == currentLease.stationGeneration,
           UInt64(exact.rocEpoch) == currentLease.rocGeneration,
           let second = packet1PreSendReady130(latest, currentLease, expectedWindow),
           let checkUs = currentUs130() {
            lastReceipt = first
            let outcome = test130CanSendSecondPacket(Test130SecondPacketGateInput(
                first: first, peerSocketMatchedFirstNonce: true,
                secondReady: second, expectedSecondNonce: nonce1, nowUs: checkUs))
            lastGate = outcome
            if outcome.accepted { return (latest, first, outcome) }
        }
        usleep(200)
    }
    return (latest, lastReceipt, lastGate)
}

@_silgen_name("t110_prepare_existing_socket")
func t110PrepareExistingSocket130(_ fd: Int32, _ local: UnsafePointer<UInt8>,
    _ ifindex: UInt32, _ errorNumber: UnsafeMutablePointer<Int32>) -> Int32
@_silgen_name("t110_current_uptime_us")
func t110CurrentUptimeUs130(_ nowUs: UnsafeMutablePointer<UInt64>) -> Int32
@_silgen_name("t110_wait_for_matching_return")
func t110WaitForMatchingReturn130(_ fd: Int32, _ peer: UnsafePointer<UInt8>,
    _ local: UnsafePointer<UInt8>, _ ifindex: UInt32, _ nonce: UnsafePointer<UInt8>,
    _ kernelDeadlineUs: UInt64, _ timeoutMs: UInt32,
    _ seen: UnsafeMutablePointer<UInt32>, _ rejected: UnsafeMutablePointer<UInt32>,
    _ errorNumber: UnsafeMutablePointer<Int32>, _ elapsedUs: UnsafeMutablePointer<UInt64>) -> Int32

var phase = "arguments"
var armMayHaveChanged = false
var accepted = false
var udpAttempts = [false, false]
var udpBytes = [-1, -1]
var peerMatched = [false, false]
var peerSeen = [UInt32(0), UInt32(0)]
var peerRejected = [UInt32(0), UInt32(0)]
var peerError = [Int32(0), Int32(0)]
var peerElapsed = [UInt64(0), UInt64(0)]
var options: [String: String] = [:]
var postArmFinalizer130: (() -> [String: Any])?
var armTransitionFailureSnapshot130: [String: Any]?

let allowed: Set<String> = ["--expect-build", "--expect-uuid", "--peer-mac",
    "--local-ipv6", "--peer-ipv6", "--nonce", "--nonce-2", "--run-token",
    "--peer-ready-file"]
let arguments = Array(CommandLine.arguments.dropFirst())
let run = arguments.last == "--run"
let optionArguments = run ? Array(arguments.dropLast()) : arguments
var argIndex = 0
while argIndex < optionArguments.count {
    let key = optionArguments[argIndex]
    guard allowed.contains(key), argIndex + 1 < optionArguments.count,
          options[key] == nil else { fail130("invalid_or_duplicate_argument") }
    options[key] = optionArguments[argIndex + 1]
    argIndex += 2
}
let required: Set<String> = ["--expect-build", "--expect-uuid", "--peer-mac",
    "--local-ipv6", "--peer-ipv6", "--nonce", "--nonce-2", "--run-token",
    "--peer-ready-file"]
guard argIndex == optionArguments.count, Set(options.keys) == required,
      let build = options["--expect-build"], matches130(build, "^25G[0-9]+-Test130$"),
      let expectedUUID = options["--expect-uuid"],
      matches130(expectedUUID, "^[0-9A-F]{8}(-[0-9A-F]{4}){3}-[0-9A-F]{12}$"),
      let peerMACText = options["--peer-mac"], let peerMAC = colonMac130(peerMACText),
      let localIPv6Text = options["--local-ipv6"],
      let localIPv6 = canonicalLinkLocal130(localIPv6Text),
      let peerIPv6Text = options["--peer-ipv6"],
      let peerIPv6 = canonicalLinkLocal130(peerIPv6Text),
      localIPv6 != peerIPv6,
      let nonce0 = options["--nonce"].flatMap({ hexBytes130($0, count: 8) }),
      let nonce1 = options["--nonce-2"].flatMap({ hexBytes130($0, count: 8) }),
      nonce0.contains(where: { $0 != 0 }), nonce1.contains(where: { $0 != 0 }),
      nonce0 != nonce1,
      let runToken = options["--run-token"], matches130(runToken, "^[0-9a-f]{32}$"),
      runToken.contains(where: { $0 != "0" }),
      let readyPath = options["--peer-ready-file"] else {
    fail130("usage_or_invalid_test130_identity")
}
if !run {
    emit130(["schema": 1, "mode": "plan", "build": build,
        "packet_count": 2, "channel": 6, "roc_window_ms": 100,
        "native_udp_payload_bytes": 8, "peer_ready_required": true,
        "ordered_kernel_rx_required_before_second_send": true,
        "automatic_retry_allowed": false, "radio_ack_proven": false,
        "peer_receipt_proven": false, "airdrop_proven": false,
        "hardware_action": false, "arm_accepted": false])
    exit(0)
}
guard geteuid() == 0 else { fail130("explicit_run_requires_administrator") }
phase = "peer_ready"
guard let ready = privateJSON130(readyPath) else { fail130("private_peer_ready_unavailable") }

let loadedProcess = Process()
loadedProcess.executableURL = URL(fileURLWithPath: "/usr/bin/kmutil")
loadedProcess.arguments = ["showloaded", "--list-only", "--bundle-identifier", "org.geekaudio.AirportItlwm"]
let loadedPipe = Pipe(); loadedProcess.standardOutput = loadedPipe
loadedProcess.standardError = FileHandle.nullDevice
do { try loadedProcess.run() } catch { fail130("cannot_inspect_loaded_kext") }
loadedProcess.waitUntilExit()
let loadedText = String(data: loadedPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
let loadedRows = loadedText.split(separator: "\n").filter { $0.contains("org.geekaudio.AirportItlwm ") }
let loadedPattern = "org\\.geekaudio\\.AirportItlwm \\([^)]*\\) " + expectedUUID + "(?:\\s|$)"
guard loadedProcess.terminationStatus == 0, loadedRows.count == 1,
      matches130(String(loadedRows[0]), loadedPattern) else { fail130("loaded_uuid_mismatch") }

var iterator: io_iterator_t = 0
guard IOServiceGetMatchingServices(kIOMainPortDefault, IOServiceMatching("AirportItlwm"),
                                   &iterator) == KERN_SUCCESS else { fail130("no_airport_controller") }
var services: [io_service_t] = []
while true { let item = IOIteratorNext(iterator); if item == 0 { break }; services.append(item) }
IOObjectRelease(iterator)
defer { services.forEach { IOObjectRelease($0) } }
guard services.count == 1 else { fail130("expected_one_airport_controller") }
let service = services[0]
func properties130() -> [String: Any] {
    var all: Unmanaged<CFMutableDictionary>?
    guard IORegistryEntryCreateCFProperties(service, &all, kCFAllocatorDefault, 0) == KERN_SUCCESS,
          let dictionary = all?.takeRetainedValue() as? [String: Any] else { return [:] }
    return dictionary
}
func currentUs130() -> UInt64? {
    var value: UInt64 = 0
    return t110CurrentUptimeUs130(&value) == 0 ? value : nil
}
func canonicalEqual130(_ object: [String: Any], _ key: String, _ expected: UInt64) -> Bool {
    number130(object, key) == expected
}
func waitForTerminal130(maximumUs: UInt64 = 5_000_000) -> [String: Any] {
    let begin = DispatchTime.now().uptimeNanoseconds
    var snapshot = properties130()
    while DispatchTime.now().uptimeNanoseconds - begin < maximumUs {
        let stage = number130(snapshot, "NativeP2PDirectedDataStage")
        let outer = number130(snapshot, "NativeP2PProbeState")
        if (stage == 8 || stage == 9 || stage == 10) && (outer ?? 0) >= 7 { return snapshot }
        usleep(10_000)
        snapshot = properties130()
    }
    return snapshot
}
func parseFinalReceipt130(_ slot: UInt32, _ nonce: Data,
                          _ snapshot: [String: Any]) -> Test130PacketReceipt? {
    packetReceipt130(slot, nonce: nonce, snapshot)
}
func outerReleaseAccepted130(_ snapshot: [String: Any],
                             _ lease: Test114RxLeaseIdentity) -> Bool {
    guard number32_130(snapshot, "NativeP2PProbeAttempted") == 1,
          number32_130(snapshot, "NativeP2PProbeState") == 7,
          number32_130(snapshot, "NativeP2PProbeRemoveResult") == 0,
          number32_130(snapshot, "NativeP2PProbeResourceMayExist") == 0,
          number130(snapshot, "NativeP2PProbeContextGeneration") == lease.contextGeneration,
          number130(snapshot, "NativeP2PProbePowerGeneration") == lease.powerGeneration,
          number130(snapshot, "NativeP2PProbeStationGeneration") == lease.stationGeneration else { return false }
    return true
}
func packetJSON130(_ packet: Test130PacketReceipt?) -> [String: Any] {
    guard let packet, let exact = packet.exactReply else { return ["present": false] }
    return ["present": true, "slot": packet.slot, "packet_serial": packet.packetSerial,
        "nonce": dataHex130(packet.nonce), "wifi_sequence": packet.wifiSequence,
        "awdl_sequence": packet.awdlSequence, "descriptor_index": packet.descriptorIndex,
        "ssn": packet.ssn, "owner_serial": packet.ownerSerial, "run_serial": packet.runSerial,
        "ifindex": packet.ifindex, "interface_incarnation": packet.interfaceIncarnation,
        "context_generation": packet.contextGeneration, "station_generation": packet.stationEpoch,
        "roc_generation": packet.rocEpoch, "deadline_us": packet.deadlineUs,
        "doorbell_us": packet.doorbellUs, "tx_rsp_seen": packet.txRspSeen,
        "tx_rsp_success": packet.txRspSuccess, "raw_tx_status": packet.rawTxStatus,
        "tx_rsp_us": packet.txRspUs,
        "origin_doorbell_recorded": packet.originDoorbellRecorded,
        "origin_completion_recorded": packet.originCompletionRecorded,
        "resources_absent": packet.resourcesAbsent,
        "exact_reply": ["ticket_serial": exact.ticketSerial,
            "snapshot_sequence": exact.snapshotSequence,
            "packet_serial": exact.packetSerial, "slot": exact.slot,
            "owner_serial": exact.ownerSerial, "run_serial": exact.runSerial,
            "ifindex": exact.ifindex, "interface_incarnation": exact.interfaceIncarnation,
            "context_generation": exact.contextGeneration, "power_generation": exact.powerGeneration,
            "station_generation": exact.stationEpoch, "roc_generation": exact.rocEpoch,
            "doorbell_us": exact.doorbellUs, "capture_us": exact.captureUs,
            "input_us": exact.inputUs, "captured": exact.captured,
            "delivered": exact.delivered, "valid": exact.valid]]
}
func rawPacketJSON130(_ slot: UInt32, _ snapshot: [String: Any]) -> [String: Any] {
    guard let raw = readRawSlot130(slot, snapshot) else { return ["present": false, "slot": slot] }
    return ["present": true, "slot": slot, "identity_present": raw.identityPresent,
        "ready": raw.ready, "packet_serial": raw.packetSerial,
        "wifi_sequence": raw.wifiSequence, "awdl_sequence": raw.awdlSequence,
        "descriptor_index": raw.descriptorIndex, "ssn": raw.ssn,
        "context_generation": raw.context, "power_generation": raw.power,
        "station_generation": raw.station, "roc_generation": raw.roc,
        "deadline_us": raw.deadlineUs, "doorbell_us": raw.doorbellUs,
        "tx_rsp_seen": raw.txRspSeen, "tx_rsp_success": raw.txRspSuccess,
        "raw_tx_status": raw.rawTxStatus, "tx_rsp_us": raw.txRspUs,
        "exact_reply_present": raw.exactReplyPresent,
        "exact_reply_captured": raw.exactReplyCaptured,
        "exact_reply_delivered": raw.exactReplyDelivered,
        "exact_reply_valid": raw.exactReplyValid,
        "exact_reply_capture_us": raw.exactReplyCaptureUs,
        "exact_reply_input_us": raw.exactReplyInputUs,
        "ifindex_input": raw.ifindexInput,
        "resources_absent": raw.resourcesAbsent,
        "origin_doorbell_recorded": raw.originDoorbellRecorded,
        "origin_completion_recorded": raw.originCompletionRecorded]
}

postArmFinalizer130 = {
    let final = waitForTerminal130()
    var observation: [String: Any] = [
        "cleanup_ack": number32_130(final, "NativeP2PDirectedDataCleanupAck") == 1,
        "run_resources_absent": number32_130(final, "NativeP2PDirectedDataResourcesAbsent") == 1,
        "packet_receipts": [packetJSON130(packetReceipt130(0, nonce: nonce0, final)),
                            packetJSON130(packetReceipt130(1, nonce: nonce1, final))],
        "raw_packet_slots": [rawPacketJSON130(0, final), rawPacketJSON130(1, final)]
    ]
    if let stage = number130(final, "NativeP2PDirectedDataStage") { observation["stage"] = stage }
    if let result = number130(final, "NativeP2PDirectedDataResult") { observation["result"] = result }
    if let outer = number130(final, "NativeP2PProbeState") { observation["outer_probe_state"] = outer }
    return observation
}

phase = "preflight"
let before = properties130()
guard before["NativeTestBuild"] as? String == build,
      number130(before, "NativePowerReady") == 1,
      IORegistryBooleanFlag107.read(before["NativeP2PManualTrigger"]) == true,
      IORegistryBooleanFlag107.read(before["NativeP2PDirectedDataEnabled"]) == true,
      IORegistryBooleanFlag107.read(before["NativeP2PDirectedDataCompiled"]) == true,
      number32_130(before, "NativeP2PProbeAttempted") == 0,
      number130(before, "NativeP2PDirectedDataDoorbellIssued") ?? 0 == 0 else {
    fail130("profile_not_ready_or_one_shot_already_consumed")
}
let localIndex = if_nametoindex("awdl0")
guard localIndex > 0 else { fail130("awdl0_absent") }
var ifaddrsHead: UnsafeMutablePointer<ifaddrs>?
guard getifaddrs(&ifaddrsHead) == 0, let firstIfaddr = ifaddrsHead else { fail130("ifaddrs_unavailable") }
defer { freeifaddrs(ifaddrsHead) }
var localMAC: [UInt8]?
var cursor: UnsafeMutablePointer<ifaddrs>? = firstIfaddr
while let current = cursor?.pointee {
    cursor = current.ifa_next
    guard let name = current.ifa_name, String(cString: name) == "awdl0",
          let address = current.ifa_addr, address.pointee.sa_family == sa_family_t(AF_LINK) else { continue }
    let link = address.withMemoryRebound(to: sockaddr_dl.self, capacity: 1) { $0.pointee }
    guard link.sdl_alen == 6 else { continue }
    var bytes: [UInt8] = []
    withUnsafePointer(to: link.sdl_data) { pointer in
        let raw = UnsafeRawPointer(pointer).assumingMemoryBound(to: UInt8.self)
        for offset in 0..<6 { bytes.append(raw[Int(link.sdl_nlen) + offset]) }
    }
    if bytes.count == 6, bytes[0] & 1 == 0, bytes.contains(where: { $0 != 0 }) { localMAC = bytes; break }
}
guard let localMAC, localMAC != peerMAC else { fail130("awdl0_mac_invalid") }
let peerWindow = validatePeerReady130(path: readyPath, runToken: runToken,
    nonce0: nonce0, nonce1: nonce1, localMAC: localMAC, peerMAC: peerMAC,
    localIPv6: localIPv6, peerIPv6: peerIPv6)
guard let peerWindow, peerWindow.expiresAt.timeIntervalSinceNow >= 1 else {
    fail130("fresh_ordered_test130_peer_ready_missing")
}

phase = "socket"
var localAddress = in6_addr()
_ = localIPv6.withUnsafeBytes { bytes in memcpy(&localAddress, bytes.baseAddress!, 16) }
let fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP)
guard fd >= 0 else { fail130("native_udp_socket_failed") }
defer { close(fd) }
var interface = UInt32(localIndex); var hop: Int32 = 1; var loop: Int32 = 0
let socketOptions = setsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_IF, &interface,
    socklen_t(MemoryLayout.size(ofValue: interface))) == 0 &&
    setsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &hop,
    socklen_t(MemoryLayout.size(ofValue: hop))) == 0 &&
    setsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, &loop,
    socklen_t(MemoryLayout.size(ofValue: loop))) == 0
var local = sockaddr_in6(); local.sin6_len = UInt8(MemoryLayout<sockaddr_in6>.size)
local.sin6_family = sa_family_t(AF_INET6); local.sin6_port = UInt16(49153).bigEndian
local.sin6_addr = localAddress; local.sin6_scope_id = UInt32(localIndex)
let bound = withUnsafePointer(to: &local) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
    bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in6>.size))
} }
guard socketOptions, bound == 0, fcntl(fd, F_SETFL, O_NONBLOCK) == 0 else {
    fail130("native_udp_socket_binding_failed")
}
var receiveError: Int32 = 0
let prepared = localIPv6.withUnsafeBufferPointer {
    t110PrepareExistingSocket130(fd, $0.baseAddress!, UInt32(localIndex), &receiveError)
}
guard prepared == 0 else { fail130("same_socket_return_capture_prepare_failed") }
var destination = sockaddr_in6(); destination.sin6_len = UInt8(MemoryLayout<sockaddr_in6>.size)
destination.sin6_family = sa_family_t(AF_INET6); destination.sin6_port = UInt16(49152).bigEndian
_ = inet_pton(AF_INET6, "ff02::1", &destination.sin6_addr)
destination.sin6_scope_id = UInt32(localIndex)

phase = "arm"
armMayHaveChanged = true
let armStatus = IORegistryEntrySetCFProperties(service, [
    "NativeP2PDirectedDataOnce": true,
    "NativeP2PDirectedDataPeerMAC": Data(peerMAC),
    "NativeP2PDirectedDataLocalIPv6": Data(localIPv6),
    "NativeP2PDirectedDataNonce": nonce0,
    "NativeP2PDirectedDataRunToken": runToken,
    "NativeP2PDirectedDataPacketCount": UInt32(2),
    "NativeP2PDirectedDataPeerIPv6": Data(peerIPv6),
    "NativeP2PDirectedDataNonce2": nonce1
] as CFDictionary)
guard armStatus == KERN_SUCCESS else { fail130("arm_set_properties_failed_do_not_retry") }
var snapshot = properties130()
guard snapshot["NativeP2PDirectedDataAcceptedRunToken"] as? String == runToken else {
    fail130("arm_receipt_missing_do_not_retry")
}
accepted = true

phase = "roc_ready"
let readyEnd = DispatchTime.now().uptimeNanoseconds + 5_000_000_000
var transitionStageSeen = false
var transitionPacketCountSeen = false
var transitionReady = false
while DispatchTime.now().uptimeNanoseconds < readyEnd && !transitionReady {
    snapshot = properties130()
    let runTokenMatches =
        snapshot["NativeP2PDirectedDataAcceptedRunToken"] as? String == runToken
    let buildMatches = snapshot["NativeTestBuild"] as? String == build
    let transition = test130EvaluateArmTransition(Test130ArmTransitionInput(
        runTokenMatches: runTokenMatches, buildMatches: buildMatches,
        stage: armObservedValue130(snapshot, "NativeP2PDirectedDataStage"),
        packetCount: armObservedValue130(snapshot,
            "NativeP2PDirectedDataPacketCount"),
        ready: armObservedValue130(snapshot, "NativeP2PDirectedDataReady"),
        stageSeen: transitionStageSeen,
        packetCountSeen: transitionPacketCountSeen, deadlineExpired: false))
    switch transition.action {
    case let .reject(reason):
        armTransitionFailureSnapshot130 = armTransitionReport130(snapshot,
            stageSeenBefore: transitionStageSeen,
            packetCountSeenBefore: transitionPacketCountSeen,
            runTokenMatches: runTokenMatches, buildMatches: buildMatches,
            outcome: transition)
        fail130("arm_transition_\(reason)")
    case .ready:
        transitionReady = true
        armTransitionFailureSnapshot130 = nil
    case .wait:
        transitionStageSeen = transition.stageSeen
        transitionPacketCountSeen = transition.packetCountSeen
        usleep(500)
    }
}
if !transitionReady {
    snapshot = properties130()
    let runTokenMatches =
        snapshot["NativeP2PDirectedDataAcceptedRunToken"] as? String == runToken
    let buildMatches = snapshot["NativeTestBuild"] as? String == build
    let transition = test130EvaluateArmTransition(Test130ArmTransitionInput(
        runTokenMatches: runTokenMatches, buildMatches: buildMatches,
        stage: armObservedValue130(snapshot, "NativeP2PDirectedDataStage"),
        packetCount: armObservedValue130(snapshot,
            "NativeP2PDirectedDataPacketCount"),
        ready: armObservedValue130(snapshot, "NativeP2PDirectedDataReady"),
        stageSeen: transitionStageSeen,
        packetCountSeen: transitionPacketCountSeen, deadlineExpired: true))
    armTransitionFailureSnapshot130 = armTransitionReport130(snapshot,
        stageSeenBefore: transitionStageSeen,
        packetCountSeenBefore: transitionPacketCountSeen,
        runTokenMatches: runTokenMatches, buildMatches: buildMatches,
        outcome: transition)
    if case let .reject(reason) = transition.action {
        fail130("arm_transition_\(reason)")
    }
    fail130("arm_transition_timeout")
}
guard number130(snapshot, "NativeP2PDirectedDataStage") == 4,
      number130(snapshot, "NativeP2PDirectedDataReady") == 1,
      let rxWindow = test114InitialWindow(snapshot),
      let rxIdentity = test114InitialIdentity(snapshot,
          requireMccOriginWitness: test114RequiresMccOriginWitness(for: build)) else {
    fail130("channel6_100ms_rx_lease_missing")
}
let leasePoll = test114PollRxLease(initial: snapshot, expectedRunToken: runToken,
    expectedBuild: build, readProperties: { properties130() },
    monotonicUs: { currentUs130() }, sleepMicroseconds: { usleep($0) },
    maximumChecks: 128,
    requireMccOriginWitness: test114RequiresMccOriginWitness(for: build))
guard leasePoll.window == rxWindow,
      leasePoll.trace.lastCheck?.valid == true,
      let nowBeforeFirst = currentUs130(), nowBeforeFirst >= rxWindow.startUs,
      nowBeforeFirst < rxWindow.deadlineUs else {
    fail130("open_rx_lease_or_global_directed_data_ready_missing")
}

func sendOnce130(_ slot: Int, _ nonce: Data) -> Bool {
    guard slot >= 0 && slot < 2, let now = currentUs130(),
          now < rxWindow.deadlineUs, peerWindow.expiresAt.timeIntervalSinceNow > 0 else { return false }
    let elapsed = now >= rxWindow.startUs ? now - rxWindow.startUs : 100_001
    let rocMs = elapsed < 100_000 ? UInt32((100_000 - elapsed) / 1000) : 0
    let peerMs = UInt32(max(0, peerWindow.expiresAt.timeIntervalSinceNow * 1000))
    let timeout = min(UInt32(100), min(rocMs, peerMs))
    guard timeout > 0 else { return false }
    udpAttempts[slot] = true
    udpBytes[slot] = nonce.withUnsafeBytes { bytes in
        withUnsafePointer(to: &destination) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                sendto(fd, bytes.baseAddress!, 8, MSG_DONTWAIT, $0,
                       socklen_t(MemoryLayout<sockaddr_in6>.size))
            }
        }
    }
    guard udpBytes[slot] == 8 else { return false }
    var seen: UInt32 = 0; var rejected: UInt32 = 0
    var error: Int32 = 0; var waitUs: UInt64 = 0
    let receiveStatus = peerIPv6.withUnsafeBufferPointer { peerBytes in
        localIPv6.withUnsafeBufferPointer { localBytes in
            nonce.withUnsafeBytes { nonceBytes in
                guard let nonceBase = nonceBytes.baseAddress?.assumingMemoryBound(to: UInt8.self) else {
                    return Int32(-1)
                }
                return t110WaitForMatchingReturn130(fd, peerBytes.baseAddress!, localBytes.baseAddress!,
                    UInt32(localIndex), nonceBase, rxWindow.deadlineUs,
                    timeout, &seen, &rejected, &error, &waitUs)
            }
        }
    }
    peerSeen[slot] = seen; peerRejected[slot] = rejected
    peerError[slot] = error; peerElapsed[slot] = waitUs
    peerMatched[slot] = receiveStatus == 1
    return peerMatched[slot]
}

phase = "packet0_once"
let firstReturn = sendOnce130(0, nonce0)
var secondSendGate: [String: Any] = ["accepted": false,
                                     "first_socket_nonce_return": firstReturn]
if firstReturn {
    let gateObservation = waitForSecondGate130(nonce0: nonce0, nonce1: nonce1,
        expectedRunToken: runToken, expectedBuild: build,
        expectedWindow: rxWindow, expectedIdentity: rxIdentity,
        peerWindow: peerWindow)
    snapshot = gateObservation.snapshot
    if let outcome = gateObservation.gate, gateObservation.receipt != nil {
        secondSendGate = ["accepted": outcome.accepted, "failures": outcome.failures]
        if outcome.accepted {
        phase = "packet1_once"
        _ = sendOnce130(1, nonce1)
        }
    } else {
        secondSendGate = ["accepted": false,
                          "reason": "first_exact_receipt_or_second_slot_not_ready_before_deadline"]
    }
} else {
    secondSendGate = ["accepted": false,
                      "reason": "first_nonce_return_missing"]
}

phase = "terminal_cleanup"
snapshot = waitForTerminal130()
let firstFinal = parseFinalReceipt130(0, nonce0, snapshot)
let secondFinal = parseFinalReceipt130(1, nonce1, snapshot)
let peerBooleans = peerMatched
let cleanupAck = number32_130(snapshot, "NativeP2PDirectedDataCleanupAck") == 1
let resourcesAbsent = number32_130(snapshot, "NativeP2PDirectedDataResourcesAbsent") == 1
let outerReleased = outerReleaseAccepted130(snapshot, rxIdentity)
let gate = test130EvaluateTerminal(expectedNonces: [nonce0, nonce1],
    packets: [firstFinal, secondFinal].compactMap { $0 },
    peerSocketMatchedNonces: peerBooleans, cleanupAck: cleanupAck,
    runResourcesAbsent: resourcesAbsent, outerReleaseAccepted: outerReleased,
    automaticRetryCount: 0)
let stage = number32_130(snapshot, "NativeP2PDirectedDataStage")
let result = number32_130(snapshot, "NativeP2PDirectedDataResult")
let runMatches = accepted && snapshot["NativeP2PDirectedDataAcceptedRunToken"] as? String == runToken &&
                 snapshot["NativeTestBuild"] as? String == build
let completed = stage == 8 && result == 0 && runMatches
let allPassed = gate.accepted && completed
var diagnostics: [String: Any] = [:]
for key in ["Stage", "Result", "PacketCount", "CurrentSlot", "CleanupAck", "ResourcesAbsent"] {
    if let value = number130(snapshot, "NativeP2PDirectedData" + key) { diagnostics[key] = value }
}
emit130(["schema": 1, "build": build, "expected_uuid": expectedUUID,
    "run_token": runToken, "run_identity_matches": runMatches,
    "arm_may_have_changed": armMayHaveChanged, "arm_accepted": accepted,
    "packet_count": 2, "native_udp_attempted": udpAttempts.contains(true),
    "native_udp_bytes": udpBytes, "peer_socket_matched": peerMatched,
    "peer_datagrams_seen": peerSeen, "peer_datagrams_rejected": peerRejected,
    "peer_receive_error": peerError, "peer_receive_elapsed_us": peerElapsed,
    "second_send_gate": secondSendGate,
    "packet_receipts": [packetJSON130(firstFinal), packetJSON130(secondFinal)],
    "raw_packet_slots": [rawPacketJSON130(0, snapshot), rawPacketJSON130(1, snapshot)],
    "tx_completion_observed": [readRawSlot130(0, snapshot)?.txRspSeen ?? false,
                               readRawSlot130(1, snapshot)?.txRspSeen ?? false],
    "firmware_attempt_succeeded": [readRawSlot130(0, snapshot)?.txRspSuccess ?? false,
                                    readRawSlot130(1, snapshot)?.txRspSuccess ?? false],
    "matched_peer_return_proven": peerMatched,
    "ifnet_delivery_proven": [firstFinal?.exactReply?.delivered ?? false,
                               secondFinal?.exactReply?.delivered ?? false],
    "cleanup_ack": cleanupAck, "run_resources_absent": resourcesAbsent,
    "outer_release_accepted": outerReleased, "terminal_gate_accepted": gate.accepted,
    "terminal_gate_failures": gate.failures, "directed_exercise_completed": completed,
    "accepted": allPassed, "diagnostics": diagnostics,
    "peer_receipt_proven": false, "radio_ack_proven": false,
    "airdrop_proven": false, "automatic_retry_allowed": false])
exit(allPassed ? 0 : 5)
