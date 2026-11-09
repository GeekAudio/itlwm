#!/usr/bin/env swift
import Foundation
import IOKit
import CoreFoundation

private let expectedCandidate = "25G416-Test134"
private let uuidPattern = "^[0-9A-F]{8}(-[0-9A-F]{4}){3}-[0-9A-F]{12}$"
private let successStage = 6
private let quarantineStage = 7
private let probeTerminalStates: Set<Int64> = [7, 8, 9, 10]
private let deadlineSeconds: TimeInterval = 20

private let admissionKeys = [
    "Stage", "OperationResult", "CleanupResult", "StationAddAck",
    "QueueConfiguredUninstalled", "NeverDoorbelled", "ResourcesAbsent",
    "OldLeaseUnchanged", "Generation", "StationSerial", "QueueSerial",
].map { "NativeP2PMulticastAdmission" + $0 }
private let allocationSerialKeys = [admissionKeys[9], admissionKeys[10]]

private let probeKeys = [
    "NativeP2PProbeAttempted", "NativeP2PProbeState",
    "NativeP2PProbeResourceMayExist", "NativeP2PProbeRemoveResult",
    "NativeP2PProbeContextGeneration", "NativeP2PProbePowerGeneration",
]

private let rocKeys = [
    "NativeP2PRocStage", "NativeP2PRocGeneration", "NativeP2PRocObserved",
    "NativeP2PRocStartSeen", "NativeP2PRocEndSeen", "NativeP2PRocUnknown",
]
private let rocSessionKeys = [
    "NativeP2PRocObserved", "NativeP2PRocStartSeen",
    "NativeP2PRocEndSeen", "NativeP2PRocUnknown",
]

private let macRemoveAckKey = "NativeP2PMulticastAdmissionMacRemoveAckAccepted"
private let macAckIdentityKeys = [
    "NativeP2PMulticastAdmissionMacRemoveAckExpectedP2PEpoch",
    "NativeP2PMulticastAdmissionMacRemoveAckExpectedDriverGeneration",
    "NativeP2PMulticastAdmissionMacRemoveAckExpectedRocToken",
]
private let prepareWitnessValidKey = "NativeP2PMulticastAdmissionPrepareWitnessValid"
private let prepareRocTokenKey = "NativeP2PMulticastAdmissionPrepareExpectedRocToken"
private let rocAbortAckKey = "NativeP2PMulticastAdmissionRocAbortAcknowledged"

private let enabledFlags = [
    "NativeP2PProbe", "NativeP2PRocProbe", "NativeP2PTxProbe",
    "NativeP2PManualTrigger", "NativeAwdlResidentEnabled",
    "NativeP2PMulticastAdmissionEnabled",
]

private let disabledFlags = [
    "NativeP2PAwdlPsfObservationOnly", "NativeP2PAwdlMifFollowup",
    "NativeP2PGp2Observation", "NativeAwdlInitObservationOnly",
    "NativeAwdlLifecycleObservationOnly", "NativeAwdlTxEvidenceEnabled",
    "NativeAwdlDiscoveryExperimentEnabled",
    "NativeAwdlDiscoveryMifCurrentSlotEnabled",
    "NativeAwdlDiscoveryCurrentAwFallbackEnabled",
    "NativeAwdlDiscoveryRxInputEnabled", "NativeP2PRx149ObservationOnly",
    "NativeP2PRx149DataInputExperiment", "NativeP2PDirectedPrepareEnabled",
    "NativeP2PDirectedDataEnabled",
]

private let zeroTxCounters = [
    "NativeP2PTxProbeEverDoorbelled",
    "NativeP2PAwdlActionFramesSubmitted",
    "NativeP2PAwdlPsfFrameSubmitted",
    "NativeP2PAwdlMifFrameSubmitted",
    "NativeP2PAwdlMifBootstrapSubmitted",
]

private struct Options {
    let expectedBuild: String
    let expectedUUID: String
    let armed: Bool
}

private func failUsage(_ message: String) -> Never {
    FileHandle.standardError.write(Data((message + "\n").utf8))
    exit(2)
}

private func parseOptions() -> Options {
    let args = Array(CommandLine.arguments.dropFirst())
    guard args.count == 4 || args.count == 5,
          args[0] == "--expect-build",
          args[2] == "--expect-uuid" else {
        failUsage("Usage: arm_multicast_admission.swift --expect-build 25G416-Test134 --expect-uuid UUID [--arm]")
    }
    let build = args[1]
    let uuid = args[3]
    guard build == expectedCandidate else {
        failUsage("Expected build must be 25G416-Test134; no IOKit changes made.")
    }
    guard uuid.range(of: uuidPattern, options: .regularExpression) != nil else {
        failUsage("Expected UUID must be uppercase Mach-O UUID; no IOKit changes made.")
    }
    let armed = args.count == 5
    if armed && args[4] != "--arm" {
        failUsage("Only --arm is accepted after the expected identity; no IOKit changes made.")
    }
    return Options(expectedBuild: build, expectedUUID: uuid, armed: armed)
}

private func loadedUUIDs() -> [String]? {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/usr/bin/kmutil")
    process.arguments = ["showloaded", "--list-only"]
    let output = Pipe()
    process.standardOutput = output
    process.standardError = FileHandle.nullDevice
    do {
        try process.run()
    } catch {
        return nil
    }
    let bytes = output.fileHandleForReading.readDataToEndOfFile()
    process.waitUntilExit()
    guard process.terminationStatus == 0,
          let text = String(data: bytes, encoding: .utf8),
          let regex = try? NSRegularExpression(
            pattern: "org\\.geekaudio\\.AirportItlwm \\([^)]*\\) ([0-9A-F-]{36})") else {
        return nil
    }
    let range = NSRange(text.startIndex..., in: text)
    return regex.matches(in: text, range: range).compactMap { match in
        guard let uuidRange = Range(match.range(at: 1), in: text) else { return nil }
        return String(text[uuidRange])
    }
}

private func matchingServices() -> [io_service_t]? {
    var iterator: io_iterator_t = 0
    guard IOServiceGetMatchingServices(kIOMainPortDefault,
        IOServiceMatching("AirportItlwm"), &iterator) == KERN_SUCCESS else {
        return nil
    }
    var services: [io_service_t] = []
    while true {
        let service = IOIteratorNext(iterator)
        if service == 0 { break }
        services.append(service)
    }
    IOObjectRelease(iterator)
    return services
}

private func cfProperty(_ service: io_service_t, _ key: String) -> Any? {
    guard let value = IORegistryEntryCreateCFProperty(service, key as CFString,
        kCFAllocatorDefault, 0) else { return nil }
    return value.takeRetainedValue()
}

private func number(_ service: io_service_t, _ key: String) -> Int64? {
    guard let value = cfProperty(service, key) as? NSNumber,
          CFGetTypeID(value) != CFBooleanGetTypeID() else { return nil }
    return value.int64Value
}

private func flag(_ service: io_service_t, _ key: String) -> Bool? {
    guard let value = cfProperty(service, key) else { return nil }
    let object = value as CFTypeRef
    guard CFGetTypeID(object) == CFBooleanGetTypeID() else { return nil }
    return CFBooleanGetValue((object as! CFBoolean))
}

private func serializableValue(_ value: Any?) -> Any {
    guard let value else { return NSNull() }
    if let number = value as? NSNumber {
        if CFGetTypeID(number) == CFBooleanGetTypeID() {
            return number.boolValue
        }
        return number.int64Value
    }
    if let string = value as? String { return string }
    return NSNull()
}

private func unsigned64Value(_ value: Any?) -> UInt64? {
    if let value = value as? UInt64 { return value }
    if let value = value as? Int64 { return UInt64(bitPattern: value) }
    guard let number = value as? NSNumber,
          CFGetTypeID(number) != CFBooleanGetTypeID() else { return nil }
    return number.uint64Value
}

private func snapshot(_ service: io_service_t) -> [String: Any] {
    let keys = Array(Set([
        "NativeTestBuild", "NativePowerReady", "NativeAwdlResidentEnabled",
        "NativeP2PProbe", "NativeP2PRocProbe", "NativeP2PTxProbe",
        "NativeP2PManualTrigger", "NativeP2PMulticastAdmissionEnabled",
        "NativeP2PManualArmed", "NativeP2PProbeBlocked",
        "NativeP2PProbeAddResult", "NativeP2PProbeRemoveResult",
        "NativeAwdlDiscoveryMacRemoveAckAccepted",
        macRemoveAckKey, prepareWitnessValidKey, prepareRocTokenKey,
        rocAbortAckKey,
    ] + enabledFlags + disabledFlags + zeroTxCounters + admissionKeys +
        probeKeys + rocKeys + macAckIdentityKeys))
    var values: [String: Any] = [:]
    for key in keys {
        let property = cfProperty(service, key)
        if allocationSerialKeys.contains(key),
           let serial = unsigned64Value(property) {
            values[key] = serial
        } else {
            values[key] = serializableValue(property)
        }
    }
    return values
}

private func currentIdentityProblems(_ service: io_service_t,
                                    options: Options,
                                    loaded: [String]?) -> [String] {
    var problems: [String] = []
    guard let loaded, loaded.count == 1, loaded[0] == options.expectedUUID else {
        problems.append("loaded_uuid")
        return problems
    }
    if cfProperty(service, "NativeTestBuild") as? String != options.expectedBuild {
        problems.append("build_tag")
    }
    guard let power = number(service, "NativePowerReady"), power == 1 else {
        problems.append("power_ready")
        return problems
    }
    for key in enabledFlags where flag(service, key) != true {
        problems.append(key)
    }
    for key in disabledFlags where flag(service, key) != false {
        problems.append(key)
    }
    for key in zeroTxCounters where number(service, key) != 0 {
        problems.append(key)
    }
    for key in admissionKeys where number(service, key) == nil {
        problems.append(key + "_missing")
    }
    for key in [prepareWitnessValidKey, prepareRocTokenKey,
                rocAbortAckKey] + macAckIdentityKeys
        where number(service, key) == nil {
        problems.append(key + "_missing")
    }
    if number(service, admissionKeys[0]) != 0 {
        problems.append("admission_stage_not_idle")
    }
    for key in admissionKeys.dropFirst(8) where number(service, key) != 0 {
        problems.append(key + "_old_identity")
    }
    if number(service, "NativeP2PManualArmed") != 0 {
        problems.append("manual_arm_not_idle")
    }
    if number(service, "NativeP2PProbeAttempted") != 0 {
        problems.append("probe_already_attempted")
    }
    if number(service, "NativeP2PProbeResourceMayExist") != 0 {
        problems.append("old_probe_resource_may_exist")
    }
    for key in rocKeys where number(service, key) == nil {
        problems.append(key + "_missing")
    }
    for key in ["NativeP2PRocObserved", "NativeP2PRocStartSeen",
                "NativeP2PRocEndSeen", "NativeP2PRocUnknown"] {
        if number(service, key) != 0 { problems.append(key + "_not_idle") }
    }
    return Array(Set(problems)).sorted()
}

private func sessionSubmitted(_ values: [String: Any]) -> Bool? {
    guard let observed = values["NativeP2PRocObserved"] as? Int64,
          let started = values["NativeP2PRocStartSeen"] as? Int64,
          let ended = values["NativeP2PRocEndSeen"] as? Int64,
          let unknown = values["NativeP2PRocUnknown"] as? Int64 else { return nil }
    if unknown != 0 { return nil }
    return observed != 0 || started != 0 || ended != 0
}

private func noDataDoorbell(_ values: [String: Any]) -> Bool? {
    var observed = false
    for key in zeroTxCounters {
        guard let value = values[key] as? Int64 else { return nil }
        if value != 0 { observed = true }
    }
    return !observed
}

private func noDataDoorbellInWindow(_ initial: [String: Any],
                                    _ final: [String: Any]) -> Bool? {
    guard noDataDoorbell(initial) == true else { return nil }
    return noDataDoorbell(final)
}

private func rocSessionUnchanged(_ before: [String: Any],
                                _ after: [String: Any]) -> Bool {
    rocSessionKeys.allSatisfy { key in
        guard let initial = before[key] as? Int64,
              let final = after[key] as? Int64 else { return false }
        return initial == 0 && final == 0
    }
}

private func terminalSnapshot(_ values: [String: Any]) -> Bool {
    guard let stage = values[admissionKeys[0]] as? Int64,
          stage == Int64(successStage) || stage == Int64(quarantineStage),
          let probeAttempted = values["NativeP2PProbeAttempted"] as? Int64,
          probeAttempted == 1,
          let probeState = values["NativeP2PProbeState"] as? Int64,
          probeTerminalStates.contains(probeState) else { return false }
    if stage == Int64(quarantineStage) { return true }
    return admissionKeys.allSatisfy { values[$0] is Int64 } &&
        [macRemoveAckKey, prepareWitnessValidKey, prepareRocTokenKey,
         rocAbortAckKey].allSatisfy { values[$0] is Int64 } &&
        macAckIdentityKeys.allSatisfy { values[$0] is Int64 } &&
        ["NativeP2PProbeResourceMayExist", "NativeP2PProbeRemoveResult",
         "NativeP2PProbeContextGeneration", "NativeP2PProbePowerGeneration"]
            .allSatisfy { values[$0] is Int64 } &&
        zeroTxCounters.allSatisfy { values[$0] is Int64 } &&
        rocSessionKeys.allSatisfy { values[$0] is Int64 }
}

private func admissionProof(_ values: [String: Any],
                            initial: [String: Any],
                            expectedBuild: String,
                            expectedUUID: String) -> [String: Any] {
    let stage = values[admissionKeys[0]] as? Int64
    let operation = values[admissionKeys[1]] as? Int64
    let cleanup = values[admissionKeys[2]] as? Int64
    let stationAck = values[admissionKeys[3]] as? Int64
    let queueAck = values[admissionKeys[4]] as? Int64
    let neverDoorbelled = values[admissionKeys[5]] as? Int64
    let resourcesAbsent = values[admissionKeys[6]] as? Int64
    let oldLeaseUnchanged = values[admissionKeys[7]] as? Int64
    let generation = values[admissionKeys[8]] as? Int64
    let stationSerial = unsigned64Value(values[admissionKeys[9]])
    let queueSerial = unsigned64Value(values[admissionKeys[10]])
    let probeState = values["NativeP2PProbeState"] as? Int64
    let probeAttempted = values["NativeP2PProbeAttempted"] as? Int64
    let probeResources = values["NativeP2PProbeResourceMayExist"] as? Int64
    let probeRemoveResult = values["NativeP2PProbeRemoveResult"] as? Int64
    let probeGeneration = values["NativeP2PProbeContextGeneration"] as? Int64
    let probePowerGeneration = values["NativeP2PProbePowerGeneration"] as? Int64
    let ack = values[macRemoveAckKey] as? Int64
    let ackEpoch = values[macAckIdentityKeys[0]] as? Int64
    let ackDriverGeneration = values[macAckIdentityKeys[1]] as? Int64
    let ackRocToken = values[macAckIdentityKeys[2]] as? Int64
    let prepareValid = values[prepareWitnessValidKey] as? Int64
    let prepareRocToken = values[prepareRocTokenKey] as? Int64
    let rocAbortAck = values[rocAbortAckKey] as? Int64
    let rocUnchanged = rocSessionUnchanged(initial, values)
    let noSession = sessionSubmitted(values) == false && rocUnchanged
    let noDoorbell = noDataDoorbellInWindow(initial, values)
    let rocAbsent: Bool? = rocUnchanged ? sessionSubmitted(values).map { !$0 } : nil
    let loadedMatches = values["loaded_uuid_matches"] as? Bool == true &&
        values["NativeTestBuild"] as? String == expectedBuild
    let probeClean = probeAttempted == 1 &&
        (probeState == 7 || probeState == 10) &&
        probeResources == 0 && probeRemoveResult == 0 && ack == 1
    let exactGeneration = generation != nil && generation! > 0 &&
        probeGeneration == generation && probePowerGeneration != nil &&
        probePowerGeneration! > 0 &&
        ackEpoch == generation && ackDriverGeneration == probePowerGeneration &&
        ackRocToken == prepareRocToken && prepareRocToken != nil &&
        prepareValid == 1 && rocAbortAck == 1
    let commonCleanup = stage == Int64(successStage) && cleanup == 0 &&
        resourcesAbsent == 1 && oldLeaseUnchanged == 1 && probeClean && noSession
    let success = commonCleanup && probeState == 7 && operation == 0 && stationAck == 1 &&
        queueAck == 1 && neverDoorbelled == 1 && exactGeneration &&
        (stationSerial ?? 0) != 0 && (queueSerial ?? 0) != 0 && loadedMatches &&
        noDoorbell == true
    let cleanFailure = commonCleanup && probeState == 10 &&
        operation != nil && operation != 0 && noDoorbell == true
    let status: String
    if success {
        status = "admission_and_cleanup_proven"
    } else if stage == Int64(quarantineStage) {
        status = "quarantined_or_resources_uncertain"
    } else if cleanFailure {
        status = "clean_failure"
    } else {
        status = "terminal_receipt_incomplete"
    }
    return [
        "status": status,
        "expected_uuid": expectedUUID,
        "expected_uuid_matches_loaded": loadedMatches,
        "stage": stage.map { Int($0) } as Any? ?? NSNull(),
        "operation_result": operation as Any? ?? NSNull(),
        "cleanup_result": cleanup as Any? ?? NSNull(),
        "station_add_ack": stationAck as Any? ?? NSNull(),
        "queue_configured_uninstalled": queueAck as Any? ?? NSNull(),
        "never_doorbelled": neverDoorbelled as Any? ?? NSNull(),
        "resources_absent": resourcesAbsent as Any? ?? NSNull(),
        "old_lease_unchanged": oldLeaseUnchanged as Any? ?? NSNull(),
        "generation": generation as Any? ?? NSNull(),
        "station_serial": stationSerial as Any? ?? NSNull(),
        "queue_serial": queueSerial as Any? ?? NSNull(),
        "outer_probe_state": probeState as Any? ?? NSNull(),
        "outer_probe_attempted": probeAttempted as Any? ?? NSNull(),
        "outer_resources_may_exist": probeResources as Any? ?? NSNull(),
        "outer_remove_result": probeRemoveResult as Any? ?? NSNull(),
        "mac_remove_ack_accepted": ack as Any? ?? NSNull(),
        "mac_remove_ack_expected_p2p_epoch": ackEpoch as Any? ?? NSNull(),
        "mac_remove_ack_expected_driver_generation": ackDriverGeneration as Any? ?? NSNull(),
        "mac_remove_ack_expected_roc_token": ackRocToken as Any? ?? NSNull(),
        "prepare_witness_valid": prepareValid as Any? ?? NSNull(),
        "prepare_expected_roc_token": prepareRocToken as Any? ?? NSNull(),
        "roc_abort_acknowledged": rocAbortAck as Any? ?? NSNull(),
        "roc_absent": rocAbsent as Any? ?? NSNull(),
        "roc_session_observed": sessionSubmitted(values) as Any? ?? NSNull(),
        "roc_session_indicators_unchanged": rocUnchanged,
        "data_doorbell_issued": noDoorbell.map { !$0 } as Any? ?? NSNull(),
        "radio_transmit_proven": false,
        "session_submitted": sessionSubmitted(values) as Any? ?? NSNull(),
        "profile_intent": [
            "multicast_resource_admission_only": true,
            "session_required": false,
            "data_submission_required": false,
        ],
        "scope": "Firmware station/queue resource admission and cleanup only; no ROC session, frame transmission, peer receipt, or AirDrop proof.",
    ]
}

private func proofFixture() -> (initial: [String: Any], final: [String: Any]) {
    var initial: [String: Any] = [:]
    for key in admissionKeys + probeKeys + rocKeys + macAckIdentityKeys +
        [macRemoveAckKey, prepareWitnessValidKey, prepareRocTokenKey,
         rocAbortAckKey] + zeroTxCounters {
        initial[key] = Int64(0)
    }
    initial["NativeP2PProbeAttempted"] = Int64(0)
    initial["NativeP2PProbeResourceMayExist"] = Int64(0)
    var final = initial
    final["NativeTestBuild"] = expectedCandidate
    final["loaded_uuid_matches"] = true
    final[admissionKeys[0]] = Int64(successStage)
    final[admissionKeys[1]] = Int64(0)
    final[admissionKeys[2]] = Int64(0)
    final[admissionKeys[3]] = Int64(1)
    final[admissionKeys[4]] = Int64(1)
    final[admissionKeys[5]] = Int64(1)
    final[admissionKeys[6]] = Int64(1)
    final[admissionKeys[7]] = Int64(1)
    final[admissionKeys[8]] = Int64(31)
    final[admissionKeys[9]] = UInt64(7)
    final[admissionKeys[10]] = (UInt64(1) << 63) | 9
    final["NativeP2PProbeAttempted"] = Int64(1)
    final["NativeP2PProbeState"] = Int64(7)
    final["NativeP2PProbeResourceMayExist"] = Int64(0)
    final["NativeP2PProbeRemoveResult"] = Int64(0)
    final["NativeP2PProbeContextGeneration"] = Int64(31)
    final["NativeP2PProbePowerGeneration"] = Int64(42)
    final["NativeP2PMulticastAdmissionPrepareWitnessValid"] = Int64(1)
    final["NativeP2PMulticastAdmissionPrepareExpectedRocToken"] = Int64(0)
    final["NativeP2PMulticastAdmissionRocAbortAcknowledged"] = Int64(1)
    final["NativeP2PMulticastAdmissionMacRemoveAckAccepted"] = Int64(1)
    final[macAckIdentityKeys[0]] = Int64(31)
    final[macAckIdentityKeys[1]] = Int64(42)
    final[macAckIdentityKeys[2]] = Int64(0)
    final["NativeP2PRocStage"] = Int64(5)
    final["NativeP2PRocGeneration"] = Int64(31)
    for key in zeroTxCounters { final[key] = Int64(0) }
    return (initial, final)
}

private func runProofSelfTests() -> Never {
    let expectedUUID = "01234567-89AB-CDEF-0123-456789ABCDEF"
    let fixture = proofFixture()
    let success = admissionProof(fixture.final, initial: fixture.initial,
        expectedBuild: expectedCandidate, expectedUUID: expectedUUID)
    guard success["status"] as? String == "admission_and_cleanup_proven",
          success["session_submitted"] as? Bool == false,
          success["data_doorbell_issued"] as? Bool == false,
          success["roc_absent"] as? Bool == true,
          success["queue_serial"] as? UInt64 == ((UInt64(1) << 63) | 9),
          success["roc_session_indicators_unchanged"] as? Bool == true else {
        emit(["schema": 1, "status": "self_test_failed", "case": "prepare_abort_changes_allowed"])
        exit(1)
    }

    var cleanFailure = fixture.final
    cleanFailure[admissionKeys[1]] = Int64(5)
    cleanFailure["NativeP2PProbeState"] = Int64(10)
    let failure = admissionProof(cleanFailure, initial: fixture.initial,
        expectedBuild: expectedCandidate, expectedUUID: expectedUUID)
    guard failure["status"] as? String == "clean_failure" else {
        emit(["schema": 1, "status": "self_test_failed", "case": "failed_operation_cleanup"])
        exit(1)
    }

    var missing = fixture.final
    missing.removeValue(forKey: "NativeP2PProbePowerGeneration")
    missing.removeValue(forKey: "NativeP2PRocUnknown")
    missing.removeValue(forKey: zeroTxCounters[0])
    let unknown = admissionProof(missing, initial: fixture.initial,
        expectedBuild: expectedCandidate, expectedUUID: expectedUUID)
    guard unknown["status"] as? String != "admission_and_cleanup_proven",
          unknown["session_submitted"] is NSNull,
          unknown["data_doorbell_issued"] is NSNull else {
        emit(["schema": 1, "status": "self_test_failed", "case": "missing_is_unknown"])
        exit(1)
    }

    var wrongAck = fixture.final
    wrongAck[macAckIdentityKeys[0]] = Int64(99)
    let mismatch = admissionProof(wrongAck, initial: fixture.initial,
        expectedBuild: expectedCandidate, expectedUUID: expectedUUID)
    guard mismatch["status"] as? String != "admission_and_cleanup_proven" else {
        emit(["schema": 1, "status": "self_test_failed", "case": "ack_identity_mismatch"])
        exit(1)
    }

    emit(["schema": 1, "status": "self_test_passed",
          "cases": ["prepare_abort_changes_allowed", "failed_operation_cleanup",
                    "missing_is_unknown", "ack_identity_mismatch"],
          "queue_serial_round_trip": success["queue_serial"] as Any? ?? NSNull(),
          "hardware_actions": false])
    exit(0)
}

private func emit(_ report: [String: Any]) {
    guard JSONSerialization.isValidJSONObject(report),
          let data = try? JSONSerialization.data(withJSONObject: report,
                                                 options: [.sortedKeys]) else {
        FileHandle.standardError.write(Data("Could not encode report.\n".utf8))
        exit(3)
    }
    FileHandle.standardOutput.write(data)
    FileHandle.standardOutput.write(Data("\n".utf8))
}

private func run() -> Never {
    if Array(CommandLine.arguments.dropFirst()) == ["--self-test"] {
        runProofSelfTests()
    }
    let options = parseOptions()
    let windowID = UUID().uuidString.lowercased().replacingOccurrences(of: "-", with: "")
    guard let loaded = loadedUUIDs() else {
        emit(["schema": 1, "window_id": windowID,
              "status": "preflight_unavailable", "arm_requested": options.armed,
              "reason": "loaded_identity_unavailable", "arm_property_accepted": false])
        exit(1)
    }
    guard let services = matchingServices() else {
        emit(["schema": 1, "window_id": windowID,
              "status": "preflight_unavailable", "arm_requested": options.armed,
              "reason": "ioreg_service_enumeration_failed", "arm_property_accepted": false])
        exit(1)
    }
    defer { for service in services { IOObjectRelease(service) } }
    guard services.count == 1 else {
        emit(["schema": 1, "window_id": windowID,
              "status": "preflight_blocked", "arm_requested": options.armed,
              "reason": "expected_one_airportitlwm_service",
              "service_count": services.count, "loaded_uuids": loaded,
              "arm_property_accepted": false])
        exit(1)
    }
    let service = services[0]
    let problems = currentIdentityProblems(service, options: options, loaded: loaded)
    var initial = snapshot(service)
    initial["loaded_uuid_matches"] = loaded.count == 1 && loaded[0] == options.expectedUUID
    let ready = problems.isEmpty
    guard options.armed else {
        let initialSessionSubmitted = sessionSubmitted(initial)
        let initialNoDoorbell = noDataDoorbell(initial)
        emit(["schema": 1, "window_id": windowID,
              "status": ready ? "preflight_ready" : "preflight_blocked",
              "arm_requested": false, "preflight_ready": ready,
              "problems": problems, "build": options.expectedBuild,
              "expected_uuid": options.expectedUUID, "loaded_uuids": loaded,
              "preflight": initial, "arm_property_accepted": false,
              "radio_transmit_proven": false,
              "session_submitted": initialSessionSubmitted as Any? ?? NSNull(),
              "data_doorbell_issued": initialNoDoorbell.map { !$0 } as Any? ?? NSNull(),
              "profile_intent": ["multicast_resource_admission_only": true,
                                 "session_required": false,
                                 "data_submission_required": false]])
        exit(ready ? 0 : 1)
    }
    guard geteuid() == 0 else {
        emit(["schema": 1, "window_id": windowID,
              "status": "preflight_blocked", "arm_requested": true,
              "preflight_ready": false, "problems": ["administrator_required"],
              "preflight": initial, "arm_property_accepted": false])
        exit(1)
    }
    guard ready else {
        emit(["schema": 1, "window_id": windowID,
              "status": "preflight_blocked", "arm_requested": true,
              "preflight_ready": false, "problems": problems,
              "preflight": initial, "arm_property_accepted": false])
        exit(1)
    }

    let setResult = IORegistryEntrySetCFProperties(service,
        ["NativeP2PArmOnce": true] as CFDictionary)
    guard setResult == KERN_SUCCESS else {
        emit(["schema": 1, "window_id": windowID,
              "status": "arm_request_rejected", "arm_requested": true,
              "preflight_ready": true, "preflight": initial,
              "arm_property_accepted": false,
              "arm_set_result": Int(setResult)])
        exit(1)
    }

    let deadline = Date().addingTimeInterval(deadlineSeconds)
    var final = snapshot(service)
    while Date() < deadline {
        final = snapshot(service)
        if terminalSnapshot(final) { break }
        Thread.sleep(forTimeInterval: 0.1)
    }
    let loadedAfter = loadedUUIDs()
    let loadedMatches = loadedAfter?.count == 1 && loadedAfter?[0] == options.expectedUUID
    final["loaded_uuid_matches"] = loadedMatches
    let proof = admissionProof(final, initial: initial,
        expectedBuild: options.expectedBuild, expectedUUID: options.expectedUUID)
    let terminal = terminalSnapshot(final)
    var report: [String: Any] = [
        "schema": 1,
        "window_id": windowID,
        "status": terminal ? (proof["status"] as? String ?? "terminal_receipt_incomplete") : "terminal_timeout_unknown",
        "arm_requested": true,
        "preflight_ready": true,
        "build": options.expectedBuild,
        "expected_uuid": options.expectedUUID,
        "loaded_uuids": loadedAfter ?? [],
        "preflight": initial,
        "arm_property_accepted": true,
        "arm_set_result": Int(setResult),
        "terminal_observed": terminal,
        "terminal_deadline_seconds": Int(deadlineSeconds),
        "final": final,
        "admission_proof": proof,
        "radio_transmit_proven": false,
        "session_submitted": sessionSubmitted(final) as Any? ?? NSNull(),
        "data_doorbell_issued": noDataDoorbellInWindow(initial, final).map { !$0 } as Any? ?? NSNull(),
        "profile_intent": ["multicast_resource_admission_only": true,
                           "session_required": false,
                           "data_submission_required": false],
    ]
    if let uuidMatch = initial["loaded_uuid_matches"] as? Bool {
        report["expected_uuid_matches_loaded"] = uuidMatch
    }
    emit(report)
    exit(proof["status"] as? String == "admission_and_cleanup_proven" ? 0 : 1)
}

run()
