#!/usr/bin/env swift
import CoreFoundation
import Darwin
import Foundation
import IOKit
import dnssd

private let expectedBuild = "25G416-Test135"
private let expectedUUID = "7ED85846-F29A-33EB-BED1-EBA2D9009D36"
private let maximumRunSeconds: UInt64 = 20
private let terminalStates: Set<Int64> = [7, 8, 9, 10]
// Generic P2P does not include AWDL. Both transports must be requested.
private let browseFlags = DNSServiceFlags(
    kDNSServiceFlagsIncludeP2P | kDNSServiceFlagsIncludeAWDL)
private let browseType = "_airdrop._tcp."
private let browseDomain = "local."

private let enabledFlags = [
    "NativeP2PProbe", "NativeP2PRocProbe", "NativeP2PTxProbe",
    "NativeP2PManualTrigger", "NativeP2PAwdlPsfObservationOnly",
    "NativeP2PAwdlMifFollowup", "NativeP2PGp2Observation",
    "NativeAwdlResidentEnabled", "NativeAwdlTxEvidenceEnabled",
    "NativeAwdlDiscoveryExperimentEnabled",
    "NativeAwdlDiscoveryMifCurrentSlotEnabled",
    "NativeAwdlDiscoveryRxInputEnabled",
]

private let disabledFlags = [
    "NativeAwdlInitObservationOnly", "NativeAwdlLifecycleObservationOnly",
    "NativeAwdlDiscoveryCurrentAwFallbackEnabled",
    "NativeAwdlQmNormalPriorityCompiled", "NativeP2PRx149ObservationOnly",
    "NativeP2PRx149DataInputExperiment", "NativeP2PDirectedPrepareEnabled",
    "NativeP2PDirectedDataEnabled", "NativeP2PMulticastAdmissionEnabled",
    "NativeAwdlReplyShadowCompiled", "NativeAwdlReplyShadowEnabled",
    "NativeRxPreOwnerObservation",
]

private let receiptKeys = [
    "NativeTestBuild", "NativePowerReady", "NativeP2PManualArmed",
    "NativePowerResetCount",
    "NativeP2PProbeBlocked", "NativeP2PProbeAttempted",
    "NativeP2PProbeState", "NativeP2PProbeAddResult",
    "NativeP2PProbeRemoveResult", "NativeP2PProbeResourceMayExist",
    "NativeP2PProbeExerciseResult",
    "NativeP2PProbeExerciseRecoveryProofAccepted",
    "NativeP2PProbeContextGeneration", "NativeP2PProbePowerGeneration",
    "NativeP2PProbeStationGeneration", "NativeP2PRocStage",
    "NativeP2PRocGeneration", "NativeP2PRocObserved",
    "NativeP2PRocStartSeen", "NativeP2PRocStartStatus",
    "NativeP2PRocEndSeen", "NativeP2PRocEndStatus",
    "NativeP2PRocCleanupAllowed",
    "NativeP2PRocUnknown", "NativeAwdlDiscoveryMacRemoveAckAccepted",
    "NativeAwdlDiscoveryMacRemoveAckReject", "NativeAwdlDataTxPending",
    "NativeAwdlDataRxPending", "NativeAwdlDataRxCaptured",
    "NativeAwdlDataRxRejected", "NativeAwdlDataRxQueueFull",
    "NativeAwdlDataRxDecoded", "NativeAwdlDataRxDelivered",
    "NativeAwdlDataRxInputFailed", "NativeAwdlDataDiscoveryInputCalls",
    "NativeAwdlDataDiscoveryInputResult", "NativeAwdlDataDiscoveryInputSuccess",
    "NativeAwdlDataDiscoverySameWindowCommitted",
    "NativeAwdlDataTxMdnsQmAttempts", "NativeAwdlDataTxMdnsQmSubmitted",
    "NativeAwdlDataTxMdnsQmCompleted", "NativeAwdlDataTxMdnsQmSucceeded",
    "NativeP2PAwdlActionFramesSubmitted", "NativeP2PAwdlActionFramesCompleted",
    "NativeP2PAwdlActionFramesSucceeded",
]

private final class BrowseCounters {
    var callbacks = 0
    var additions = 0
    var removals = 0
    var callbackErrors = 0
    var lastError = 0
    var interfaceIndices = Set<UInt32>()
}

private struct Options {
    let run: Bool
    let help: Bool
}

private func writeLine(_ text: String, to handle: FileHandle = .standardOutput) {
    handle.write(Data((text + "\n").utf8))
}

private func emit(_ object: [String: Any], exitCode: Int32) -> Never {
    if JSONSerialization.isValidJSONObject(object),
       let data = try? JSONSerialization.data(withJSONObject: object,
                                               options: [.sortedKeys]) {
        FileHandle.standardOutput.write(data)
        FileHandle.standardOutput.write(Data("\n".utf8))
    } else {
        writeLine("{\"status\":\"receipt_encoding_failed\"}")
    }
    exit(exitCode)
}

private func parseOptions() -> Options {
    let args = Array(CommandLine.arguments.dropFirst())
    if args == ["--help"] || args == ["-h"] { return Options(run: false, help: true) }
    if args.isEmpty { return Options(run: false, help: false) }
    if args == ["--run"] { return Options(run: true, help: false) }
    writeLine("Usage: browse_system_qm_test135.swift [--run]", to: .standardError)
    exit(2)
}

private func help() -> Never {
    writeLine("""
    Test135 one-shot system Bonjour browse and manual ARM helper.
    Default: read-only build/profile preflight.
    --run: starts one DNSServiceBrowse(_airdrop._tcp., local., IncludeP2P | IncludeAWDL),
           issues NativeP2PArmOnce once, and records up to 20 seconds.
    Required loaded build: \(expectedBuild), UUID: \(expectedUUID)
    Output: one JSON receipt on stdout; no service instance names are recorded.
    """)
    exit(0)
}

private func loadedUUIDs() -> [String]? {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/usr/bin/kmutil")
    process.arguments = ["showloaded", "--list-only"]
    let pipe = Pipe()
    process.standardOutput = pipe
    process.standardError = FileHandle.nullDevice
    do { try process.run() } catch { return nil }
    let bytes = pipe.fileHandleForReading.readDataToEndOfFile()
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
    var result: [io_service_t] = []
    while true {
        let service = IOIteratorNext(iterator)
        if service == 0 { break }
        result.append(service)
    }
    IOObjectRelease(iterator)
    return result
}

private func propertyDictionary(_ service: io_service_t) -> [String: Any] {
    var unmanaged: Unmanaged<CFMutableDictionary>?
    guard IORegistryEntryCreateCFProperties(service, &unmanaged,
            kCFAllocatorDefault, 0) == KERN_SUCCESS,
          let dictionary = unmanaged?.takeRetainedValue() as? [String: Any] else {
        return [:]
    }
    return dictionary
}

private func serializable(_ value: Any?) -> Any {
    guard let value else { return NSNull() }
    if let number = value as? NSNumber {
        if CFGetTypeID(number) == CFBooleanGetTypeID() { return number.boolValue }
        return number.int64Value
    }
    if let string = value as? String { return string }
    return NSNull()
}

private func number(_ values: [String: Any], _ key: String) -> Int64? {
    guard let value = values[key] as? NSNumber,
          CFGetTypeID(value) != CFBooleanGetTypeID() else { return nil }
    return value.int64Value
}

private func flag(_ values: [String: Any], _ key: String) -> Bool? {
    guard let value = values[key] as? NSNumber,
          CFGetTypeID(value) == CFBooleanGetTypeID() else { return nil }
    return value.boolValue
}

private func snapshot(_ service: io_service_t) -> [String: Any] {
    let properties = propertyDictionary(service)
    var result: [String: Any] = [:]
    for key in Set(receiptKeys + enabledFlags + disabledFlags) {
        result[key] = serializable(properties[key])
    }
    // These immutable payloads are address-free by their production schema.
    for key in ["NativeP2PQmWireSnapshot", "NativeP2PCurrentAwAttemptOnly"] {
        if let data = properties[key] as? Data {
            result[key + "Base64"] = data.base64EncodedString()
        } else {
            result[key + "Base64"] = NSNull()
        }
    }
    // Preserve bounded numeric PSF/MIF evidence while excluding strings, data,
    // addresses, and all unrelated registry properties.
    for (key, value) in properties where
        key.hasPrefix("NativeP2PAwdlPsf") || key.hasPrefix("NativeP2PAwdlMif") {
        if value is NSNumber { result[key] = serializable(value) }
    }
    return result
}

private func profileProblems(_ values: [String: Any], loaded: [String]?) -> [String] {
    var problems: [String] = []
    if loaded?.count != 1 || loaded?.first != expectedUUID { problems.append("loaded_uuid") }
    if values["NativeTestBuild"] as? String != expectedBuild { problems.append("build_tag") }
    if number(values, "NativePowerReady") != 1 { problems.append("power_not_ready") }
    for key in enabledFlags where flag(values, key) != true { problems.append(key) }
    for key in disabledFlags where flag(values, key) != false { problems.append(key) }
    if number(values, "NativeP2PManualArmed") != 0 { problems.append("manual_arm_not_idle") }
    if number(values, "NativeP2PProbeAttempted") != 0 { problems.append("probe_already_attempted") }
    if number(values, "NativeP2PProbeResourceMayExist") != 0 {
        problems.append("probe_resource_may_exist")
    }
    for key in ["NativePowerResetCount", "NativeP2PProbeContextGeneration",
                "NativeP2PRocObserved", "NativeP2PRocStartSeen",
                "NativeP2PRocEndSeen", "NativeP2PRocUnknown"] {
        if number(values, key) == nil { problems.append(key + "_missing") }
        else if key != "NativePowerResetCount" &&
                key != "NativeP2PProbeContextGeneration" && number(values, key) != 0 {
            problems.append(key + "_not_idle")
        }
    }
    for key in ["NativeAwdlDataTxPending", "NativeAwdlDataRxPending"] {
        if let pending = number(values, key), pending != 0 { problems.append(key + "_not_empty") }
    }
    return Array(Set(problems)).sorted()
}

private func terminalObserved(_ values: [String: Any]) -> Bool {
    guard number(values, "NativeP2PProbeAttempted") == 1,
          let state = number(values, "NativeP2PProbeState") else { return false }
    return terminalStates.contains(state)
}

private func cleanupProof(_ values: [String: Any], terminalIdentityValid: Bool) -> [String: Any] {
    let attempted = number(values, "NativeP2PProbeAttempted")
    let state = number(values, "NativeP2PProbeState")
    let remove = number(values, "NativeP2PProbeRemoveResult")
    let mayExist = number(values, "NativeP2PProbeResourceMayExist")
    let operationResult = number(values, "NativeP2PProbeExerciseResult")
    let recoveryAccepted = number(values, "NativeP2PProbeExerciseRecoveryProofAccepted")
    let macAck = number(values, "NativeAwdlDiscoveryMacRemoveAckAccepted")
    let rocObserved = number(values, "NativeP2PRocObserved")
    let rocStarted = number(values, "NativeP2PRocStartSeen")
    let rocStartStatus = number(values, "NativeP2PRocStartStatus")
    let rocEnded = number(values, "NativeP2PRocEndSeen")
    let rocEndStatus = number(values, "NativeP2PRocEndStatus")
    let rocCleanupAllowed = number(values, "NativeP2PRocCleanupAllowed")
    let rocUnknown = number(values, "NativeP2PRocUnknown")
    let rxPending = number(values, "NativeAwdlDataRxPending")
    // Test135 cleanup is only proven by a real current ROC END receipt.
    let rocTerminal = rocObserved == 1 && rocStarted == 1 && rocStartStatus == 1 &&
        rocEnded == 1 && rocEndStatus == 1 && rocCleanupAllowed == 1 && rocUnknown == 0
    let cleanTerminal = state == 7 || state == 10
    let operationConsistent = state == 7 ? operationResult == 0 :
        (state == 10 && operationResult != nil && operationResult != 0 && recoveryAccepted == 1)
    let proven = terminalIdentityValid && attempted == 1 && cleanTerminal &&
        operationConsistent && remove == 0 && mayExist == 0 && macAck == 1 &&
        rocTerminal && rxPending == 0
    return [
        "status": proven ? "cleanup_receipt_proven" : "cleanup_unknown_or_incomplete",
        "terminal_identity_valid": terminalIdentityValid,
        "probe_attempted": attempted as Any? ?? NSNull(),
        "probe_state": state as Any? ?? NSNull(),
        "probe_exercise_result": operationResult as Any? ?? NSNull(),
        "probe_exercise_recovery_proof_accepted": recoveryAccepted as Any? ?? NSNull(),
        "probe_remove_result": remove as Any? ?? NSNull(),
        "probe_resource_may_exist": mayExist as Any? ?? NSNull(),
        "discovery_mac_remove_ack_accepted": macAck as Any? ?? NSNull(),
        "roc_observed": rocObserved as Any? ?? NSNull(),
        "roc_start_seen": rocStarted as Any? ?? NSNull(),
        "roc_start_status": rocStartStatus as Any? ?? NSNull(),
        "roc_end_seen": rocEnded as Any? ?? NSNull(),
        "roc_end_status": rocEndStatus as Any? ?? NSNull(),
        "roc_cleanup_allowed": rocCleanupAllowed as Any? ?? NSNull(),
        "roc_unknown": rocUnknown as Any? ?? NSNull(),
        "rx_pending": rxPending as Any? ?? NSNull(),
        "ifnet_input_calls": number(values, "NativeAwdlDataDiscoveryInputCalls") as Any? ?? NSNull(),
        "ifnet_input_success": number(values, "NativeAwdlDataDiscoveryInputSuccess") as Any? ?? NSNull(),
        "same_window_committed": number(values, "NativeAwdlDataDiscoverySameWindowCommitted") as Any? ?? NSNull(),
        "radio_ack_proven": false,
        "peer_receipt_proven": false,
        "airdrop_proven": false,
    ]
}

private func delta(_ before: [String: Any], _ after: [String: Any], _ key: String) -> Int64? {
    guard let start = number(before, key), let end = number(after, key), end >= start else {
        return nil
    }
    return end - start
}

private func browseCallback(_ sdRef: DNSServiceRef?, _ flags: DNSServiceFlags,
                            _ interfaceIndex: UInt32, _ errorCode: DNSServiceErrorType,
                            _ serviceName: UnsafePointer<CChar>?,
                            _ regtype: UnsafePointer<CChar>?,
                            _ replyDomain: UnsafePointer<CChar>?,
                            _ context: UnsafeMutableRawPointer?) {
    guard let context else { return }
    let counters = Unmanaged<BrowseCounters>.fromOpaque(context).takeUnretainedValue()
    counters.callbacks += 1
    counters.interfaceIndices.insert(interfaceIndex)
    if errorCode != kDNSServiceErr_NoError {
        counters.callbackErrors += 1
        counters.lastError = Int(errorCode)
    } else if flags & kDNSServiceFlagsAdd != 0 {
        counters.additions += 1
    } else {
        counters.removals += 1
    }
    // Deliberately do not retain or print service names.
    _ = sdRef; _ = serviceName; _ = regtype; _ = replyDomain
}

private func browseSummary(_ counters: BrowseCounters) -> [String: Any] {
    [
        "service_type": browseType,
        "domain": browseDomain,
        "include_p2p": true,
        "include_awdl": true,
        "requested_flags": UInt32(browseFlags),
        "interface_index": "any",
        "callbacks": counters.callbacks,
        "additions": counters.additions,
        "removals": counters.removals,
        "callback_errors": counters.callbackErrors,
        "last_error": counters.lastError,
        "callback_interface_indices": counters.interfaceIndices.sorted(),
        "service_names_recorded": false,
    ]
}

private func terminalFingerprint(_ values: [String: Any]) -> [Int64?] {
    ["NativePowerResetCount", "NativeP2PProbeContextGeneration",
     "NativeP2PProbePowerGeneration", "NativeP2PProbeStationGeneration",
     "NativeP2PRocGeneration", "NativeP2PProbeState", "NativeP2PProbeRemoveResult",
     "NativeP2PProbeResourceMayExist", "NativeP2PRocEndSeen",
     "NativeP2PRocEndStatus", "NativeP2PRocCleanupAllowed",
     "NativeP2PRocUnknown",
     "NativeAwdlDataRxPending", "NativeAwdlDataDiscoveryInputCalls",
     "NativeAwdlDataDiscoveryInputSuccess"].map { number(values, $0) }
}

private func run(_ options: Options) -> Never {
    if options.help { help() }
    let runID = UUID().uuidString.lowercased().replacingOccurrences(of: "-", with: "")
    guard let loaded = loadedUUIDs() else {
        emit(["schema": 1, "run_id": runID, "status": "preflight_unavailable",
              "reason": "loaded_identity_unavailable", "arm_property_accepted": false], exitCode: 1)
    }
    guard let services = matchingServices() else {
        emit(["schema": 1, "run_id": runID, "status": "preflight_unavailable",
              "reason": "ioreg_service_enumeration_failed", "arm_property_accepted": false], exitCode: 1)
    }
    defer { for service in services { IOObjectRelease(service) } }
    guard services.count == 1 else {
        emit(["schema": 1, "run_id": runID, "status": "preflight_blocked",
              "reason": "expected_one_AirportItlwm_service", "service_count": services.count,
              "loaded_uuids": loaded, "arm_property_accepted": false], exitCode: 1)
    }
    let service = services[0]
    let initial = snapshot(service)
    let problems = profileProblems(initial, loaded: loaded)
    guard problems.isEmpty else {
        emit(["schema": 1, "run_id": runID,
              "status": "preflight_blocked", "problems": problems,
              "expected_build": expectedBuild, "expected_uuid": expectedUUID,
              "loaded_uuids": loaded, "preflight": initial,
              "run_requested": options.run, "arm_property_accepted": false,
              "radio_ack_proven": false, "peer_receipt_proven": false,
              "airdrop_proven": false], exitCode: 1)
    }
    guard options.run else {
        emit(["schema": 1, "run_id": runID, "status": "preflight_ready",
              "expected_build": expectedBuild, "expected_uuid": expectedUUID,
              "loaded_uuids": loaded, "preflight": initial,
              "run_requested": false, "arm_property_accepted": false,
              "radio_ack_proven": false, "peer_receipt_proven": false,
              "airdrop_proven": false], exitCode: 0)
    }
    guard geteuid() == 0 else {
        emit(["schema": 1, "run_id": runID, "status": "preflight_blocked",
              "problems": ["administrator_required"], "preflight": initial,
              "run_requested": true, "arm_property_accepted": false], exitCode: 1)
    }

    let counters = BrowseCounters()
    var browseRef: DNSServiceRef?
    let browseStartedNs = DispatchTime.now().uptimeNanoseconds
    let browseResult = DNSServiceBrowse(&browseRef, browseFlags,
        UInt32(kDNSServiceInterfaceIndexAny), browseType, browseDomain,
        browseCallback, Unmanaged.passUnretained(counters).toOpaque())
    guard browseResult == kDNSServiceErr_NoError, let activeBrowse = browseRef else {
        if let browseRef { DNSServiceRefDeallocate(browseRef) }
        emit(["schema": 1, "run_id": runID, "status": "browse_start_failed",
              "dns_sd_result": Int(browseResult), "preflight": initial,
              "browse": browseSummary(counters), "arm_property_accepted": false,
              "radio_ack_proven": false, "peer_receipt_proven": false,
              "airdrop_proven": false], exitCode: 1)
    }
    let beforeArmLoaded = loadedUUIDs()
    let beforeArm = snapshot(service)
    let beforeArmProblems = profileProblems(beforeArm, loaded: beforeArmLoaded)
    guard beforeArmProblems.isEmpty,
          number(beforeArm, "NativeP2PProbeAttempted") == 0,
          number(beforeArm, "NativeP2PManualArmed") == 0,
          number(beforeArm, "NativePowerResetCount") == number(initial, "NativePowerResetCount"),
          number(beforeArm, "NativeP2PProbeContextGeneration") == number(initial, "NativeP2PProbeContextGeneration") else {
        DNSServiceRefDeallocate(activeBrowse)
        emit(["schema": 1, "run_id": runID, "status": "pre_arm_identity_changed",
              "problems": beforeArmProblems + ["probe_or_arm_state_changed"],
              "preflight": initial, "before_arm": beforeArm,
              "browse": browseSummary(counters), "arm_property_accepted": false,
              "radio_ack_proven": false, "peer_receipt_proven": false,
              "airdrop_proven": false], exitCode: 1)
    }
    let armResult = IORegistryEntrySetCFProperties(service,
        ["NativeP2PArmOnce": true] as CFDictionary)
    guard armResult == KERN_SUCCESS else {
        DNSServiceRefDeallocate(activeBrowse)
        emit(["schema": 1, "run_id": runID, "status": "arm_request_rejected",
              "arm_set_result": Int(armResult), "preflight": initial,
              "before_arm": beforeArm, "browse": browseSummary(counters),
              "arm_property_accepted": false, "radio_ack_proven": false,
              "peer_receipt_proven": false, "airdrop_proven": false], exitCode: 1)
    }

    let start = DispatchTime.now().uptimeNanoseconds
    let deadline = start + maximumRunSeconds * 1_000_000_000
    let socketFD = DNSServiceRefSockFD(activeBrowse)
    var final = snapshot(service)
    var previousFingerprint: [Int64?]?
    var stableTerminalReads = 0
    var dnsProcessError: Int?
    while DispatchTime.now().uptimeNanoseconds < deadline {
        if socketFD >= 0 && dnsProcessError == nil {
            var descriptor = pollfd(fd: socketFD, events: Int16(POLLIN), revents: 0)
            let pollResult = poll(&descriptor, 1, 100)
            if pollResult > 0 && (descriptor.revents & Int16(POLLIN)) != 0 {
                let processResult = DNSServiceProcessResult(activeBrowse)
                if processResult != kDNSServiceErr_NoError {
                    dnsProcessError = Int(processResult)
                }
            }
        } else {
            Thread.sleep(forTimeInterval: 0.1)
        }
        final = snapshot(service)
        if terminalObserved(final) {
            let fingerprint = terminalFingerprint(final)
            if fingerprint == previousFingerprint { stableTerminalReads += 1 }
            else { stableTerminalReads = 0 }
            previousFingerprint = fingerprint
            if stableTerminalReads >= 2 { break }
        } else {
            previousFingerprint = nil
            stableTerminalReads = 0
        }
    }
    let browseElapsedSeconds = Double(DispatchTime.now().uptimeNanoseconds - browseStartedNs) / 1_000_000_000
    let observationElapsedSeconds = Double(DispatchTime.now().uptimeNanoseconds - start) / 1_000_000_000
    DNSServiceRefDeallocate(activeBrowse)
    let afterRunLoaded = loadedUUIDs()
    final = snapshot(service)
    let terminal = terminalObserved(final)
    let resetStable = number(initial, "NativePowerResetCount") != nil &&
        number(beforeArm, "NativePowerResetCount") == number(initial, "NativePowerResetCount") &&
        number(final, "NativePowerResetCount") == number(initial, "NativePowerResetCount")
    let finalBuildMatches = final["NativeTestBuild"] as? String == expectedBuild
    let loadedMatches = afterRunLoaded?.count == 1 && afterRunLoaded?.first == expectedUUID
    let contextBeforeArm = number(beforeArm, "NativeP2PProbeContextGeneration")
    let finalContext = number(final, "NativeP2PProbeContextGeneration")
    let contextChangedForRun = finalContext != nil && finalContext != 0 &&
        contextBeforeArm != finalContext
    let rocOccurred = (number(final, "NativeP2PRocObserved") ?? 0) != 0 ||
        (number(final, "NativeP2PRocStartSeen") ?? 0) != 0 ||
        (number(final, "NativeP2PRocEndSeen") ?? 0) != 0
    let rocGenerationMatches = !rocOccurred ||
        number(final, "NativeP2PRocGeneration") == finalContext
    let terminalIdentityValid = terminal && stableTerminalReads >= 2 &&
        previousFingerprint == terminalFingerprint(final) && resetStable &&
        finalBuildMatches && loadedMatches && contextChangedForRun &&
        rocGenerationMatches
    let cleanup = cleanupProof(final, terminalIdentityValid: terminalIdentityValid)
    let deltaKeys = [
        "NativeAwdlDataDiscoveryInputCalls", "NativeAwdlDataDiscoveryInputSuccess",
        "NativeAwdlDataDiscoverySameWindowCommitted", "NativeAwdlDataRxCaptured",
        "NativeAwdlDataRxDecoded", "NativeAwdlDataRxDelivered",
        "NativeAwdlDataRxRejected", "NativeAwdlDataRxQueueFull",
        "NativeAwdlDataRxInputFailed", "NativeAwdlDataTxMdnsQmAttempts",
        "NativeAwdlDataTxMdnsQmSubmitted", "NativeAwdlDataTxMdnsQmCompleted",
        "NativeAwdlDataTxMdnsQmSucceeded",
    ]
    var deltas: [String: Any] = [:]
    for key in deltaKeys { deltas[key] = delta(beforeArm, final, key) as Any? ?? NSNull() }
    let initialQM = initial["NativeP2PQmWireSnapshotBase64"] as? String
    let finalQM = final["NativeP2PQmWireSnapshotBase64"] as? String
    let initialAW = initial["NativeP2PCurrentAwAttemptOnlyBase64"] as? String
    let finalAW = final["NativeP2PCurrentAwAttemptOnlyBase64"] as? String
    emit([
        "schema": 1,
        "run_id": runID,
        "status": terminal ? (cleanup["status"] as? String ?? "terminal_receipt_incomplete") : "terminal_timeout_unknown",
        "expected_build": expectedBuild,
        "expected_uuid": expectedUUID,
        "loaded_uuids_after": afterRunLoaded ?? [],
        "loaded_uuid_matches_after": loadedMatches,
        "final_build_matches": finalBuildMatches,
        "power_reset_count_stable": resetStable,
        "context_generation_before_arm": contextBeforeArm as Any? ?? NSNull(),
        "terminal_context_generation": finalContext as Any? ?? NSNull(),
        "context_changed_for_run": contextChangedForRun,
        "roc_generation_matches_context": rocGenerationMatches,
        "terminal_identity_valid": terminalIdentityValid,
        "browse_started": true,
        "browse_start_result": Int(browseResult),
        "browse_process_error": dnsProcessError as Any? ?? NSNull(),
        "browse": browseSummary(counters),
        "arm_property_accepted": true,
        "arm_set_result": Int(armResult),
        "terminal_observed": terminal,
        "terminal_deadline_seconds": Int(maximumRunSeconds),
        "observation_elapsed_seconds": observationElapsedSeconds,
        "browse_elapsed_seconds": browseElapsedSeconds,
        "cleanup": cleanup,
        "counter_deltas_from_before_arm": deltas,
        "qm_wire_snapshot_changed": initialQM != nil && finalQM != nil ? initialQM != finalQM : NSNull(),
        "current_aw_snapshot_changed": initialAW != nil && finalAW != nil ? initialAW != finalAW : NSNull(),
        "preflight": initial,
        "before_arm": beforeArm,
        "final": final,
        "radio_ack_proven": false,
        "peer_receipt_proven": false,
        "airdrop_proven": false,
        "scope": "One Bonjour IncludeP2P | IncludeAWDL browse plus one Test135 manual ARM; local driver and ifnet receipts only.",
    ], exitCode: terminalIdentityValid &&
        (cleanup["status"] as? String == "cleanup_receipt_proven") ? 0 : 1)
}

private let options = parseOptions()
if options.help { help() }
run(options)
