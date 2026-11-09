// SPDX-License-Identifier: GPL-2.0-only
import Foundation
import CoreFoundation

public struct Test114RxLeaseWindow: Equatable {
    public let startUs: UInt64
    public let deadlineUs: UInt64

    public init(startUs: UInt64, deadlineUs: UInt64) {
        self.startUs = startUs
        self.deadlineUs = deadlineUs
    }
}

public struct Test114RxLeaseIdentity: Equatable {
    public let ownerSerial: UInt64
    public let contextGeneration: UInt64
    public let powerGeneration: UInt64
    public let stationGeneration: UInt64
    public let rocGeneration: UInt64
    public let startUs: UInt64
    public let deadlineUs: UInt64
    public let mccRevision: UInt64
    public let mccNoticeGeneration: UInt64
    public let mccSourceGeneration: UInt64
    public let mccAppliedNoticeGeneration: UInt64
    /// Present only for Test126's origin-bound MCC witness profile.
    public let mccOrigin: UInt64?
    public let mccRequestSequence: UInt64?
    public let mccNoticeEpoch: UInt64?
    public let mccResponseStatus: UInt64
    public let mccResponseChannelCount: UInt64
    public let channel: UInt64

    fileprivate init(ownerSerial: UInt64, contextGeneration: UInt64,
                     powerGeneration: UInt64, stationGeneration: UInt64,
                     rocGeneration: UInt64, startUs: UInt64, deadlineUs: UInt64,
                     mccRevision: UInt64, mccNoticeGeneration: UInt64,
                     mccSourceGeneration: UInt64, mccAppliedNoticeGeneration: UInt64,
                     mccOrigin: UInt64?, mccRequestSequence: UInt64?,
                     mccNoticeEpoch: UInt64?,
                     mccResponseStatus: UInt64, mccResponseChannelCount: UInt64,
                     channel: UInt64) {
        self.ownerSerial = ownerSerial
        self.contextGeneration = contextGeneration
        self.powerGeneration = powerGeneration
        self.stationGeneration = stationGeneration
        self.rocGeneration = rocGeneration
        self.startUs = startUs
        self.deadlineUs = deadlineUs
        self.mccRevision = mccRevision
        self.mccNoticeGeneration = mccNoticeGeneration
        self.mccSourceGeneration = mccSourceGeneration
        self.mccAppliedNoticeGeneration = mccAppliedNoticeGeneration
        self.mccOrigin = mccOrigin
        self.mccRequestSequence = mccRequestSequence
        self.mccNoticeEpoch = mccNoticeEpoch
        self.mccResponseStatus = mccResponseStatus
        self.mccResponseChannelCount = mccResponseChannelCount
        self.channel = channel
    }
}

public struct Test114RxLeaseCheck {
    public let valid: Bool
    public let falsePredicates: [String]
    public let safeNumericSnapshot: [String: UInt64]
    public let monotonicUs: UInt64?
    public let window: Test114RxLeaseWindow?

    public var jsonObject: [String: Any] {
        var object: [String: Any] = [
            "valid": valid,
            "false_predicates": falsePredicates,
            "safe_numeric_snapshot": safeNumericSnapshot
        ]
        if let monotonicUs { object["monotonic_us"] = monotonicUs }
        if let window {
            object["lease_window"] = [
                "start_us": window.startUs,
                "deadline_us": window.deadlineUs,
                "duration_us": window.deadlineUs - window.startUs
            ]
        }
        return object
    }
}

public struct Test114RxLeasePollTrace {
    public private(set) var checkCount = 0
    public private(set) var firstCheck: Test114RxLeaseCheck?
    public private(set) var firstFailure: Test114RxLeaseCheck?
    public private(set) var lastCheck: Test114RxLeaseCheck?
    public private(set) var completionReason: String?

    public init() {}

    public mutating func record(_ check: Test114RxLeaseCheck) {
        checkCount += 1
        if firstCheck == nil { firstCheck = check }
        if firstFailure == nil && !check.valid { firstFailure = check }
        lastCheck = check
    }

    public mutating func finish(_ reason: String) {
        completionReason = reason
    }

    public var jsonObject: [String: Any] {
        var object: [String: Any] = ["check_count": checkCount]
        if let completionReason { object["completion_reason"] = completionReason }
        if let firstCheck { object["first_check"] = firstCheck.jsonObject }
        if let firstFailure { object["first_failure"] = firstFailure.jsonObject }
        if let lastCheck { object["last_check"] = lastCheck.jsonObject }
        return object
    }
}

private let leaseNumericKeys = [
    "NativeP2PDirectedDataRxLeaseRevisionBegin",
    "NativeP2PDirectedDataRxLeaseRevisionEnd",
    "NativeP2PDirectedDataRxLeaseReady",
    "NativeP2PDirectedDataRxLeaseOwnerSerial",
    "NativeP2PDirectedDataRxLeaseContextGeneration",
    "NativeP2PDirectedDataRxLeasePowerGeneration",
    "NativeP2PDirectedDataRxLeaseStationGeneration",
    "NativeP2PDirectedDataRxLeaseRocGeneration",
    "NativeP2PDirectedDataRxLeaseStartUs",
    "NativeP2PDirectedDataRxLeaseDeadlineUs",
    "NativeP2PDirectedDataRxLeaseMccRevision",
    "NativeP2PDirectedDataRxLeaseMccNoticeGeneration",
    "NativeP2PDirectedDataRxLeaseMccSourceGeneration",
    "NativeP2PDirectedDataRxLeaseMccAppliedNoticeGeneration",
    "NativeP2PDirectedDataRxLeaseMccOrigin",
    "NativeP2PDirectedDataRxLeaseMccRequestSequence",
    "NativeP2PDirectedDataRxLeaseMccNoticeEpoch",
    "NativeP2PDirectedDataRxLeaseMccResponseStatus",
    "NativeP2PDirectedDataRxLeaseMccResponseChannelCount",
    "NativeP2PDirectedDataRxLeaseChannel",
    "NativeP2PRocGeneration",
    "NativeP2PRocActualChannel",
    "NativeP2PRocStartSeen",
    "NativeP2PRocEndSeen",
    "NativeP2PDirectedDataStage",
    "NativeP2PDirectedDataReady"
]

private func strictUInt64(_ object: [String: Any], _ key: String) -> UInt64? {
    guard let value = object[key] as? NSNumber,
          CFGetTypeID(value) != CFBooleanGetTypeID() else { return nil }
    let number = value.doubleValue
    guard number.isFinite, number >= 0,
          number.rounded(.towardZero) == number,
          number < 18_446_744_073_709_551_616.0 else { return nil }
    return value.uint64Value
}

private func strictUInt32(_ object: [String: Any], _ key: String) -> UInt64? {
    guard let value = strictUInt64(object, key), value <= UInt64(UInt32.max) else { return nil }
    return value
}

/// Capture the immutable ROC window from the first coherent lease publication.
/// A later poll is never allowed to replace or extend this window.
public func test114InitialWindow(_ object: [String: Any]) -> Test114RxLeaseWindow? {
    guard let begin = strictUInt64(object, "NativeP2PDirectedDataRxLeaseRevisionBegin"),
          let end = strictUInt64(object, "NativeP2PDirectedDataRxLeaseRevisionEnd"),
          begin > 0, begin == end, begin & 1 == 0,
          let start = strictUInt64(object, "NativeP2PDirectedDataRxLeaseStartUs"), start > 0,
          let deadline = strictUInt64(object, "NativeP2PDirectedDataRxLeaseDeadlineUs"),
          deadline > start, deadline - start == 100_000 else { return nil }
    return Test114RxLeaseWindow(startUs: start, deadlineUs: deadline)
}

/// Capture the core identity before allowing any short mirror-read retry.
/// A partial/unstable initial publication is not a basis for adopting a later lease.
public func test114InitialIdentity(_ object: [String: Any],
                                   requireMccOriginWitness: Bool = false) -> Test114RxLeaseIdentity? {
    guard let begin = strictUInt64(object, "NativeP2PDirectedDataRxLeaseRevisionBegin"),
          let end = strictUInt64(object, "NativeP2PDirectedDataRxLeaseRevisionEnd"),
          begin > 0, begin == end, begin & 1 == 0,
          strictUInt64(object, "NativeP2PDirectedDataRxLeaseReady") == 1,
          let owner = strictUInt64(object, "NativeP2PDirectedDataRxLeaseOwnerSerial"), owner > 0,
          let context = strictUInt64(object, "NativeP2PDirectedDataRxLeaseContextGeneration"), context > 0,
          let power = strictUInt64(object, "NativeP2PDirectedDataRxLeasePowerGeneration"), power > 0,
          let station = strictUInt64(object, "NativeP2PDirectedDataRxLeaseStationGeneration"), station > 0,
          let roc = strictUInt64(object, "NativeP2PDirectedDataRxLeaseRocGeneration"), roc > 0,
          context == roc,
          let start = strictUInt64(object, "NativeP2PDirectedDataRxLeaseStartUs"), start > 0,
          let deadline = strictUInt64(object, "NativeP2PDirectedDataRxLeaseDeadlineUs"),
          deadline > start, deadline - start == 100_000,
          let mccRevision = strictUInt64(object, "NativeP2PDirectedDataRxLeaseMccRevision"),
          mccRevision > 0, mccRevision & 1 == 0,
          let mccNotice = strictUInt64(object, "NativeP2PDirectedDataRxLeaseMccNoticeGeneration"),
          let mccSource = strictUInt64(object, "NativeP2PDirectedDataRxLeaseMccSourceGeneration"),
          mccSource == power,
          let mccApplied = strictUInt64(object, "NativeP2PDirectedDataRxLeaseMccAppliedNoticeGeneration"),
          let mccStatus = strictUInt64(object, "NativeP2PDirectedDataRxLeaseMccResponseStatus"), mccStatus <= 1,
          let mccChannels = strictUInt64(object, "NativeP2PDirectedDataRxLeaseMccResponseChannelCount"), mccChannels == 51,
          let channel = strictUInt64(object, "NativeP2PDirectedDataRxLeaseChannel"), channel == 6 else { return nil }
    var mccOrigin: UInt64?
    var mccRequestSequence: UInt64?
    var mccNoticeEpoch: UInt64?
    if requireMccOriginWitness {
        guard let origin = strictUInt32(object, "NativeP2PDirectedDataRxLeaseMccOrigin"),
              let requestSequence = strictUInt32(object, "NativeP2PDirectedDataRxLeaseMccRequestSequence"),
              let noticeEpoch = strictUInt32(object, "NativeP2PDirectedDataRxLeaseMccNoticeEpoch"),
              noticeEpoch & 1 == 0 else {
            return nil
        }
        switch origin {
        case 1:
            guard requestSequence > 0, mccNotice == 0, mccApplied == 0 else { return nil }
        case 2:
            guard requestSequence == 0, noticeEpoch > 0,
                  mccNotice == noticeEpoch, mccApplied == noticeEpoch else { return nil }
        default:
            return nil
        }
        mccOrigin = origin
        mccRequestSequence = requestSequence
        mccNoticeEpoch = noticeEpoch
    } else {
        guard mccNotice > 0, mccApplied == mccNotice else { return nil }
    }
    return Test114RxLeaseIdentity(
        ownerSerial: owner, contextGeneration: context, powerGeneration: power,
        stationGeneration: station, rocGeneration: roc, startUs: start,
        deadlineUs: deadline, mccRevision: mccRevision,
        mccNoticeGeneration: mccNotice, mccSourceGeneration: mccSource,
        mccAppliedNoticeGeneration: mccApplied, mccOrigin: mccOrigin,
        mccRequestSequence: mccRequestSequence, mccNoticeEpoch: mccNoticeEpoch,
        mccResponseStatus: mccStatus,
        mccResponseChannelCount: mccChannels, channel: channel)
}

/// Evaluate every lease and context predicate so a failure is actionable.
/// `originalWindow` is fixed from the first coherent snapshot; it is not refreshed.
public func test114CheckRxLease(
    _ object: [String: Any],
    originalWindow: Test114RxLeaseWindow?,
    originalIdentity: Test114RxLeaseIdentity?,
    monotonicUs: UInt64?,
    bindOriginAccepted: Bool,
    buildMatches: Bool,
    stageReady: Bool
) -> Test114RxLeaseCheck {
    var failures: [String] = []
    func require(_ condition: Bool, _ name: String) {
        if !condition { failures.append(name) }
    }
    func value(_ key: String) -> UInt64? { strictUInt64(object, key) }
    func value32(_ key: String) -> UInt64? { strictUInt32(object, key) }

    let begin = value("NativeP2PDirectedDataRxLeaseRevisionBegin")
    let end = value("NativeP2PDirectedDataRxLeaseRevisionEnd")
    let ready = value("NativeP2PDirectedDataRxLeaseReady")
    let owner = value("NativeP2PDirectedDataRxLeaseOwnerSerial")
    let context = value("NativeP2PDirectedDataRxLeaseContextGeneration")
    let power = value("NativeP2PDirectedDataRxLeasePowerGeneration")
    let station = value("NativeP2PDirectedDataRxLeaseStationGeneration")
    let roc = value("NativeP2PDirectedDataRxLeaseRocGeneration")
    let start = value("NativeP2PDirectedDataRxLeaseStartUs")
    let deadline = value("NativeP2PDirectedDataRxLeaseDeadlineUs")
    let mccRevision = value("NativeP2PDirectedDataRxLeaseMccRevision")
    let mccNotice = value("NativeP2PDirectedDataRxLeaseMccNoticeGeneration")
    let mccSource = value("NativeP2PDirectedDataRxLeaseMccSourceGeneration")
    let mccApplied = value("NativeP2PDirectedDataRxLeaseMccAppliedNoticeGeneration")
    let mccOrigin = value32("NativeP2PDirectedDataRxLeaseMccOrigin")
    let mccRequestSequence = value32("NativeP2PDirectedDataRxLeaseMccRequestSequence")
    let mccNoticeEpoch = value32("NativeP2PDirectedDataRxLeaseMccNoticeEpoch")
    let mccStatus = value("NativeP2PDirectedDataRxLeaseMccResponseStatus")
    let mccChannels = value("NativeP2PDirectedDataRxLeaseMccResponseChannelCount")
    let channel = value("NativeP2PDirectedDataRxLeaseChannel")
    let mirrorRoc = value("NativeP2PRocGeneration")
    let mirrorChannel = value("NativeP2PRocActualChannel")
    let mirrorStart = value("NativeP2PRocStartSeen")
    let mirrorEnd = value("NativeP2PRocEndSeen")

    require(begin != nil, "lease_revision_begin_numeric")
    require(end != nil, "lease_revision_end_numeric")
    require(begin.map { $0 > 0 } == true, "lease_revision_begin_nonzero")
    require(begin != nil && begin == end && begin! & 1 == 0, "lease_revision_stable_even")
    require(ready == 1, "lease_ready")
    require(owner.map { $0 > 0 } == true, "owner_serial_nonzero")
    require(context.map { $0 > 0 } == true, "context_generation_nonzero")
    require(power.map { $0 > 0 } == true, "power_generation_nonzero")
    require(station.map { $0 > 0 } == true, "station_generation_nonzero")
    require(roc.map { $0 > 0 } == true, "roc_generation_nonzero")
    require(context != nil && context == roc, "context_matches_roc")
    require(start.map { $0 > 0 } == true, "lease_start_nonzero")
    require(deadline != nil, "lease_deadline_numeric")
    require(start != nil && deadline != nil && deadline! > start! && deadline! - start! == 100_000,
            "lease_window_exactly_100ms")
    require(mccRevision.map { $0 > 0 && $0 & 1 == 0 } == true, "mcc_revision_nonzero_even")
    require(mccSource != nil && mccSource == power, "mcc_source_matches_power")
    if let originalIdentity, let initialOrigin = originalIdentity.mccOrigin {
        require(mccOrigin != nil, "mcc_origin_uint32")
        require(mccRequestSequence != nil, "mcc_request_sequence_uint32")
        require(mccNoticeEpoch != nil, "mcc_notice_epoch_uint32")
        require(mccOrigin == 1 || mccOrigin == 2, "mcc_origin_supported")
        switch initialOrigin {
        case 1:
            require(mccRequestSequence.map { $0 > 0 } == true,
                    "mcc_init_request_sequence_nonzero")
            require(mccNoticeEpoch != nil, "mcc_init_notice_epoch_numeric")
            require(mccNoticeEpoch.map { $0 & 1 == 0 } == true,
                    "mcc_init_notice_epoch_even")
            require(mccNotice == 0, "mcc_init_notice_generation_zero")
            require(mccApplied == 0, "mcc_init_applied_notice_generation_zero")
        case 2:
            require(mccRequestSequence == 0, "mcc_chub_request_sequence_zero")
            require(mccNoticeEpoch.map { $0 > 0 } == true, "mcc_chub_notice_epoch_nonzero")
            require(mccNoticeEpoch.map { $0 & 1 == 0 } == true,
                    "mcc_chub_notice_epoch_even")
            require(mccNoticeEpoch != nil && mccNoticeEpoch == mccNotice,
                    "mcc_chub_epoch_matches_notice")
            require(mccNotice.map { $0 > 0 } == true, "mcc_notice_nonzero")
            require(mccApplied != nil && mccApplied == mccNotice,
                    "mcc_applied_notice_matches")
        default:
            require(false, "mcc_origin_supported")
        }
        require(mccOrigin == originalIdentity.mccOrigin, "mcc_origin_matches_initial")
        require(mccRequestSequence == originalIdentity.mccRequestSequence,
                "mcc_request_sequence_matches_initial")
        require(mccNoticeEpoch == originalIdentity.mccNoticeEpoch,
                "mcc_notice_epoch_matches_initial")
    } else {
        require(mccNotice.map { $0 > 0 } == true, "mcc_notice_nonzero")
        require(mccApplied != nil && mccApplied == mccNotice, "mcc_applied_notice_matches")
    }
    require(mccStatus.map { $0 <= 1 } == true, "mcc_status_success")
    require(mccChannels == 51, "mcc_channel_count")
    require(channel == 6, "lease_channel_6")
    require(mirrorRoc != nil && mirrorRoc == roc, "roc_mirror_generation_matches")
    require(mirrorChannel == 6, "roc_mirror_channel_6")
    require(mirrorStart == 1, "roc_mirror_start_seen")
    require(mirrorEnd == 0, "roc_mirror_end_not_seen")
    require(originalWindow != nil, "original_window_available")
    if let originalWindow {
        require(start == originalWindow.startUs && deadline == originalWindow.deadlineUs,
                "lease_matches_original_window")
    }
    require(originalIdentity != nil, "initial_identity_profile_available")
    if let originalIdentity {
        require(owner == originalIdentity.ownerSerial, "owner_serial_matches_initial")
        require(context == originalIdentity.contextGeneration, "context_generation_matches_initial")
        require(power == originalIdentity.powerGeneration, "power_generation_matches_initial")
        require(station == originalIdentity.stationGeneration, "station_generation_matches_initial")
        require(roc == originalIdentity.rocGeneration, "roc_generation_matches_initial")
        require(start == originalIdentity.startUs && deadline == originalIdentity.deadlineUs,
                "lease_window_matches_initial_identity")
        require(mccRevision == originalIdentity.mccRevision, "mcc_revision_matches_initial")
        require(mccNotice == originalIdentity.mccNoticeGeneration, "mcc_notice_matches_initial")
        require(mccSource == originalIdentity.mccSourceGeneration, "mcc_source_matches_initial")
        require(mccApplied == originalIdentity.mccAppliedNoticeGeneration,
                "mcc_applied_notice_matches_initial")
        require(mccStatus == originalIdentity.mccResponseStatus, "mcc_status_matches_initial")
        require(mccChannels == originalIdentity.mccResponseChannelCount,
                "mcc_channel_count_matches_initial")
        require(channel == originalIdentity.channel, "channel_matches_initial")
    }
    require(monotonicUs != nil, "monotonic_clock_available")
    if let start, let deadline, let monotonicUs {
        require(monotonicUs >= start, "lease_window_started")
        require(monotonicUs < deadline, "lease_deadline_live")
    } else {
        require(false, "lease_deadline_live")
    }
    require(bindOriginAccepted, "bind_origin_accepted")
    require(buildMatches, "build_identity_matches")
    require(stageReady, "stage4_ready")

    var safeSnapshot: [String: UInt64] = [:]
    for key in leaseNumericKeys {
        if let number = value(key) {
            safeSnapshot[key.replacingOccurrences(of: "NativeP2PDirectedData", with: "")] = number
        }
    }
    return Test114RxLeaseCheck(
        valid: failures.isEmpty,
        falsePredicates: failures,
        safeNumericSnapshot: safeSnapshot,
        monotonicUs: monotonicUs,
        window: originalWindow)
}

public func test114MayPoll(originalWindow: Test114RxLeaseWindow?,
                           monotonicUs: UInt64?,
                           completedChecks: Int,
                           maximumChecks: Int = 128) -> Bool {
    guard let originalWindow, let monotonicUs,
          originalWindow.deadlineUs > originalWindow.startUs,
          originalWindow.deadlineUs - originalWindow.startUs == 100_000,
          monotonicUs < originalWindow.deadlineUs,
          completedChecks < maximumChecks else { return false }
    return true
}

public struct Test114RxLeasePollOutcome {
    public let window: Test114RxLeaseWindow?
    public let trace: Test114RxLeasePollTrace
}

/// The exact Test114 poll loop. Dependencies are closures so tests can replay
/// property/clock interleavings without IOKit, sockets, or RF access.
public func test114PollRxLease(
    initial: [String: Any],
    expectedRunToken: String,
    expectedBuild: String,
    readProperties: () -> [String: Any],
    monotonicUs: () -> UInt64?,
    sleepMicroseconds: (UInt32) -> Void,
    maximumChecks: Int = 128,
    requireMccOriginWitness: Bool = false
) -> Test114RxLeasePollOutcome {
    let originalWindow = test114InitialWindow(initial)
    let originalIdentity = test114InitialIdentity(
        initial, requireMccOriginWitness: requireMccOriginWitness)
    var trace = Test114RxLeasePollTrace()
    var current = initial
    var firstRead = true
    var sawCurrentRoc = false
    let checkLimit = max(0, min(maximumChecks, 128))

    while trace.checkCount < checkLimit {
        if !firstRead {
            guard let originalWindow else {
                trace.finish("original_window_unavailable")
                return Test114RxLeasePollOutcome(window: nil, trace: trace)
            }
            guard let beforeReadUs = monotonicUs(),
                  beforeReadUs < originalWindow.deadlineUs else {
                trace.finish("original_deadline_elapsed")
                return Test114RxLeasePollOutcome(window: nil, trace: trace)
            }
            current = readProperties()
        }
        firstRead = false

        let nowUs = monotonicUs()
        let bindOriginAccepted = current["NativeP2PDirectedDataAcceptedRunToken"] as? String == expectedRunToken
        let buildMatches = current["NativeTestBuild"] as? String == expectedBuild
        let stageReady = strictUInt64(current, "NativeP2PDirectedDataStage") == 4 &&
                         strictUInt64(current, "NativeP2PDirectedDataReady") == 1
        let check = test114CheckRxLease(
            current, originalWindow: originalWindow, originalIdentity: originalIdentity,
            monotonicUs: nowUs, bindOriginAccepted: bindOriginAccepted,
            buildMatches: buildMatches, stageReady: stageReady)
        trace.record(check)

        if let originalIdentity {
            let mirrorRoc = strictUInt64(current, "NativeP2PRocGeneration")
            if mirrorRoc == originalIdentity.rocGeneration { sawCurrentRoc = true }
            if let mirrorRoc, mirrorRoc > originalIdentity.rocGeneration {
                trace.finish("newer_roc_generation_seen")
                return Test114RxLeasePollOutcome(window: nil, trace: trace)
            }
            if strictUInt64(current, "NativeP2PRocEndSeen") == 1 &&
               (mirrorRoc == originalIdentity.rocGeneration || sawCurrentRoc) {
                trace.finish("current_roc_end_seen")
                return Test114RxLeasePollOutcome(window: nil, trace: trace)
            }
        }

        if check.valid {
            trace.finish("lease_valid")
            return Test114RxLeasePollOutcome(window: originalWindow, trace: trace)
        }
        guard let originalWindow else {
            trace.finish("original_window_unavailable")
            return Test114RxLeasePollOutcome(window: nil, trace: trace)
        }
        guard originalIdentity != nil else {
            trace.finish("initial_identity_profile_unavailable")
            return Test114RxLeasePollOutcome(window: nil, trace: trace)
        }
        let transientPredicates: Set<String> = [
            "roc_mirror_generation_matches", "roc_mirror_channel_6",
            "roc_mirror_start_seen", "roc_mirror_end_not_seen",
            "lease_window_started"
        ]
        guard bindOriginAccepted, buildMatches, stageReady,
              check.falsePredicates.allSatisfy({ transientPredicates.contains($0) }) else {
            trace.finish("non_mirror_lease_predicate_failed")
            return Test114RxLeasePollOutcome(window: nil, trace: trace)
        }
        guard test114MayPoll(originalWindow: originalWindow, monotonicUs: nowUs,
                             completedChecks: trace.checkCount,
                             maximumChecks: checkLimit) else {
            let deadlineElapsed = nowUs.map { $0 >= originalWindow.deadlineUs } ?? false
            trace.finish(deadlineElapsed ? "original_deadline_elapsed" : "check_limit_reached")
            return Test114RxLeasePollOutcome(window: nil, trace: trace)
        }
        sleepMicroseconds(250)
    }
    trace.finish("check_limit_reached")
    return Test114RxLeasePollOutcome(window: nil, trace: trace)
}
