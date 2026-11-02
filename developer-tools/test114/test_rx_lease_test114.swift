// SPDX-License-Identifier: GPL-2.0-only
import Foundation
import CoreFoundation
import Test114RxLease

func expect(_ condition: @autoclosure () -> Bool, _ message: String) {
    if !condition() {
        FileHandle.standardError.write(Data("FAIL: \(message)\n".utf8))
        exit(1)
    }
}

func goodLease(start: UInt64 = 5_000_000) -> [String: Any] {
    let deadline = start + 100_000
    return [
        "NativeP2PDirectedDataRxLeaseRevisionBegin": NSNumber(value: 4),
        "NativeP2PDirectedDataRxLeaseRevisionEnd": NSNumber(value: 4),
        "NativeP2PDirectedDataRxLeaseReady": NSNumber(value: 1),
        "NativeP2PDirectedDataRxLeaseOwnerSerial": NSNumber(value: 44),
        "NativeP2PDirectedDataRxLeaseContextGeneration": NSNumber(value: 7),
        "NativeP2PDirectedDataRxLeasePowerGeneration": NSNumber(value: 8),
        "NativeP2PDirectedDataRxLeaseStationGeneration": NSNumber(value: 9),
        "NativeP2PDirectedDataRxLeaseRocGeneration": NSNumber(value: 7),
        "NativeP2PDirectedDataRxLeaseStartUs": NSNumber(value: start),
        "NativeP2PDirectedDataRxLeaseDeadlineUs": NSNumber(value: deadline),
        "NativeP2PDirectedDataRxLeaseMccRevision": NSNumber(value: 2),
        "NativeP2PDirectedDataRxLeaseMccNoticeGeneration": NSNumber(value: 12),
        "NativeP2PDirectedDataRxLeaseMccSourceGeneration": NSNumber(value: 8),
        "NativeP2PDirectedDataRxLeaseMccAppliedNoticeGeneration": NSNumber(value: 12),
        "NativeP2PDirectedDataRxLeaseMccResponseStatus": NSNumber(value: 0),
        "NativeP2PDirectedDataRxLeaseMccResponseChannelCount": NSNumber(value: 51),
        "NativeP2PDirectedDataRxLeaseChannel": NSNumber(value: 6),
        "NativeP2PRocGeneration": NSNumber(value: 7),
        "NativeP2PRocActualChannel": NSNumber(value: 6),
        "NativeP2PRocStartSeen": NSNumber(value: 1),
        "NativeP2PRocEndSeen": NSNumber(value: 0),
        "NativeP2PDirectedDataStage": NSNumber(value: 4),
        "NativeP2PDirectedDataReady": NSNumber(value: 1)
    ]
}

func liveLease() -> [String: Any] {
    var lease = goodLease()
    lease["NativeP2PDirectedDataAcceptedRunToken"] = "fixture-run"
    lease["NativeTestBuild"] = "25G332-Test114"
    return lease
}

func poll(_ initial: [String: Any], sequence: [[String: Any]], now initialNow: UInt64 = 5_020_000,
          maximumChecks: Int = 128) -> (Test114RxLeasePollOutcome, Int) {
    var now = initialNow
    var reads = 0
    let outcome = test114PollRxLease(
        initial: initial, expectedRunToken: "fixture-run", expectedBuild: "25G332-Test114",
        readProperties: {
            let index = min(reads, sequence.count - 1)
            reads += 1
            return sequence[index]
        },
        monotonicUs: { now },
        sleepMicroseconds: { now += UInt64($0) },
        maximumChecks: maximumChecks)
    return (outcome, reads)
}

let first = goodLease()
let originalWindow = test114InitialWindow(first)
let originalIdentity = test114InitialIdentity(first)
expect(originalWindow == Test114RxLeaseWindow(startUs: 5_000_000, deadlineUs: 5_100_000),
       "capture coherent original 100 ms window")
expect(originalIdentity != nil, "capture the first valid owner and MCC identity")
let success = test114CheckRxLease(
    first, originalWindow: originalWindow, originalIdentity: originalIdentity,
    monotonicUs: 5_020_000,
    bindOriginAccepted: true, buildMatches: true, stageReady: true)
expect(success.valid && success.falsePredicates.isEmpty, "accept complete valid lease")

var staleMirror = first
staleMirror["NativeP2PRocStartSeen"] = NSNumber(value: 0)
let failedOnce = test114CheckRxLease(
    staleMirror, originalWindow: originalWindow, originalIdentity: originalIdentity,
    monotonicUs: 5_020_000,
    bindOriginAccepted: true, buildMatches: true, stageReady: true)
expect(!failedOnce.valid && failedOnce.falsePredicates == ["roc_mirror_start_seen"],
       "report legacy ROC mirror lag without weakening other predicates")
var trace = Test114RxLeasePollTrace()
trace.record(failedOnce)
trace.record(success)
expect(trace.checkCount == 2, "record both bounded samples")
expect(trace.firstCheck?.falsePredicates == ["roc_mirror_start_seen"], "retain first sample")
expect(trace.firstFailure?.falsePredicates == ["roc_mirror_start_seen"], "retain first failure")
expect(trace.lastCheck?.valid == true, "retain final successful sample")

var invalid = first
invalid["NativeP2PDirectedDataRxLeaseOwnerSerial"] = NSNumber(value: 0)
invalid["NativeP2PDirectedDataRxLeaseContextGeneration"] = NSNumber(value: 6)
invalid["NativeP2PDirectedDataRxLeaseMccSourceGeneration"] = NSNumber(value: 99)
invalid["NativeP2PDirectedDataRxLeaseChannel"] = NSNumber(value: 149)
invalid["NativeP2PDirectedDataRxLeaseDeadlineUs"] = NSNumber(value: 5_100_001)
let rejected = test114CheckRxLease(
    invalid, originalWindow: originalWindow, originalIdentity: originalIdentity,
    monotonicUs: 5_020_000,
    bindOriginAccepted: true, buildMatches: true, stageReady: true)
expect(!rejected.valid, "reject invalid owner/context/MCC/channel/window")
for predicate in ["owner_serial_nonzero", "context_matches_roc", "mcc_source_matches_power",
                  "lease_channel_6", "lease_window_exactly_100ms",
                  "lease_matches_original_window"] {
    expect(rejected.falsePredicates.contains(predicate), "retain false predicate \(predicate)")
}

var changedWindow = goodLease(start: 5_000_001)
let changedWindowCheck = test114CheckRxLease(
    changedWindow, originalWindow: originalWindow, originalIdentity: originalIdentity,
    monotonicUs: 5_020_000,
    bindOriginAccepted: true, buildMatches: true, stageReady: true)
expect(changedWindowCheck.falsePredicates.contains("lease_matches_original_window"),
       "reject a later lease that could extend the deadline")

var changedOwner = goodLease()
changedOwner["NativeP2PDirectedDataRxLeaseOwnerSerial"] = NSNumber(value: 45)
let changedOwnerCheck = test114CheckRxLease(
    changedOwner, originalWindow: originalWindow, originalIdentity: originalIdentity,
    monotonicUs: 5_020_000, bindOriginAccepted: true, buildMatches: true, stageReady: true)
expect(changedOwnerCheck.falsePredicates.contains("owner_serial_matches_initial"),
       "reject an owner change within the same run token and ROC window")

var booleanReady = goodLease()
booleanReady["NativeP2PDirectedDataRxLeaseReady"] = kCFBooleanTrue
let booleanCheck = test114CheckRxLease(
    booleanReady, originalWindow: originalWindow, originalIdentity: originalIdentity,
    monotonicUs: 5_020_000,
    bindOriginAccepted: true, buildMatches: true, stageReady: true)
expect(booleanCheck.falsePredicates.contains("lease_ready"), "reject boolean where a numeric lease flag is required")

expect(test114MayPoll(originalWindow: originalWindow, monotonicUs: 5_099_999,
                      completedChecks: 127), "permit final bounded sample before deadline")
expect(!test114MayPoll(originalWindow: originalWindow, monotonicUs: 5_100_000,
                       completedChecks: 127), "never poll at or after original deadline")
expect(!test114MayPoll(originalWindow: originalWindow, monotonicUs: 5_050_000,
                       completedChecks: 128), "enforce maximum check count")
expect(!test114MayPoll(originalWindow: nil, monotonicUs: 5_050_000,
                       completedChecks: 1), "do not poll without a coherent original window")

let live = liveLease()
var staleOldEnd = live
staleOldEnd["NativeP2PRocGeneration"] = NSNumber(value: 6)
staleOldEnd["NativeP2PRocActualChannel"] = NSNumber(value: 1)
staleOldEnd["NativeP2PRocEndSeen"] = NSNumber(value: 1)
let (caughtUp, caughtUpReads) = poll(staleOldEnd, sequence: [live])
expect(caughtUp.window != nil && caughtUp.trace.checkCount == 2 && caughtUpReads == 1,
       "allow an old ROC END mirror to converge to the current lease")
expect(caughtUp.trace.completionReason == "lease_valid", "record successful catch-up")

var unknownOldEnd = live
unknownOldEnd.removeValue(forKey: "NativeP2PRocGeneration")
unknownOldEnd["NativeP2PRocEndSeen"] = NSNumber(value: 1)
let (unknownCaughtUp, unknownCaughtUpReads) = poll(unknownOldEnd, sequence: [live])
expect(unknownCaughtUp.window != nil && unknownCaughtUpReads == 1 &&
       unknownCaughtUp.trace.completionReason == "lease_valid",
       "allow an unknown-generation END mirror only until current-generation evidence arrives")

var currentEnded = live
currentEnded["NativeP2PRocEndSeen"] = NSNumber(value: 1)
let (endThenClear, endThenClearReads) = poll(currentEnded, sequence: [live])
expect(endThenClear.window == nil && endThenClearReads == 0 && endThenClear.trace.checkCount == 1,
       "current ROC END is terminal before a later END=0 can revive it")
expect(endThenClear.trace.completionReason == "current_roc_end_seen",
       "report sticky terminal reason for current ROC END")

var currentStartLag = live
currentStartLag["NativeP2PRocStartSeen"] = NSNumber(value: 0)
var currentEndAfterMatch = live
currentEndAfterMatch["NativeP2PRocEndSeen"] = NSNumber(value: 1)
let (endAfterMatch, endAfterMatchReads) = poll(
    currentStartLag, sequence: [currentEndAfterMatch, live])
expect(endAfterMatch.window == nil && endAfterMatchReads == 1 &&
       endAfterMatch.trace.checkCount == 2,
       "END after current ROC was matched is terminal even if a later sample clears it")
expect(endAfterMatch.trace.completionReason == "current_roc_end_seen",
       "retain terminal state after current ROC match")

var unknownEndAfterMatch = live
unknownEndAfterMatch.removeValue(forKey: "NativeP2PRocGeneration")
unknownEndAfterMatch["NativeP2PRocEndSeen"] = NSNumber(value: 1)
let (unknownEnd, unknownEndReads) = poll(
    currentStartLag, sequence: [unknownEndAfterMatch, live])
expect(unknownEnd.window == nil && unknownEndReads == 1 && unknownEnd.trace.checkCount == 2 &&
       unknownEnd.trace.completionReason == "current_roc_end_seen",
       "END remains terminal after current ROC was matched, even if a later mirror loses its generation")

var newerRoc = live
newerRoc["NativeP2PRocGeneration"] = NSNumber(value: 8)
let (newer, newerReads) = poll(staleOldEnd, sequence: [newerRoc, live])
expect(newer.window == nil && newerReads == 1 && newer.trace.checkCount == 2,
       "a newer ROC epoch terminates the original lease poll")
expect(newer.trace.completionReason == "newer_roc_generation_seen",
       "report newer ROC terminal reason")

var ownerChangedWhileWaiting = live
ownerChangedWhileWaiting["NativeP2PDirectedDataRxLeaseOwnerSerial"] = NSNumber(value: 45)
let (ownerInterleave, ownerInterleaveReads) = poll(currentStartLag, sequence: [ownerChangedWhileWaiting, live])
expect(ownerInterleave.window == nil && ownerInterleaveReads == 1 &&
       ownerInterleave.trace.completionReason == "non_mirror_lease_predicate_failed",
       "stop actual polling when the lease owner changes")

var revokedWhileWaiting = live
revokedWhileWaiting["NativeP2PDirectedDataRxLeaseReady"] = NSNumber(value: 0)
let (revokedInterleave, revokedInterleaveReads) = poll(currentStartLag, sequence: [revokedWhileWaiting, live])
expect(revokedInterleave.window == nil && revokedInterleaveReads == 1 &&
       revokedInterleave.trace.completionReason == "non_mirror_lease_predicate_failed",
       "stop actual polling when the kernel revokes the lease")

var terminalStage = live
terminalStage["NativeP2PDirectedDataStage"] = NSNumber(value: 10)
let (stageInterleave, stageInterleaveReads) = poll(currentStartLag, sequence: [terminalStage, live])
expect(stageInterleave.window == nil && stageInterleaveReads == 1 &&
       stageInterleave.trace.completionReason == "non_mirror_lease_predicate_failed",
       "stop actual polling when the diagnostic stage becomes terminal")

let (checkLimit, checkLimitReads) = poll(currentStartLag, sequence: [currentStartLag], maximumChecks: 3)
expect(checkLimit.window == nil && checkLimit.trace.checkCount == 3 && checkLimitReads == 2 &&
       checkLimit.trace.completionReason == "check_limit_reached",
       "enforce the maximum poll count in the actual loop")
let (absoluteCheckLimit, absoluteCheckLimitReads) = poll(
    currentStartLag, sequence: [currentStartLag], maximumChecks: 512)
expect(absoluteCheckLimit.window == nil && absoluteCheckLimit.trace.checkCount == 128 &&
       absoluteCheckLimitReads == 127 &&
       absoluteCheckLimit.trace.completionReason == "check_limit_reached",
       "never allow callers to raise the hard cap above 128 checks")

var incompleteWindow = live
incompleteWindow["NativeP2PDirectedDataRxLeaseDeadlineUs"] = NSNumber(value: 5_100_001)
let (unknownWindow, unknownWindowReads) = poll(incompleteWindow, sequence: [live])
expect(unknownWindow.window == nil && unknownWindowReads == 0 &&
       unknownWindow.trace.completionReason == "original_window_unavailable",
       "do not infer or adopt a deadline when the initial window is incoherent")

print("Test114 RX lease offline checks passed")
