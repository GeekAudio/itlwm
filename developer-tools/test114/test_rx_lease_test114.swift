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

func goodTest126InitLease(start: UInt64 = 5_000_000) -> [String: Any] {
    var lease = goodLease(start: start)
    lease["NativeP2PDirectedDataRxLeaseMccNoticeGeneration"] = NSNumber(value: 0)
    lease["NativeP2PDirectedDataRxLeaseMccAppliedNoticeGeneration"] = NSNumber(value: 0)
    lease["NativeP2PDirectedDataRxLeaseMccOrigin"] = NSNumber(value: 1)
    lease["NativeP2PDirectedDataRxLeaseMccRequestSequence"] = NSNumber(value: 33)
    lease["NativeP2PDirectedDataRxLeaseMccNoticeEpoch"] = NSNumber(value: 0)
    return lease
}

func goodTest126ChubLease(start: UInt64 = 5_000_000) -> [String: Any] {
    var lease = goodLease(start: start)
    lease["NativeP2PDirectedDataRxLeaseMccOrigin"] = NSNumber(value: 2)
    lease["NativeP2PDirectedDataRxLeaseMccRequestSequence"] = NSNumber(value: 0)
    lease["NativeP2PDirectedDataRxLeaseMccNoticeEpoch"] = NSNumber(value: 12)
    return lease
}

func liveLease(_ source: [String: Any] = goodLease(), build: String = "25G332-Test114") -> [String: Any] {
    var lease = source
    lease["NativeP2PDirectedDataAcceptedRunToken"] = "fixture-run"
    lease["NativeTestBuild"] = build
    return lease
}

func poll(_ initial: [String: Any], sequence: [[String: Any]], now initialNow: UInt64 = 5_020_000,
          maximumChecks: Int = 128, expectedBuild: String = "25G332-Test114",
          requireMccOriginWitness: Bool = false) -> (Test114RxLeasePollOutcome, Int) {
    var now = initialNow
    var reads = 0
    let outcome = test114PollRxLease(
        initial: initial, expectedRunToken: "fixture-run", expectedBuild: expectedBuild,
        readProperties: {
            let index = min(reads, sequence.count - 1)
            reads += 1
            return sequence[index]
        },
        monotonicUs: { now },
        sleepMicroseconds: { now += UInt64($0) },
        maximumChecks: maximumChecks,
        requireMccOriginWitness: requireMccOriginWitness)
    return (outcome, reads)
}

let first = goodLease()
let originalWindow = test114InitialWindow(first)
let originalIdentity = test114InitialIdentity(first)
expect(originalWindow == Test114RxLeaseWindow(startUs: 5_000_000, deadlineUs: 5_100_000),
       "capture coherent original 100 ms window")
expect(originalIdentity != nil, "capture the first valid owner and MCC identity")
expect(originalIdentity?.mccOrigin == nil,
       "preserve the older lease profile when origin witness fields are absent")
let success = test114CheckRxLease(
    first, originalWindow: originalWindow, originalIdentity: originalIdentity,
    monotonicUs: 5_020_000,
    bindOriginAccepted: true, buildMatches: true, stageReady: true)
expect(success.valid && success.falsePredicates.isEmpty, "accept complete valid lease")

let test126Init = goodTest126InitLease()
let test126InitIdentity = test114InitialIdentity(test126Init, requireMccOriginWitness: true)
expect(test126InitIdentity?.mccOrigin == 1 && test126InitIdentity?.mccRequestSequence == 33 &&
       test126InitIdentity?.mccNoticeEpoch == 0,
       "accept init witness with nonzero request sequence and zero invalidation epoch")
let test126InitCheck = test114CheckRxLease(
    test126Init, originalWindow: test114InitialWindow(test126Init),
    originalIdentity: test126InitIdentity, monotonicUs: 5_020_000,
    bindOriginAccepted: true, buildMatches: true, stageReady: true)
expect(test126InitCheck.valid, "accept complete Test126 initialization witness")

let test126Chub = goodTest126ChubLease()
let test126ChubIdentity = test114InitialIdentity(test126Chub, requireMccOriginWitness: true)
expect(test126ChubIdentity?.mccOrigin == 2 &&
       test126ChubIdentity?.mccRequestSequence == 0 &&
       test126ChubIdentity?.mccNoticeEpoch == 12,
       "accept CHUB witness only with sequence zero and matching nonzero notice epoch")
let test126ChubCheck = test114CheckRxLease(
    test126Chub, originalWindow: test114InitialWindow(test126Chub),
    originalIdentity: test126ChubIdentity, monotonicUs: 5_020_000,
    bindOriginAccepted: true, buildMatches: true, stageReady: true)
expect(test126ChubCheck.valid, "accept complete Test126 CHUB witness")

var zeroOrigin = test126Init
zeroOrigin["NativeP2PDirectedDataRxLeaseMccOrigin"] = NSNumber(value: 0)
expect(test114InitialIdentity(zeroOrigin, requireMccOriginWitness: true) == nil,
       "reject zero or stale origin in Test126 identity capture")
var unsupportedOrigin = test126Init
unsupportedOrigin["NativeP2PDirectedDataRxLeaseMccOrigin"] = NSNumber(value: 3)
let unsupportedOriginCheck = test114CheckRxLease(
    unsupportedOrigin, originalWindow: test114InitialWindow(test126Init),
    originalIdentity: test126InitIdentity, monotonicUs: 5_020_000,
    bindOriginAccepted: true, buildMatches: true, stageReady: true)
expect(unsupportedOriginCheck.falsePredicates.contains("mcc_origin_supported"),
       "reject an origin outside the init and CHUB domains")

var zeroInitSequence = test126Init
zeroInitSequence["NativeP2PDirectedDataRxLeaseMccRequestSequence"] = NSNumber(value: 0)
let zeroInitSequenceCheck = test114CheckRxLease(
    zeroInitSequence, originalWindow: test114InitialWindow(test126Init),
    originalIdentity: test126InitIdentity, monotonicUs: 5_020_000,
    bindOriginAccepted: true, buildMatches: true, stageReady: true)
expect(zeroInitSequenceCheck.falsePredicates.contains("mcc_init_request_sequence_nonzero"),
       "reject an init witness without a real request sequence")
var mixedInitNotice = test126Init
mixedInitNotice["NativeP2PDirectedDataRxLeaseMccNoticeGeneration"] = NSNumber(value: 12)
mixedInitNotice["NativeP2PDirectedDataRxLeaseMccAppliedNoticeGeneration"] = NSNumber(value: 12)
let mixedInitNoticeCheck = test114CheckRxLease(
    mixedInitNotice, originalWindow: test114InitialWindow(test126Init),
    originalIdentity: test126InitIdentity, monotonicUs: 5_020_000,
    bindOriginAccepted: true, buildMatches: true, stageReady: true)
expect(mixedInitNoticeCheck.falsePredicates.contains("mcc_init_notice_generation_zero") &&
       mixedInitNoticeCheck.falsePredicates.contains("mcc_init_applied_notice_generation_zero"),
       "reject CHUB notice fields mixed into an init-origin witness")
var mixedChubSequence = test126Chub
mixedChubSequence["NativeP2PDirectedDataRxLeaseMccRequestSequence"] = NSNumber(value: 33)
let mixedChubSequenceCheck = test114CheckRxLease(
    mixedChubSequence, originalWindow: test114InitialWindow(test126Chub),
    originalIdentity: test126ChubIdentity, monotonicUs: 5_020_000,
    bindOriginAccepted: true, buildMatches: true, stageReady: true)
expect(mixedChubSequenceCheck.falsePredicates.contains("mcc_chub_request_sequence_zero"),
       "reject an init request sequence mixed into a CHUB-origin witness")
var staleChubEpoch = test126Chub
staleChubEpoch["NativeP2PDirectedDataRxLeaseMccNoticeEpoch"] = NSNumber(value: 11)
let staleChubEpochCheck = test114CheckRxLease(
    staleChubEpoch, originalWindow: test114InitialWindow(test126Chub),
    originalIdentity: test126ChubIdentity, monotonicUs: 5_020_000,
    bindOriginAccepted: true, buildMatches: true, stageReady: true)
expect(staleChubEpochCheck.falsePredicates.contains("mcc_chub_epoch_matches_notice"),
       "reject a CHUB epoch that does not identify its notice")
var oddInitEpoch = test126Init
oddInitEpoch["NativeP2PDirectedDataRxLeaseMccNoticeEpoch"] = NSNumber(value: 1)
expect(test114InitialIdentity(oddInitEpoch, requireMccOriginWitness: true) == nil,
       "reject an odd initialization invalidation epoch")
var oversizedOrigin = test126Init
oversizedOrigin["NativeP2PDirectedDataRxLeaseMccOrigin"] = NSNumber(value: UInt64(UInt32.max) + 1)
expect(test114InitialIdentity(oversizedOrigin, requireMccOriginWitness: true) == nil,
       "reject an MCC origin value outside its uint32 property width")
var oversizedSequence = test126Init
oversizedSequence["NativeP2PDirectedDataRxLeaseMccRequestSequence"] =
    NSNumber(value: UInt64(UInt32.max) + 1)
expect(test114InitialIdentity(oversizedSequence, requireMccOriginWitness: true) == nil,
       "reject a request sequence outside its uint32 property width")
var oversizedEpoch = test126Init
oversizedEpoch["NativeP2PDirectedDataRxLeaseMccNoticeEpoch"] =
    NSNumber(value: UInt64(UInt32.max) + 1)
expect(test114InitialIdentity(oversizedEpoch, requireMccOriginWitness: true) == nil,
       "reject a notice epoch outside its uint32 property width")

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

let test126InitLive = liveLease(test126Init, build: "25G416-Test126")
var test126InitStartLag = test126InitLive
test126InitStartLag["NativeP2PRocStartSeen"] = NSNumber(value: 0)
let (test126InitPoll, test126InitPollReads) = poll(
    test126InitLive, sequence: [test126InitLive], expectedBuild: "25G416-Test126",
    requireMccOriginWitness: true)
expect(test126InitPoll.window != nil && test126InitPollReads == 0 &&
       test126InitPoll.trace.completionReason == "lease_valid",
       "select and accept Test126's strict init-origin lease path")

var changedInitSequence = test126InitLive
changedInitSequence["NativeP2PDirectedDataRxLeaseMccRequestSequence"] = NSNumber(value: 34)
let (sequenceChangedPoll, sequenceChangedReads) = poll(
    test126InitStartLag, sequence: [changedInitSequence, test126InitLive],
    expectedBuild: "25G416-Test126", requireMccOriginWitness: true)
expect(sequenceChangedPoll.window == nil && sequenceChangedReads == 1 &&
       sequenceChangedPoll.trace.completionReason == "non_mirror_lease_predicate_failed" &&
       sequenceChangedPoll.trace.lastCheck?.falsePredicates.contains(
           "mcc_request_sequence_matches_initial") == true,
       "stop polling when the init request sequence changes within a lease")

let changedInitOrigin = liveLease(test126Chub, build: "25G416-Test126")
let (originChangedPoll, originChangedReads) = poll(
    test126InitStartLag, sequence: [changedInitOrigin, test126InitLive],
    expectedBuild: "25G416-Test126", requireMccOriginWitness: true)
expect(originChangedPoll.window == nil && originChangedReads == 1 &&
       originChangedPoll.trace.lastCheck?.falsePredicates.contains(
           "mcc_origin_matches_initial") == true,
       "stop polling when the MCC witness switches from init to CHUB origin")

var changedInitEpoch = test126InitLive
changedInitEpoch["NativeP2PDirectedDataRxLeaseMccNoticeEpoch"] = NSNumber(value: 2)
let (epochChangedPoll, epochChangedReads) = poll(
    test126InitStartLag, sequence: [changedInitEpoch, test126InitLive],
    expectedBuild: "25G416-Test126", requireMccOriginWitness: true)
expect(epochChangedPoll.window == nil && epochChangedReads == 1 &&
       epochChangedPoll.trace.lastCheck?.falsePredicates.contains(
           "mcc_notice_epoch_matches_initial") == true,
       "stop polling when the init invalidation epoch changes")

var changedInitGeneration = test126InitLive
changedInitGeneration["NativeP2PDirectedDataRxLeaseMccSourceGeneration"] = NSNumber(value: 9)
let (generationChangedPoll, generationChangedReads) = poll(
    test126InitStartLag, sequence: [changedInitGeneration, test126InitLive],
    expectedBuild: "25G416-Test126", requireMccOriginWitness: true)
expect(generationChangedPoll.window == nil && generationChangedReads == 1 &&
       generationChangedPoll.trace.lastCheck?.falsePredicates.contains(
           "mcc_source_matches_power") == true,
       "keep the real MCC source generation tied to the lease power generation")

var missingInitEpoch = test126InitLive
missingInitEpoch.removeValue(forKey: "NativeP2PDirectedDataRxLeaseMccNoticeEpoch")
let (missingEpochPoll, missingEpochReads) = poll(
    test126InitStartLag, sequence: [missingInitEpoch, test126InitLive],
    expectedBuild: "25G416-Test126", requireMccOriginWitness: true)
expect(missingEpochPoll.window == nil && missingEpochReads == 1 &&
       missingEpochPoll.trace.lastCheck?.falsePredicates.contains(
           "mcc_notice_epoch_uint32") == true,
       "stop polling when a strict Test126 witness field disappears")

var missingInitialSequence = test126InitLive
missingInitialSequence.removeValue(forKey: "NativeP2PDirectedDataRxLeaseMccRequestSequence")
let (missingInitialPoll, missingInitialReads) = poll(
    missingInitialSequence, sequence: [test126InitLive], expectedBuild: "25G416-Test126",
    requireMccOriginWitness: true)
expect(missingInitialPoll.window == nil && missingInitialReads == 0 &&
       missingInitialPoll.trace.firstFailure?.falsePredicates.contains(
           "initial_identity_profile_available") == true,
       "refuse to poll later into a lease whose initial strict identity was incomplete")

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
