// SPDX-License-Identifier: GPL-2.0-only
import Foundation

func input(stage: UInt32? = 8, result: UInt32? = 0,
           completion: UInt32? = 1, rawStatus: UInt32? = 1,
           firmware: UInt32? = 1, cleanupAck: UInt32? = 1,
           resourcesAbsent: UInt32? = 1, matchedReturn: Bool = true,
           runIdentityMatches: Bool = true, attempted: UInt32? = 1,
           outerState: UInt32? = 7, remove: UInt32? = 0,
           resourceMayExist: UInt32? = 0,
           outerContext: UInt32? = 3, outerPower: UInt32? = 5,
           outerStation: UInt32? = 7,
           frozenContext: UInt32? = 3, frozenPower: UInt32? = 5,
           frozenStation: UInt32? = 7) -> Test129TerminalInput {
    Test129TerminalInput(
        stage: stage, result: result, completionObserved: completion,
        rawTxStatus: rawStatus, firmwareAttemptSucceeded: firmware,
        cleanupAck: cleanupAck, resourcesAbsent: resourcesAbsent,
        matchedPeerReturn: matchedReturn, runIdentityMatches: runIdentityMatches,
        outerAttempted: attempted, outerState: outerState,
        outerRemoveResult: remove, outerResourceMayExist: resourceMayExist,
        outerContextGeneration: outerContext, outerPowerGeneration: outerPower,
        outerStationGeneration: outerStation,
        frozenContextGeneration: frozenContext, frozenPowerGeneration: frozenPower,
        frozenStationGeneration: frozenStation)
}

@main
struct TestTerminalGate129 {
    static func main() {
        let success = test129EvaluateTerminal(input())
        precondition(success.accepted)
        precondition(success.txCompletionObserved && success.firmwareAttemptSucceeded &&
                     success.matchedPeerReturn && success.outerReleaseAccepted)

let noCompletion = test129EvaluateTerminal(input(completion: 0))
precondition(!noCompletion.accepted && !noCompletion.txCompletionObserved)
precondition(noCompletion.firmwareAttemptSucceeded && noCompletion.matchedPeerReturn)

let noFirmwareSuccess = test129EvaluateTerminal(input(firmware: 0))
precondition(!noFirmwareSuccess.accepted && !noFirmwareSuccess.firmwareAttemptSucceeded)

let noMatchedReturn = test129EvaluateTerminal(input(matchedReturn: false))
precondition(!noMatchedReturn.accepted && !noMatchedReturn.matchedPeerReturn)

let staleRun = test129EvaluateTerminal(input(runIdentityMatches: false))
precondition(!staleRun.accepted && !staleRun.outerReleaseAccepted)

let unattempted = test129EvaluateTerminal(input(attempted: 0))
precondition(!unattempted.accepted && !unattempted.outerReleaseAccepted)

let failures: [(String, Test129TerminalInput)] = [
    ("stage8-inner-only", input(outerState: 6)),
    ("quarantined", input(outerState: 8)),
    ("remove-error", input(remove: UInt32.max)),
    ("resource-may-exist", input(resourceMayExist: 1)),
    ("cleanup-unacknowledged", input(cleanupAck: 0)),
    ("inner-resource-present", input(resourcesAbsent: 0)),
    ("context-generation-mismatch", input(outerContext: 4)),
    ("power-generation-mismatch", input(outerPower: 6)),
    ("station-generation-mismatch", input(outerStation: 8)),
    ("missing-frozen-lease", input(frozenStation: nil)),
    ("zero-frozen-lease", input(frozenContext: 0)),
    ("wrong-raw-status", input(rawStatus: 0)),
    ("stage-mismatch", input(stage: 10)),
    ("result-failure", input(result: 16)),
]
for (name, candidate) in failures {
    precondition(!test129EvaluateTerminal(candidate).accepted, "accepted \(name)")
}

let notYetValid: [String: UInt64] = [
    "RxLeaseContextGeneration": 0,
    "RxLeasePowerGeneration": 0,
    "RxLeaseStationGeneration": 0,
]
precondition(test129FreezeAcceptedRxLease(valid: false, snapshot: notYetValid) == nil)
let acceptedLease: [String: UInt64] = [
    "RxLeaseContextGeneration": 3,
    "RxLeasePowerGeneration": 5,
    "RxLeaseStationGeneration": 7,
]
let frozen = test129FreezeAcceptedRxLease(valid: true, snapshot: acceptedLease)
precondition(frozen?.context == 3 && frozen?.power == 5 && frozen?.station == 7)
let clearedAfterCleanup: [String: UInt64] = [
    "RxLeaseContextGeneration": 0,
    "RxLeasePowerGeneration": 0,
    "RxLeaseStationGeneration": 0,
]
precondition(test129FreezeAcceptedRxLease(valid: true, snapshot: clearedAfterCleanup) == nil)
precondition(test129EvaluateTerminal(input(
    outerContext: frozen?.context, outerPower: frozen?.power,
    outerStation: frozen?.station,
    frozenContext: frozen?.context, frozenPower: frozen?.power,
    frozenStation: frozen?.station)).accepted)

        print("Test129 terminal gate cases passed: \(failures.count + 8)")
    }
}
