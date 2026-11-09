// SPDX-License-Identifier: GPL-2.0-only
import Foundation

public struct Test129TerminalInput {
    public let stage: UInt32?
    public let result: UInt32?
    public let completionObserved: UInt32?
    public let rawTxStatus: UInt32?
    public let firmwareAttemptSucceeded: UInt32?
    public let cleanupAck: UInt32?
    public let resourcesAbsent: UInt32?
    public let matchedPeerReturn: Bool
    public let runIdentityMatches: Bool
    public let outerAttempted: UInt32?
    public let outerState: UInt32?
    public let outerRemoveResult: UInt32?
    public let outerResourceMayExist: UInt32?
    public let outerContextGeneration: UInt32?
    public let outerPowerGeneration: UInt32?
    public let outerStationGeneration: UInt32?
    public let frozenContextGeneration: UInt32?
    public let frozenPowerGeneration: UInt32?
    public let frozenStationGeneration: UInt32?

    public init(stage: UInt32?, result: UInt32?, completionObserved: UInt32?,
                rawTxStatus: UInt32?, firmwareAttemptSucceeded: UInt32?,
                cleanupAck: UInt32?, resourcesAbsent: UInt32?,
                matchedPeerReturn: Bool, runIdentityMatches: Bool,
                outerAttempted: UInt32?,
                outerState: UInt32?, outerRemoveResult: UInt32?,
                outerResourceMayExist: UInt32?, outerContextGeneration: UInt32?,
                outerPowerGeneration: UInt32?, outerStationGeneration: UInt32?,
                frozenContextGeneration: UInt32?, frozenPowerGeneration: UInt32?,
                frozenStationGeneration: UInt32?) {
        self.stage = stage
        self.result = result
        self.completionObserved = completionObserved
        self.rawTxStatus = rawTxStatus
        self.firmwareAttemptSucceeded = firmwareAttemptSucceeded
        self.cleanupAck = cleanupAck
        self.resourcesAbsent = resourcesAbsent
        self.matchedPeerReturn = matchedPeerReturn
        self.runIdentityMatches = runIdentityMatches
        self.outerAttempted = outerAttempted
        self.outerState = outerState
        self.outerRemoveResult = outerRemoveResult
        self.outerResourceMayExist = outerResourceMayExist
        self.outerContextGeneration = outerContextGeneration
        self.outerPowerGeneration = outerPowerGeneration
        self.outerStationGeneration = outerStationGeneration
        self.frozenContextGeneration = frozenContextGeneration
        self.frozenPowerGeneration = frozenPowerGeneration
        self.frozenStationGeneration = frozenStationGeneration
    }
}

public struct Test129TerminalOutcome {
    public let txCompletionObserved: Bool
    public let firmwareAttemptSucceeded: Bool
    public let matchedPeerReturn: Bool
    public let outerReleaseAccepted: Bool
    public let accepted: Bool
    public let failures: [String]
}

public struct Test129FrozenRxLeaseGenerations: Equatable {
    public let context: UInt32
    public let power: UInt32
    public let station: UInt32
}

/// Freeze generations only from the valid lease check that admitted sendto.
/// The later properties may be cleared to zero during cleanup.
public func test129FreezeAcceptedRxLease(valid: Bool,
                                        snapshot: [String: UInt64]) -> Test129FrozenRxLeaseGenerations? {
    guard valid,
          let context = snapshot["RxLeaseContextGeneration"], context > 0,
          let power = snapshot["RxLeasePowerGeneration"], power > 0,
          let station = snapshot["RxLeaseStationGeneration"], station > 0,
          context <= UInt64(UInt32.max), power <= UInt64(UInt32.max),
          station <= UInt64(UInt32.max) else { return nil }
    return Test129FrozenRxLeaseGenerations(context: UInt32(context),
                                           power: UInt32(power),
                                           station: UInt32(station))
}

/// The terminal acceptance predicate used by the Test129 helper and its
/// offline regression harness. It does not treat application return as TX
/// completion, cleanup acknowledgement, radio ACK, or AirDrop evidence.
public func test129EvaluateTerminal(_ input: Test129TerminalInput) -> Test129TerminalOutcome {
    var failures: [String] = []
    func require(_ condition: Bool, _ name: String) {
        if !condition { failures.append(name) }
    }

    let txCompletion = input.completionObserved == 1
    let firmwareSuccess = input.firmwareAttemptSucceeded == 1
    let matchedReturn = input.matchedPeerReturn
    let generationIdentity = input.frozenContextGeneration.map { $0 > 0 } == true &&
        input.frozenPowerGeneration.map { $0 > 0 } == true &&
        input.frozenStationGeneration.map { $0 > 0 } == true &&
        input.outerContextGeneration == input.frozenContextGeneration &&
        input.outerPowerGeneration == input.frozenPowerGeneration &&
        input.outerStationGeneration == input.frozenStationGeneration
    let outerRelease = input.runIdentityMatches && input.outerAttempted == 1 &&
        input.cleanupAck == 1 && input.resourcesAbsent == 1 &&
        input.outerState == 7 && input.outerRemoveResult == 0 &&
        input.outerResourceMayExist == 0 && generationIdentity

    require(input.runIdentityMatches, "run_identity_matches")
    require(input.stage == 8, "directed_stage_complete")
    require(input.result == 0, "directed_result_success")
    require(txCompletion, "tx_completion_observed")
    require(input.rawTxStatus == 1, "raw_tx_status_success")
    require(firmwareSuccess, "firmware_attempt_succeeded")
    require(matchedReturn, "matched_peer_return")
    require(input.cleanupAck == 1, "mac_remove_cleanup_acknowledged")
    require(input.resourcesAbsent == 1, "directed_resources_absent")
    require(input.outerAttempted == 1, "outer_probe_attempted")
    require(input.outerState == 7, "outer_probe_complete")
    require(input.outerRemoveResult == 0, "outer_remove_succeeded")
    require(input.outerResourceMayExist == 0, "outer_resource_absent")
    require(generationIdentity, "outer_generations_match_frozen_rx_lease")

    return Test129TerminalOutcome(
        txCompletionObserved: txCompletion,
        firmwareAttemptSucceeded: firmwareSuccess,
        matchedPeerReturn: matchedReturn,
        outerReleaseAccepted: outerRelease,
        accepted: failures.isEmpty,
        failures: failures)
}
