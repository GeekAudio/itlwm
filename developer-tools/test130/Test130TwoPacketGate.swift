// SPDX-License-Identifier: GPL-2.0-only
import Foundation

public struct Test130ExactReplyReceipt: Equatable {
    public let snapshotSequence: UInt64
    public let ticketSerial: UInt64
    public let packetSerial: UInt64
    public let slot: UInt32
    public let ownerSerial: UInt64
    public let runSerial: UInt64
    public let ifindex: UInt32
    public let interfaceIncarnation: UInt64
    public let contextGeneration: UInt32
    public let powerGeneration: UInt32
    public let stationEpoch: UInt32
    public let rocEpoch: UInt32
    public let doorbellUs: UInt64
    public let captureUs: UInt64
    public let inputUs: UInt64
    public let captured: Bool
    public let delivered: Bool
    public let valid: Bool

    public init(snapshotSequence: UInt64, ticketSerial: UInt64, packetSerial: UInt64, slot: UInt32,
                ownerSerial: UInt64, runSerial: UInt64, ifindex: UInt32,
                interfaceIncarnation: UInt64, contextGeneration: UInt32,
                powerGeneration: UInt32, stationEpoch: UInt32, rocEpoch: UInt32,
                doorbellUs: UInt64, captureUs: UInt64, inputUs: UInt64,
                captured: Bool, delivered: Bool, valid: Bool) {
        self.snapshotSequence = snapshotSequence
        self.ticketSerial = ticketSerial
        self.packetSerial = packetSerial
        self.slot = slot
        self.ownerSerial = ownerSerial
        self.runSerial = runSerial
        self.ifindex = ifindex
        self.interfaceIncarnation = interfaceIncarnation
        self.contextGeneration = contextGeneration
        self.powerGeneration = powerGeneration
        self.stationEpoch = stationEpoch
        self.rocEpoch = rocEpoch
        self.doorbellUs = doorbellUs
        self.captureUs = captureUs
        self.inputUs = inputUs
        self.captured = captured
        self.delivered = delivered
        self.valid = valid
    }
}

public struct Test130PacketReceipt: Equatable {
    public let slot: UInt32
    public let packetSerial: UInt64
    public let nonce: Data
    public let wifiSequence: UInt16
    public let awdlSequence: UInt16
    public let descriptorIndex: UInt32
    public let ssn: UInt16
    public let ownerSerial: UInt64
    public let runSerial: UInt64
    public let ifindex: UInt32
    public let interfaceIncarnation: UInt64
    public let contextGeneration: UInt32
    public let powerGeneration: UInt32
    public let stationEpoch: UInt32
    public let rocEpoch: UInt32
    public let deadlineUs: UInt64
    public let doorbellUs: UInt64
    public let txRspSeen: Bool
    public let txRspSuccess: Bool
    public let rawTxStatus: UInt16
    public let txRspUs: UInt64
    public let originDoorbellRecorded: Bool
    public let originCompletionRecorded: Bool
    public let exactReply: Test130ExactReplyReceipt?
    public let resourcesAbsent: Bool

    public init(slot: UInt32, packetSerial: UInt64, nonce: Data,
                wifiSequence: UInt16, awdlSequence: UInt16,
                descriptorIndex: UInt32, ssn: UInt16, ownerSerial: UInt64,
                runSerial: UInt64, ifindex: UInt32,
                interfaceIncarnation: UInt64, contextGeneration: UInt32,
                powerGeneration: UInt32, stationEpoch: UInt32, rocEpoch: UInt32,
                deadlineUs: UInt64, doorbellUs: UInt64, txRspSeen: Bool,
                txRspSuccess: Bool, rawTxStatus: UInt16, txRspUs: UInt64,
                originDoorbellRecorded: Bool, originCompletionRecorded: Bool,
                exactReply: Test130ExactReplyReceipt?, resourcesAbsent: Bool) {
        self.slot = slot
        self.packetSerial = packetSerial
        self.nonce = nonce
        self.wifiSequence = wifiSequence
        self.awdlSequence = awdlSequence
        self.descriptorIndex = descriptorIndex
        self.ssn = ssn
        self.ownerSerial = ownerSerial
        self.runSerial = runSerial
        self.ifindex = ifindex
        self.interfaceIncarnation = interfaceIncarnation
        self.contextGeneration = contextGeneration
        self.powerGeneration = powerGeneration
        self.stationEpoch = stationEpoch
        self.rocEpoch = rocEpoch
        self.deadlineUs = deadlineUs
        self.doorbellUs = doorbellUs
        self.txRspSeen = txRspSeen
        self.txRspSuccess = txRspSuccess
        self.rawTxStatus = rawTxStatus
        self.txRspUs = txRspUs
        self.originDoorbellRecorded = originDoorbellRecorded
        self.originCompletionRecorded = originCompletionRecorded
        self.exactReply = exactReply
        self.resourcesAbsent = resourcesAbsent
    }
}

public struct Test130PacketIdentity: Equatable {
    public let slot: UInt32
    public let packetSerial: UInt64
    public let nonce: Data
    public let wifiSequence: UInt16
    public let awdlSequence: UInt16
    public let descriptorIndex: UInt32
    public let ssn: UInt16
    public let ownerSerial: UInt64
    public let runSerial: UInt64
    public let ifindex: UInt32
    public let interfaceIncarnation: UInt64
    public let contextGeneration: UInt32
    public let powerGeneration: UInt32
    public let stationEpoch: UInt32
    public let rocEpoch: UInt32
    public let deadlineUs: UInt64
    public let doorbellUs: UInt64

    public init(slot: UInt32, packetSerial: UInt64, nonce: Data,
                wifiSequence: UInt16, awdlSequence: UInt16,
                descriptorIndex: UInt32, ssn: UInt16, ownerSerial: UInt64,
                runSerial: UInt64, ifindex: UInt32, interfaceIncarnation: UInt64,
                contextGeneration: UInt32, powerGeneration: UInt32,
                stationEpoch: UInt32,
                rocEpoch: UInt32, deadlineUs: UInt64, doorbellUs: UInt64) {
        self.slot = slot; self.packetSerial = packetSerial; self.nonce = nonce
        self.wifiSequence = wifiSequence; self.awdlSequence = awdlSequence
        self.descriptorIndex = descriptorIndex; self.ssn = ssn
        self.ownerSerial = ownerSerial; self.runSerial = runSerial
        self.ifindex = ifindex; self.interfaceIncarnation = interfaceIncarnation
        self.contextGeneration = contextGeneration
        self.powerGeneration = powerGeneration
        self.stationEpoch = stationEpoch; self.rocEpoch = rocEpoch
        self.deadlineUs = deadlineUs; self.doorbellUs = doorbellUs
    }
}

public struct Test130SecondPacketGateInput {
    public let first: Test130PacketReceipt
    public let peerSocketMatchedFirstNonce: Bool
    public let secondReady: Test130PacketSlotReady?
    public let expectedSecondNonce: Data
    public let nowUs: UInt64
    public init(first: Test130PacketReceipt,
                peerSocketMatchedFirstNonce: Bool,
                secondReady: Test130PacketSlotReady?, expectedSecondNonce: Data,
                nowUs: UInt64) {
        self.first = first
        self.peerSocketMatchedFirstNonce = peerSocketMatchedFirstNonce
        self.secondReady = secondReady
        self.expectedSecondNonce = expectedSecondNonce
        self.nowUs = nowUs
    }
}

/// Minimal kernel admission signal for slot 1 before its frame has been
/// queued. Descriptor, SSN and packet serial are intentionally post-doorbell
/// evidence and are checked only by the terminal gate.
public struct Test130PacketSlotReady {
    public let slot: UInt32
    public let ready: Bool
    public let contextGeneration: UInt32
    public let powerGeneration: UInt32
    public let stationEpoch: UInt32
    public let rocEpoch: UInt32
    public let deadlineUs: UInt64
    public let doorbellIssued: Bool

    public init(slot: UInt32, ready: Bool, contextGeneration: UInt32,
                powerGeneration: UInt32, stationEpoch: UInt32,
                rocEpoch: UInt32, deadlineUs: UInt64, doorbellIssued: Bool) {
        self.slot = slot
        self.ready = ready
        self.contextGeneration = contextGeneration
        self.powerGeneration = powerGeneration
        self.stationEpoch = stationEpoch
        self.rocEpoch = rocEpoch
        self.deadlineUs = deadlineUs
        self.doorbellIssued = doorbellIssued
    }
}

public struct Test130GateOutcome {
    public let accepted: Bool
    public let failures: [String]
}

public enum Test130ArmObservedValue: Equatable {
    case missing
    case malformed
    case value(UInt64)
}

public enum Test130ArmTransitionAction: Equatable {
    case wait
    case ready
    case reject(String)
}

public struct Test130ArmTransitionInput {
    public let runTokenMatches: Bool
    public let buildMatches: Bool
    public let stage: Test130ArmObservedValue
    public let packetCount: Test130ArmObservedValue
    public let ready: Test130ArmObservedValue
    public let stageSeen: Bool
    public let packetCountSeen: Bool
    public let deadlineExpired: Bool

    public init(runTokenMatches: Bool, buildMatches: Bool,
                stage: Test130ArmObservedValue,
                packetCount: Test130ArmObservedValue,
                ready: Test130ArmObservedValue,
                stageSeen: Bool, packetCountSeen: Bool,
                deadlineExpired: Bool) {
        self.runTokenMatches = runTokenMatches
        self.buildMatches = buildMatches
        self.stage = stage
        self.packetCount = packetCount
        self.ready = ready
        self.stageSeen = stageSeen
        self.packetCountSeen = packetCountSeen
        self.deadlineExpired = deadlineExpired
    }
}

public struct Test130ArmTransitionOutcome: Equatable {
    public let action: Test130ArmTransitionAction
    public let stageSeen: Bool
    public let packetCountSeen: Bool
    public init(action: Test130ArmTransitionAction, stageSeen: Bool,
                packetCountSeen: Bool) {
        self.action = action
        self.stageSeen = stageSeen
        self.packetCountSeen = packetCountSeen
    }
}

/// Allows only the documented asynchronous ARM publication window. Identity
/// and every present field remain strict; a missing count is provisional only
/// before READY (stage < 4), and may never disappear after first observation.
public func test130EvaluateArmTransition(
    _ input: Test130ArmTransitionInput) -> Test130ArmTransitionOutcome {
    func reject(_ reason: String, _ stageSeen: Bool? = nil,
                _ packetCountSeen: Bool? = nil) -> Test130ArmTransitionOutcome {
        Test130ArmTransitionOutcome(action: .reject(reason),
            stageSeen: stageSeen ?? input.stageSeen,
            packetCountSeen: packetCountSeen ?? input.packetCountSeen)
    }

    guard input.runTokenMatches else { return reject("run_token_changed") }
    guard input.buildMatches else { return reject("build_changed") }
    if case .malformed = input.packetCount {
        return reject("packet_count_malformed")
    }
    let count: UInt64?
    switch input.packetCount {
    case .missing:
        if input.packetCountSeen {
            return reject("packet_count_disappeared")
        }
        count = nil
    case .malformed:
        return reject("packet_count_malformed")
    case let .value(value):
        guard value == 2 else { return reject("packet_count_wrong") }
        count = value
    }
    let seen = input.packetCountSeen || count == 2

    if case .malformed = input.ready { return reject("ready_malformed", nil, seen) }
    let readyValue: UInt64?
    switch input.ready {
    case .missing:
        readyValue = nil
    case .malformed:
        return reject("ready_malformed", nil, seen)
    case let .value(value):
        guard value <= 1 else { return reject("ready_wrong", nil, seen) }
        readyValue = value
    }

    if case .malformed = input.stage {
        return reject("stage_malformed", nil, seen)
    }
    guard case let .value(stage) = input.stage else {
        if input.stageSeen { return reject("stage_disappeared", true, seen) }
        if readyValue == 1 { return reject("ready_stage_missing", false, seen) }
        if input.deadlineExpired { return reject("ready_missing_at_timeout", false, seen) }
        // ARM may be acknowledged before the worker's first stage publication.
        // This provisional state can wait, but can never authorize a send.
        return Test130ArmTransitionOutcome(action: .wait, stageSeen: false,
                                           packetCountSeen: seen)
    }
    let stageSeen = true
    if stage >= 8 { return reject("kernel_terminal_before_ready", stageSeen, seen) }
    if stage > 4 { return reject("ready_stage_passed", stageSeen, seen) }

    if let readyValue, readyValue == 1 {
        guard stage == 4 else { return reject("ready_stage_mismatch", stageSeen, seen) }
        guard count == 2 else { return reject("ready_packet_count_missing", stageSeen, seen) }
        if input.deadlineExpired {
            return reject("arm_transition_timeout", stageSeen, seen)
        }
        return Test130ArmTransitionOutcome(action: .ready, stageSeen: stageSeen,
                                           packetCountSeen: seen)
    }

    // The worker publishes stage 4 just before READY=1. Permit that narrow
    // property-write interval only when the two-packet count is already there.
    if stage == 4 && count == nil {
        return reject("packet_count_missing_at_ready_stage", stageSeen, seen)
    }
    if input.deadlineExpired {
        return reject("ready_missing_at_timeout", stageSeen, seen)
    }
    return Test130ArmTransitionOutcome(action: .wait, stageSeen: stageSeen,
                                       packetCountSeen: seen)
}

/// The only gate that permits the second send. An early UDP return by itself
/// cannot advance the run; the origin receipt and slot-1 READY must also match.
public func test130CanSendSecondPacket(_ input: Test130SecondPacketGateInput) -> Test130GateOutcome {
    let first = input.first
    let exact = first.exactReply
    var failures: [String] = []
    func require(_ condition: Bool, _ name: String) {
        if !condition { failures.append(name) }
    }
    require(first.slot == 0, "first_slot_is_zero")
    require(first.packetSerial > 0, "first_packet_serial_present")
    require(first.ownerSerial > 0 && first.runSerial > 0 && first.ifindex > 0 &&
            first.interfaceIncarnation > 0 && first.contextGeneration > 0 &&
            first.powerGeneration > 0 && first.stationEpoch > 0 && first.rocEpoch > 0,
            "first_run_identity_present")
    require(first.nonce.count == 8 && first.nonce.contains(where: { $0 != 0 }),
            "first_nonce_valid")
    require(first.txRspSeen, "first_tx_rsp_seen")
    require(first.txRspSuccess, "first_tx_rsp_success")
    require(first.originDoorbellRecorded && first.originCompletionRecorded,
            "first_origin_doorbell_and_completion_recorded")
    require(first.txRspUs >= first.doorbellUs && first.txRspUs < first.deadlineUs,
            "first_tx_rsp_inside_window")
    require(first.resourcesAbsent, "first_packet_resources_absent")
    require(input.peerSocketMatchedFirstNonce, "first_peer_nonce_received")
    if let second = input.secondReady {
        require(second.slot == 1 && second.ready, "second_packet_kernel_ready")
        require(input.expectedSecondNonce.count == 8 &&
                input.expectedSecondNonce.contains(where: { $0 != 0 }) &&
                input.expectedSecondNonce != first.nonce, "second_nonce_bound_and_distinct")
        require(second.contextGeneration == first.contextGeneration &&
                second.powerGeneration == first.powerGeneration &&
                second.stationEpoch == first.stationEpoch && second.rocEpoch == first.rocEpoch &&
                second.deadlineUs == first.deadlineUs,
                "second_slot_same_session_and_roc")
        require(!second.doorbellIssued, "second_slot_not_doorbelled_before_gate")
    } else {
        failures.append("second_slot_ready")
    }
    require(input.nowUs >= first.doorbellUs && input.nowUs < first.deadlineUs,
            "same_roc_window_still_open")
    require(first.doorbellUs > 0 && first.deadlineUs > first.doorbellUs,
            "first_deadline_bound")
    if let exact {
        require(exact.snapshotSequence > 0 && (exact.snapshotSequence & 1) == 0 &&
                exact.ticketSerial > 0,
                "first_exact_snapshot_and_ticket_present")
        require(exact.packetSerial == first.packetSerial && exact.slot == 0,
                "first_exact_receipt_packet_identity")
        require(exact.ownerSerial == first.ownerSerial &&
                exact.runSerial == first.runSerial &&
                exact.ifindex == first.ifindex &&
                exact.interfaceIncarnation == first.interfaceIncarnation &&
                exact.contextGeneration == first.contextGeneration &&
                exact.powerGeneration == first.powerGeneration &&
                exact.stationEpoch == first.stationEpoch &&
                exact.rocEpoch == first.rocEpoch,
                "first_exact_receipt_same_session")
        require(exact.captured && exact.delivered && exact.valid,
                "first_exact_reply_delivered")
        require(exact.doorbellUs == first.doorbellUs &&
                exact.doorbellUs <= exact.captureUs &&
                exact.captureUs <= exact.inputUs &&
                exact.inputUs < first.deadlineUs,
                "first_exact_receipt_inside_window")
        require(input.nowUs >= exact.inputUs,
                "first_kernel_return_precedes_second_send")
    } else {
        failures.append("first_exact_receipt_missing")
    }
    return Test130GateOutcome(accepted: failures.isEmpty, failures: failures)
}

/// Per-slot terminal acceptance. Two results are mandatory; no scalar latest
/// receipt may stand in for either packet. Run-level cleanup is checked apart.
public func test130EvaluateTerminal(expectedNonces: [Data],
                                    packets: [Test130PacketReceipt],
                                    peerSocketMatchedNonces: [Bool],
                                    cleanupAck: Bool,
                                    runResourcesAbsent: Bool,
                                    outerReleaseAccepted: Bool,
                                    automaticRetryCount: UInt32) -> Test130GateOutcome {
    var failures: [String] = []
    func require(_ condition: Bool, _ name: String) {
        if !condition { failures.append(name) }
    }
    require(expectedNonces.count == 2 && expectedNonces.allSatisfy({
        $0.count == 8 && $0.contains(where: { $0 != 0 })
    }) && expectedNonces[0] != expectedNonces[1], "two_fresh_ordered_nonces")
    require(packets.count == 2, "exactly_two_packet_receipts")
    require(peerSocketMatchedNonces.count == 2 && peerSocketMatchedNonces.allSatisfy { $0 },
            "two_peer_socket_nonce_returns")
    if packets.count == 2 && expectedNonces.count == 2 && peerSocketMatchedNonces.count == 2 {
        let first = packets[0]
        let second = packets[1]
        require(first.slot == 0 && second.slot == 1, "ordered_packet_slots")
        require(first.packetSerial > 0 && second.packetSerial > 0 &&
                first.packetSerial != second.packetSerial, "distinct_packet_serials")
        require(first.nonce == expectedNonces[0] && second.nonce == expectedNonces[1],
                "nonce_bound_to_each_packet")
        require(first.ownerSerial > 0 && first.runSerial > 0 && first.ifindex > 0 &&
                first.interfaceIncarnation > 0 && first.contextGeneration > 0 &&
                first.stationEpoch > 0 && first.rocEpoch > 0,
                "run_identity_present")
        let sameSession = first.ownerSerial == second.ownerSerial &&
            first.runSerial == second.runSerial && first.ifindex == second.ifindex &&
            first.interfaceIncarnation == second.interfaceIncarnation &&
            first.contextGeneration == second.contextGeneration &&
            first.powerGeneration == second.powerGeneration &&
            first.stationEpoch == second.stationEpoch && first.rocEpoch == second.rocEpoch &&
            first.deadlineUs == second.deadlineUs
        require(sameSession, "both_packets_same_session_and_roc")
        require(first.descriptorIndex != second.descriptorIndex,
                "distinct_live_descriptors")
        require(first.wifiSequence != second.wifiSequence &&
                first.awdlSequence != second.awdlSequence && first.ssn != second.ssn,
                "distinct_packet_sequences")
        require(first.deadlineUs > first.doorbellUs &&
                second.deadlineUs > second.doorbellUs &&
                first.doorbellUs < second.doorbellUs &&
                first.doorbellUs < first.deadlineUs &&
                second.doorbellUs < second.deadlineUs,
                "ordered_doorbells_inside_same_window")
        require(first.txRspSeen && first.txRspSuccess &&
                first.txRspUs >= first.doorbellUs && first.txRspUs < first.deadlineUs,
                "packet_zero_tx_rsp_success")
        require(second.txRspSeen && second.txRspSuccess &&
                second.txRspUs >= second.doorbellUs && second.txRspUs < second.deadlineUs,
                "packet_one_tx_rsp_success")
        require(first.originDoorbellRecorded && first.originCompletionRecorded &&
                second.originDoorbellRecorded && second.originCompletionRecorded,
                "per_packet_origin_doorbell_and_completion_recorded")
        require(first.resourcesAbsent && second.resourcesAbsent,
                "per_packet_dma_resources_absent")
        require(first.exactReply != nil && second.exactReply != nil,
                "both_exact_reply_receipts_present")
        for (packet, expectedSlot, label) in [(first, UInt32(0), "packet_zero"),
                                               (second, UInt32(1), "packet_one")] {
            guard let receipt = packet.exactReply else { continue }
            require(receipt.snapshotSequence > 0 && (receipt.snapshotSequence & 1) == 0 &&
                    receipt.ticketSerial > 0 &&
                    receipt.packetSerial == packet.packetSerial &&
                    receipt.slot == expectedSlot, "\(label)_exact_receipt_packet_identity")
            require(receipt.ownerSerial == packet.ownerSerial &&
                    receipt.runSerial == packet.runSerial && receipt.ifindex == packet.ifindex &&
                    receipt.interfaceIncarnation == packet.interfaceIncarnation &&
                    receipt.contextGeneration == packet.contextGeneration &&
                    receipt.powerGeneration == packet.powerGeneration &&
                    receipt.stationEpoch == packet.stationEpoch &&
                    receipt.rocEpoch == packet.rocEpoch,
                    "\(label)_exact_receipt_same_session")
            require(receipt.captured && receipt.delivered && receipt.valid,
                    "\(label)_exact_reply_delivered")
            require(receipt.doorbellUs == packet.doorbellUs &&
                    receipt.doorbellUs <= receipt.captureUs &&
                    receipt.captureUs <= receipt.inputUs &&
                    receipt.inputUs < packet.deadlineUs,
                    "\(label)_exact_receipt_inside_window")
        }
        if let firstReturn = first.exactReply?.inputUs,
           let secondReturn = second.exactReply?.inputUs {
            require(firstReturn < second.doorbellUs &&
                    first.txRspUs < second.doorbellUs &&
                    second.doorbellUs <= secondReturn,
                    "second_only_after_first_tx_and_exact_return")
        } else {
            failures.append("ordered_exact_returns_present")
        }
        if let firstTicket = first.exactReply?.ticketSerial,
           let secondTicket = second.exactReply?.ticketSerial {
            require(firstTicket > 0 && firstTicket == secondTicket,
                    "same_nonzero_ticket_serial")
        } else {
            failures.append("same_nonzero_ticket_serial")
        }
    }
    require(cleanupAck, "run_cleanup_acknowledged")
    require(runResourcesAbsent, "run_resources_absent")
    require(outerReleaseAccepted, "outer_owner_release_accepted")
    require(automaticRetryCount == 0, "no_automatic_retry")
    return Test130GateOutcome(accepted: failures.isEmpty, failures: failures)
}
