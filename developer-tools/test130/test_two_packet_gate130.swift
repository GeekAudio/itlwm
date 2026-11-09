// SPDX-License-Identifier: GPL-2.0-only
import Foundation

func expect(_ outcome: Test130GateOutcome, _ accepted: Bool, _ label: String) {
    precondition(outcome.accepted == accepted,
                 "\(label): expected \(accepted), got \(outcome.failures)")
}
func nonce(_ value: UInt8) -> Data { Data(repeating: value, count: 8) }
func identity(_ slot: UInt32, packetSerial: UInt64? = nil,
              nonceValue: Data? = nil, descriptor: UInt32? = nil,
              wifiSequence: UInt16? = nil, awdlSequence: UInt16? = nil,
              ssn: UInt16? = nil, deadline: UInt64 = 200,
              doorbell: UInt64? = nil, context: UInt32 = 3,
              power: UInt32 = 5, station: UInt32 = 7,
              roc: UInt32 = 9) -> Test130PacketIdentity {
    Test130PacketIdentity(slot: slot, packetSerial: packetSerial ?? 100 + UInt64(slot),
        nonce: nonceValue ?? nonce(UInt8(0x10 + slot)),
        wifiSequence: wifiSequence ?? UInt16(0x210 + slot),
        awdlSequence: awdlSequence ?? UInt16(0x310 + slot),
        descriptorIndex: descriptor ?? 16 + slot, ssn: ssn ?? UInt16(20 + slot),
        ownerSerial: 11, runSerial: 13, ifindex: 4, interfaceIncarnation: 17,
        contextGeneration: context, powerGeneration: power, stationEpoch: station,
        rocEpoch: roc, deadlineUs: deadline,
        doorbellUs: doorbell ?? (slot == 0 ? 100 : 140))
}
func slotReady(_ slot: UInt32 = 1, ready: Bool = true,
               context: UInt32 = 3, power: UInt32 = 5,
               station: UInt32 = 7, roc: UInt32 = 9,
               deadline: UInt64 = 200,
               doorbellIssued: Bool = false) -> Test130PacketSlotReady {
    Test130PacketSlotReady(slot: slot, ready: ready, contextGeneration: context,
        powerGeneration: power, stationEpoch: station, rocEpoch: roc,
        deadlineUs: deadline, doorbellIssued: doorbellIssued)
}
func exact(_ identity: Test130PacketIdentity,
           ticket: UInt64? = nil, slot: UInt32? = nil,
           packetSerial: UInt64? = nil, delivered: Bool = true,
           capture: UInt64? = nil, input: UInt64? = nil,
           context: UInt32? = nil, power: UInt32? = nil, valid: Bool = true,
           station: UInt32? = nil, roc: UInt32? = nil) -> Test130ExactReplyReceipt {
    let base = identity.doorbellUs
    return Test130ExactReplyReceipt(snapshotSequence: 4,
        ticketSerial: ticket ?? 900,
        packetSerial: packetSerial ?? identity.packetSerial,
        slot: slot ?? identity.slot, ownerSerial: identity.ownerSerial,
        runSerial: identity.runSerial, ifindex: identity.ifindex,
        interfaceIncarnation: identity.interfaceIncarnation,
        contextGeneration: context ?? identity.contextGeneration,
        powerGeneration: power ?? identity.powerGeneration,
        stationEpoch: station ?? identity.stationEpoch, rocEpoch: roc ?? identity.rocEpoch,
        doorbellUs: base, captureUs: capture ?? base + 1,
        inputUs: input ?? base + 2, captured: true, delivered: delivered,
        valid: valid)
}
func receipt(_ id: Test130PacketIdentity, tx: Bool = true,
             originDoorbell: Bool = true, originCompletion: Bool = true,
             resourceAbsent: Bool = true,
             txRspUs: UInt64? = nil,
             exactReply: Test130ExactReplyReceipt? = nil) -> Test130PacketReceipt {
    Test130PacketReceipt(slot: id.slot, packetSerial: id.packetSerial, nonce: id.nonce,
        wifiSequence: id.wifiSequence, awdlSequence: id.awdlSequence,
        descriptorIndex: id.descriptorIndex, ssn: id.ssn,
        ownerSerial: id.ownerSerial, runSerial: id.runSerial,
        ifindex: id.ifindex, interfaceIncarnation: id.interfaceIncarnation,
        contextGeneration: id.contextGeneration,
        powerGeneration: id.powerGeneration,
        stationEpoch: id.stationEpoch, rocEpoch: id.rocEpoch,
        deadlineUs: id.deadlineUs, doorbellUs: id.doorbellUs,
        txRspSeen: tx, txRspSuccess: tx, rawTxStatus: 0,
        txRspUs: txRspUs ?? id.doorbellUs + 1,
        originDoorbellRecorded: originDoorbell,
        originCompletionRecorded: originCompletion,
        exactReply: exactReply ?? exact(id), resourcesAbsent: resourceAbsent)
}
func terminal(_ packets: [Test130PacketReceipt],
              matched: [Bool] = [true, true], cleanup: Bool = true,
              runResources: Bool = true, outer: Bool = true,
              retries: UInt32 = 0,
              nonces: [Data] = [nonce(0x10), nonce(0x11)]) -> Test130GateOutcome {
    test130EvaluateTerminal(expectedNonces: nonces, packets: packets,
        peerSocketMatchedNonces: matched, cleanupAck: cleanup,
        runResourcesAbsent: runResources, outerReleaseAccepted: outer,
        automaticRetryCount: retries)
}

@main
struct Test130Main {
static func main() {
let firstId = identity(0)
let secondId = identity(1)
let firstReceipt = receipt(firstId, exactReply: exact(firstId, capture: 110, input: 130))
let secondReceipt = receipt(secondId, exactReply: exact(secondId, capture: 150, input: 160))
expect(terminal([firstReceipt, secondReceipt]), true, "complete ordered run")

let validSecondGate = Test130SecondPacketGateInput(
    first: firstReceipt, peerSocketMatchedFirstNonce: true,
    secondReady: slotReady(), expectedSecondNonce: nonce(0x11), nowUs: 135)
expect(test130CanSendSecondPacket(validSecondGate), true, "second send gate")
expect(test130CanSendSecondPacket(Test130SecondPacketGateInput(
    first: firstReceipt, peerSocketMatchedFirstNonce: true,
    secondReady: nil, expectedSecondNonce: nonce(0x11), nowUs: 135)),
    false, "slot 1 must be ready")
expect(test130CanSendSecondPacket(Test130SecondPacketGateInput(
    first: receipt(firstId, tx: false,
                   exactReply: exact(firstId, capture: 110, input: 130)),
    peerSocketMatchedFirstNonce: true, secondReady: slotReady(),
    expectedSecondNonce: nonce(0x11), nowUs: 135)), false, "TX_RSP required")
expect(test130CanSendSecondPacket(Test130SecondPacketGateInput(
    first: receipt(firstId, originCompletion: false,
                   exactReply: exact(firstId, capture: 110, input: 130)),
    peerSocketMatchedFirstNonce: true, secondReady: slotReady(),
    expectedSecondNonce: nonce(0x11), nowUs: 135)), false, "origin completion required")
expect(test130CanSendSecondPacket(Test130SecondPacketGateInput(
    first: firstReceipt, peerSocketMatchedFirstNonce: true,
    secondReady: slotReady(context: 99),
    expectedSecondNonce: nonce(0x11), nowUs: 135)), false, "same lease generations")
expect(test130CanSendSecondPacket(Test130SecondPacketGateInput(
    first: firstReceipt, peerSocketMatchedFirstNonce: true,
    secondReady: slotReady(power: 99),
    expectedSecondNonce: nonce(0x11), nowUs: 135)), false, "same power generation")
expect(test130CanSendSecondPacket(Test130SecondPacketGateInput(
    first: firstReceipt, peerSocketMatchedFirstNonce: true,
    secondReady: slotReady(ready: false),
    expectedSecondNonce: nonce(0x11), nowUs: 135)), false, "kernel pre-send ready required")
expect(test130CanSendSecondPacket(Test130SecondPacketGateInput(
    first: firstReceipt, peerSocketMatchedFirstNonce: true,
    secondReady: slotReady(doorbellIssued: true),
    expectedSecondNonce: nonce(0x11), nowUs: 135)), false, "one-way doorbell gate")
expect(test130CanSendSecondPacket(Test130SecondPacketGateInput(
    first: firstReceipt, peerSocketMatchedFirstNonce: false,
    secondReady: slotReady(), expectedSecondNonce: nonce(0x11), nowUs: 135)),
    false, "socket nonce alone is required")
expect(test130CanSendSecondPacket(Test130SecondPacketGateInput(
    first: firstReceipt, peerSocketMatchedFirstNonce: true,
    secondReady: slotReady(), expectedSecondNonce: nonce(0x11), nowUs: 200)),
    false, "expired window")

expect(terminal([firstReceipt]), false, "missing second packet")
expect(terminal([firstReceipt, receipt(secondId, tx: false)]), false, "second TX missing")
expect(terminal([firstReceipt, receipt(secondId, originDoorbell: false)]),
    false, "per-packet doorbell record")
expect(terminal([firstReceipt, receipt(secondId,
    exactReply: exact(secondId, slot: 0))]), false, "wrong RX slot")
expect(terminal([firstReceipt, receipt(secondId,
    exactReply: exact(secondId, packetSerial: firstId.packetSerial))]),
    false, "latest receipt cannot cover both packets")
expect(terminal([firstReceipt, receipt(secondId,
    exactReply: exact(secondId, delivered: false))]), false, "ifnet input required")
expect(terminal([firstReceipt, receipt(secondId,
    exactReply: exact(secondId, context: 99))]), false, "epoch binding")
expect(terminal([firstReceipt, receipt(secondId,
    exactReply: exact(secondId, power: 99))]), false, "power epoch binding")
expect(terminal([firstReceipt, receipt(identity(1, nonceValue: nonce(0x10)))]),
    false, "nonce replay")
expect(terminal([firstReceipt,
    receipt(identity(1, doorbell: 129),
            exactReply: exact(identity(1, doorbell: 129), capture: 130, input: 131))]),
    false, "second send precedes first kernel return")
expect(terminal([receipt(firstId, txRspUs: 141), secondReceipt]),
    false, "second send cannot precede first TX completion")
expect(terminal([firstReceipt, receipt(secondId,
    exactReply: exact(secondId, ticket: 901))]),
    false, "both packet receipts must share one ticket")
expect(terminal([firstReceipt, receipt(secondId,
    exactReply: Test130ExactReplyReceipt(snapshotSequence: 3, ticketSerial: 900,
        packetSerial: secondId.packetSerial, slot: 1, ownerSerial: secondId.ownerSerial,
        runSerial: secondId.runSerial, ifindex: secondId.ifindex,
        interfaceIncarnation: secondId.interfaceIncarnation,
        contextGeneration: secondId.contextGeneration,
        powerGeneration: secondId.powerGeneration, stationEpoch: secondId.stationEpoch,
        rocEpoch: secondId.rocEpoch, doorbellUs: secondId.doorbellUs,
        captureUs: secondId.doorbellUs + 1, inputUs: secondId.doorbellUs + 2,
        captured: true, delivered: true, valid: true))]),
    false, "exact reply snapshot sequence must be even")
expect(terminal([firstReceipt, secondReceipt], matched: [true, false]),
    false, "second peer return missing")
expect(terminal([firstReceipt, secondReceipt], cleanup: false), false, "cleanup ack")
expect(terminal([firstReceipt, secondReceipt], runResources: false), false, "run cleanup")
expect(terminal([firstReceipt, secondReceipt], outer: false), false, "outer release")
expect(terminal([firstReceipt, secondReceipt], retries: 1), false, "no retries")
expect(terminal([firstReceipt, secondReceipt], nonces: [nonce(0x10), nonce(0x10)]),
    false, "fresh nonce pair")
print("PASS: ordered two-packet gate rejects missing, replayed, stale, wrong-slot and latest-only evidence")
}
}
