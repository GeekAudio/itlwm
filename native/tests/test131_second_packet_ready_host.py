#!/usr/bin/env python3
"""Execute the production Test131 second-packet READY predicate on the host."""
from pathlib import Path
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[2]
PROBE = (ROOT / "itlwm/hal_iwx/ItlIwxP2PProbe.cpp").read_text()
ACTION = (ROOT / "itlwm/hal_iwx/ItlIwxP2PAction.cpp").read_text()


def extract(source: str, marker: str) -> str:
    start = source.index(marker)
    opening = source.index("{", start)
    depth = 1
    end = opening + 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[start:end]


predicate = extract(PROBE, "static bool directedDataPacket1PreSendReady(")
margin = extract(ACTION, "static bool directedDataSubmitHasDeadlineMargin(")
assert "kDirectedDataSecondSubmitMarginUs = 5000ULL" in ACTION
assert "context->currentSlot == 1 ?" in margin
assert "context->binding.deadlineUs - nowUs >= marginUs" in margin

fixture = r"""
#include <cassert>
#include <cstdint>

namespace NativeAwdlDirectedOriginTx {
constexpr uint64_t kMaximumWindowUs = 100000ULL;
struct Epochs { uint32_t context, power, station, roc; };
inline bool validEpochs(const Epochs &value) {
    return value.context && value.power && value.station && value.roc;
}
inline bool sameEpochs(const Epochs &left, const Epochs &right) {
    return left.context == right.context && left.power == right.power &&
        left.station == right.station && left.roc == right.roc;
}
enum class State { OpenNext, Failed, Expired, Revoked };
struct Ticket {
    uint64_t ticketSerial = 0, ownerSerial = 0, runSerial = 0;
    uint64_t interfaceIncarnation = 0, rocStartUs = 0, deadlineUs = 0;
    uint32_t ifindex = 0;
    Epochs epochs{};
};
struct PacketSnapshot {
    bool present = false, packetQueued = false, packetPopping = false;
    bool packetSpent = false, doorbellObserved = false;
    bool txResponseObserved = false, txSucceeded = false;
    bool replyCaptured = false, replyDelivered = false, exactReplyValid = false;
    uint8_t slot = 0;
    uint64_t packetSerial = 0, doorbellUs = 0, txResponseUs = 0;
    uint64_t replyCaptureUs = 0, replyInputUs = 0;
};
struct Snapshot {
    bool ticketPresent = false, packetQueued = false, packetPopping = false;
    State state = State::Failed;
    uint8_t packetCount = 0;
    uint64_t ticketSerial = 0, ownerSerial = 0, runSerial = 0;
    uint64_t interfaceIncarnation = 0, rocStartUs = 0, deadlineUs = 0;
    uint32_t ifindex = 0;
    Epochs epochs{};
    PacketSnapshot packets[2]{};
};
}

namespace NativeP2PDirectedDataRxInput {
// This deliberately remains a distinct type from the BSD/HAL epoch type.
struct Epochs { uint32_t context, power, station, roc; };
inline bool sameEpochs(const Epochs &left, const Epochs &right) {
    return left.context == right.context && left.power == right.power &&
        left.station == right.station && left.roc == right.roc;
}
struct Lease {
    bool compiled = false, runtimeEnabled = false, profileEnabled = false;
    bool profileSelected = false, ownerCurrent = false, epochsMatch = false;
    bool tokenMatches = false, commandReturned = false;
    bool commandSucceeded = false, goNegotiationConfiguration = false;
    bool channel6Roc = false, startSeen = false, startSucceeded = false;
    bool endSeen = false, outcomeUnknown = false, mccCurrent = false;
    Epochs epochs{};
    uint64_t ownerSerial = 0, startUs = 0, deadlineUs = 0, nowUs = 0;
};
}

namespace IwxMccRefreshPolicy {
struct DirectedDataWitness {
    uint32_t origin, requestSequence, noticeEpoch, firmwareGeneration;
    uint32_t responseStatus, channelCount;
};
inline bool sameDirectedDataWitness(const DirectedDataWitness &left,
                                    const DirectedDataWitness &right) {
    return left.origin == right.origin &&
        left.requestSequence == right.requestSequence &&
        left.noticeEpoch == right.noticeEpoch &&
        left.firmwareGeneration == right.firmwareGeneration &&
        left.responseStatus == right.responseStatus &&
        left.channelCount == right.channelCount;
}
}

constexpr uint32_t IWX_SESSION_PROTECT_CONF_P2P_GO_NEGOTIATION = 6;
enum class TahoeP2PDirectedDataState { kArmed, kTicketBound, kCompleted };
using TahoeP2PDirectedDataEpochs = NativeAwdlDirectedOriginTx::Epochs;
struct Binding {
    uint64_t ownerSerial = 0, runSerial = 0;
    TahoeP2PDirectedDataEpochs epochs{};
    uint32_t generation = 0, p2pFirmwareGeneration = 0;
    uint64_t rocToken = 0, rocStartUs = 0, deadlineUs = 0;
    IwxMccRefreshPolicy::DirectedDataWitness mcc{};
};
struct ProbeArm { uint8_t packetCount = 0; };
struct TahoeP2PDirectedDataPacketSnapshot {
    uint64_t packetToken = 0, doorbellUs = 0, txResponseUs = 0;
    uint64_t exactReplyCaptureUs = 0, exactReplyInputUs = 0;
    uint8_t slot = 0;
    bool identityBound = false, sequenceReserved = false;
    bool permitIssued = false, doorbellIssued = false;
    bool completionObserved = false, frameAttemptSucceeded = false;
    bool exactReplyCaptured = false, exactReplyDelivered = false;
    bool originDoorbellRecorded = false, originCompletionRecorded = false;
    bool resourcesAbsent = false;
};
struct TahoeP2PDirectedDataSnapshot {
    TahoeP2PDirectedDataState state = TahoeP2PDirectedDataState::kArmed;
    uint8_t packetCount = 0, currentSlot = 0;
    uint64_t ticketSerial = 0, ownerSerial = 0, runSerial = 0;
    uint64_t interfaceIncarnation = 0, rocToken = 0, deadlineUs = 0;
    uint32_t generation = 0, p2pFirmwareGeneration = 0, ifindex = 0;
    bool originWindowBound = false, originTicketBound = false;
    bool originClosed = false;
    IwxMccRefreshPolicy::DirectedDataWitness mcc{};
    TahoeP2PDirectedDataPacketSnapshot packets[2]{};
};
struct ProbeRun {
    bool directedDataOnly = true, directedDataTicketBound = true;
    bool directedDataReady = true;
    ProbeArm directedDataArm{2};
    Binding directedDataBinding{};
    IwxMccRefreshPolicy::DirectedDataWitness directedDataPreflightMcc{};
    NativeAwdlDirectedOriginTx::Ticket directedDataOriginTicket{};
    uint32_t contextGeneration = 0, powerGeneration = 0;
    uint32_t stationGeneration = 0, p2pFirmwareGeneration = 0;
};
using P2PProbeRun = ProbeRun;
struct SessionSnapshot {
    uint32_t generation = 0, configuration = 0, startStatus = 0;
    int commandResult = 0;
    bool commandReturned = false, startSeen = false;
    bool endSeen = false, outcomeUnknown = false;
    uint64_t startObservedMonotonicUs = 0;
};
struct RocEventRun {
    SessionSnapshot snapshot{};
    NativeP2PDirectedDataRxInput::Lease directedDataRxLease{};
};
""" + predicate + r"""

struct TestState {
    ProbeRun probe{};
    TahoeP2PDirectedDataSnapshot data{};
    NativeAwdlDirectedOriginTx::Snapshot origin{};
    RocEventRun event{};
    uint64_t nowUs = 0;
};

static TestState validState() {
    constexpr uint64_t start = 1000000ULL;
    constexpr uint64_t deadline = start + 100000ULL;
    constexpr uint64_t now = start + 40000ULL;
    constexpr NativeAwdlDirectedOriginTx::Epochs epochs{9, 11, 12, 9};
    constexpr NativeP2PDirectedDataRxInput::Epochs leaseEpochs{9, 11, 12, 9};
    constexpr IwxMccRefreshPolicy::DirectedDataWitness mcc{1, 2, 3, 4, 5, 51};

    TestState value{};
    value.nowUs = now;
    value.probe.contextGeneration = epochs.context;
    value.probe.powerGeneration = epochs.power;
    value.probe.stationGeneration = epochs.station;
    value.probe.p2pFirmwareGeneration = 14;
    value.probe.directedDataBinding.ownerSerial = 7;
    value.probe.directedDataBinding.runSerial = 8;
    value.probe.directedDataBinding.epochs = epochs;
    value.probe.directedDataBinding.generation = epochs.power;
    value.probe.directedDataBinding.p2pFirmwareGeneration = 14;
    value.probe.directedDataBinding.mcc = mcc;
    value.probe.directedDataPreflightMcc = mcc;
    // These are intentionally absent from the ARM-time copy.
    value.probe.directedDataBinding.rocToken = 0;
    value.probe.directedDataBinding.rocStartUs = 0;
    value.probe.directedDataBinding.deadlineUs = 0;
    value.probe.directedDataOriginTicket.ticketSerial = 22;
    value.probe.directedDataOriginTicket.ownerSerial = 7;
    value.probe.directedDataOriginTicket.runSerial = 8;
    value.probe.directedDataOriginTicket.interfaceIncarnation = 13;
    value.probe.directedDataOriginTicket.ifindex = 15;
    value.probe.directedDataOriginTicket.rocStartUs = start;
    value.probe.directedDataOriginTicket.deadlineUs = deadline;
    value.probe.directedDataOriginTicket.epochs = epochs;

    value.data.state = TahoeP2PDirectedDataState::kCompleted;
    value.data.packetCount = 2;
    value.data.currentSlot = 0;
    value.data.ticketSerial = 22;
    value.data.ownerSerial = 7;
    value.data.runSerial = 8;
    value.data.interfaceIncarnation = 13;
    value.data.ifindex = 15;
    value.data.rocToken = epochs.roc;
    value.data.deadlineUs = deadline;
    value.data.generation = epochs.power;
    value.data.p2pFirmwareGeneration = 14;
    value.data.originWindowBound = true;
    value.data.originTicketBound = true;
    value.data.mcc = mcc;

    auto &first = value.data.packets[0];
    first.slot = 0;
    first.packetToken = 33;
    first.identityBound = true;
    first.sequenceReserved = true;
    first.doorbellIssued = true;
    first.completionObserved = true;
    first.frameAttemptSucceeded = true;
    first.exactReplyCaptured = true;
    first.exactReplyDelivered = true;
    first.originDoorbellRecorded = true;
    first.originCompletionRecorded = true;
    first.resourcesAbsent = true;
    first.doorbellUs = start + 10000ULL;
    first.txResponseUs = start + 20000ULL;
    first.exactReplyCaptureUs = start + 30000ULL;
    first.exactReplyInputUs = start + 31000ULL;

    value.origin.ticketPresent = true;
    value.origin.state = NativeAwdlDirectedOriginTx::State::OpenNext;
    value.origin.packetCount = 2;
    value.origin.ticketSerial = 22;
    value.origin.ownerSerial = 7;
    value.origin.runSerial = 8;
    value.origin.interfaceIncarnation = 13;
    value.origin.ifindex = 15;
    value.origin.rocStartUs = start;
    value.origin.deadlineUs = deadline;
    value.origin.epochs = epochs;
    auto &originFirst = value.origin.packets[0];
    originFirst.present = true;
    originFirst.packetSpent = true;
    originFirst.doorbellObserved = true;
    originFirst.txResponseObserved = true;
    originFirst.txSucceeded = true;
    originFirst.exactReplyValid = true;
    originFirst.replyCaptured = true;
    originFirst.replyDelivered = true;
    originFirst.slot = 0;
    originFirst.packetSerial = 33;
    originFirst.doorbellUs = first.doorbellUs;
    originFirst.txResponseUs = first.txResponseUs;
    originFirst.replyCaptureUs = first.exactReplyCaptureUs;
    originFirst.replyInputUs = first.exactReplyInputUs;

    auto &session = value.event.snapshot;
    session.generation = epochs.context;
    session.configuration = IWX_SESSION_PROTECT_CONF_P2P_GO_NEGOTIATION;
    session.commandReturned = true;
    session.startSeen = true;
    session.startStatus = 1;
    session.startObservedMonotonicUs = start;
    auto &lease = value.event.directedDataRxLease;
    lease.compiled = true;
    lease.runtimeEnabled = true;
    lease.profileEnabled = true;
    lease.profileSelected = true;
    lease.ownerCurrent = true;
    lease.epochsMatch = true;
    lease.tokenMatches = true;
    lease.commandReturned = true;
    lease.commandSucceeded = true;
    lease.goNegotiationConfiguration = true;
    lease.channel6Roc = true;
    lease.startSeen = true;
    lease.startSucceeded = true;
    lease.mccCurrent = true;
    lease.epochs = leaseEpochs;
    lease.ownerSerial = 7;
    lease.startUs = start;
    lease.deadlineUs = deadline;
    lease.nowUs = now - 1000ULL;
    return value;
}

static bool ready(const TestState &value) {
    return directedDataPacket1PreSendReady(
        &value.probe, value.data, value.origin, &value.event, value.nowUs);
}

int main() {
    const TestState base = validState();
    assert(base.probe.directedDataBinding.rocToken == 0);
    assert(base.probe.directedDataBinding.rocStartUs == 0);
    assert(base.probe.directedDataBinding.deadlineUs == 0);
    assert(ready(base));

    auto rejects = [](TestState value) { assert(!ready(value)); };
    auto changed = base;
    changed.data.ownerSerial++;
    rejects(changed);
    changed = base;
    changed.event.directedDataRxLease.epochs.power++;
    rejects(changed);
    changed = base;
    changed.data.rocToken++;
    rejects(changed);
    changed = base;
    changed.origin.deadlineUs++;
    rejects(changed);
    changed = base;
    changed.event.snapshot.endSeen = true;
    rejects(changed);
    changed = base;
    changed.nowUs = changed.data.deadlineUs;
    changed.event.directedDataRxLease.nowUs = changed.nowUs;
    rejects(changed);
    changed = base;
    changed.data.packets[0].resourcesAbsent = false;
    rejects(changed);
    changed = base;
    changed.data.packets[1].identityBound = true;
    rejects(changed);
    changed = base;
    changed.event.directedDataRxLease.mccCurrent = false;
    rejects(changed);
    changed = base;
    changed.data.state = TahoeP2PDirectedDataState::kTicketBound;
    rejects(changed);
}
"""

with tempfile.TemporaryDirectory(prefix="test131-second-ready-") as tmp:
    source = Path(tmp) / "second_ready.cpp"
    binary = Path(tmp) / "second_ready"
    source.write_text(fixture)
    compiled = subprocess.run(
        ["c++", "-std=c++14", "-Wall", "-Wextra", "-Werror",
         "-fsanitize=address,undefined", str(source), "-o", str(binary)],
        text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    if compiled.returncode:
        raise SystemExit(compiled.stdout)
    subprocess.run([str(binary)], check=True)

print("Test131 second-packet READY predicate passed")
