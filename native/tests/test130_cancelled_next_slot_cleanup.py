#!/usr/bin/env python3
"""Exercise the production two-packet unsubmitted-slot retirement policy."""
from pathlib import Path
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[2]
ACTION_PATH = ROOT / "itlwm/hal_iwx/ItlIwxP2PAction.cpp"
DATA_PATH = ROOT / "itlwm/hal_iwx/ItlIwxP2PData.hpp"
ACTION = ACTION_PATH.read_text()
DATA = DATA_PATH.read_text()


def extract(source: str, marker: str) -> str:
    start = source.index(marker)
    opening = source.index("{", start)
    depth = 1
    end = opening + 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[start:end]


states = extract(DATA, "enum class TahoeP2PDirectedDataState : uint8_t {") + ";"
reasons = extract(DATA, "enum class TahoeP2PDirectedDataReason : uint8_t {") + ";"
all_completed = extract(ACTION, "static bool directedDataAllDoorbellsCompleted(")
has_doorbell = extract(ACTION, "static bool directedDataHasDoorbellHistory(")
record_cancel = extract(ACTION, "static void directedDataRecordUnsubmittedSlot(")
evidence = extract(ACTION, "struct DirectedDataUnsubmittedNextSlotEvidence {") + ";"
retire = extract(ACTION, "static bool directedDataRetireUnsubmittedNextSlot(")
close_commit = extract(ACTION, "static IOReturn directedDataCommitCloseAction(")
close_wrapper = extract(ACTION, "static bool directedDataRetireUnsubmittedNextSlotOnMainGate(")
fail_before = extract(ACTION, "static int directedDataFailBeforeDoorbell(")
submit = extract(ACTION, "static int directedDataTxSubmitOnMainGate(")

# The pure production transition is only called after origin closure and a
# lock-protected active-queue/ring snapshot. It may retire an unused slot, but
# it may never erase an unknown doorbell or treat slot zero as slot one.
assert close_commit.index("context->originClosed = true;") < \
       close_commit.index("directedDataRetireUnsubmittedNextSlotOnMainGate(") < \
       close_commit.index("if (anyDoorbell && (")
assert "context->state == TahoeP2PDirectedDataState::kTicketBound" in close_commit
assert "context->state == TahoeP2PDirectedDataState::kPermitIssued" in close_commit
assert "context->packets[1].doorbellIssued" in close_commit
assert "iwx_tahoe_p2p_tvqm_lock_completion" in close_wrapper
assert "lifecycle.outstandingTx == 0 && lifecycle.completionObserved" in close_wrapper
assert "ring->cur == ring->tail" in close_wrapper
assert "ring->data[index].m || ring->data[index].in" in close_wrapper
assert close_wrapper.index("iwx_tahoe_p2p_tvqm_unlock") < \
       close_wrapper.index("directedDataRetireUnsubmittedNextSlot(context")
assert "directedDataRecordUnsubmittedSlot(context, reason);" in fail_before
assert "directedDataRecordUnsubmittedSlot(context," in submit
assert "directedDataRecordUnsubmittedSlot(context, reason);" in submit
assert "if (cancelError)" in submit
assert "if (queueCancelError)" in submit

fixture = r'''
#include <cassert>
#include <cstdint>
#include <initializer_list>
''' + states + "\n" + reasons + r'''
struct CompletionSnapshot { bool armed = false; bool completed = false; };
struct Completion {
    CompletionSnapshot value{};
    CompletionSnapshot snapshot() const { return value; }
};
struct Packet {
    bool identityBound = false;
    bool sequenceReserved = false;
    bool permitIssued = false;
    bool doorbellIssued = false;
    bool completionObserved = false;
    bool frameAttemptSucceeded = false;
    bool resourcesAbsent = false;
};
struct Permit { bool valid = false; };
struct TahoeP2PDirectedDataContext {
    Completion completion;
    Permit permit;
    Packet packets[2];
    TahoeP2PDirectedDataState state = TahoeP2PDirectedDataState::kIdle;
    TahoeP2PDirectedDataReason reason = TahoeP2PDirectedDataReason::kNone;
    bool sequenceReservationValid = false;
    bool permitIssued = false;
    bool completionObserved = false;
    bool frameAttemptSucceeded = false;
    bool mbufHeldByRing = false;
    bool ticketBound = false;
    bool originClosed = false;
    uint8_t packetCount = 2;
    uint8_t currentSlot = 1;
};
''' + all_completed + "\n" + has_doorbell + "\n" + record_cancel + "\n" + \
    evidence + "\n" + retire + r'''

static TahoeP2PDirectedDataContext validRun() {
    TahoeP2PDirectedDataContext c{};
    c.ticketBound = true;
    c.originClosed = true;
    c.state = TahoeP2PDirectedDataState::kTicketBound;
    c.sequenceReservationValid = true;
    c.permitIssued = true;
    c.permit.valid = true;
    c.packets[0].identityBound = true;
    c.packets[0].doorbellIssued = true;
    c.packets[0].completionObserved = true;
    c.packets[0].frameAttemptSucceeded = true;
    c.packets[0].resourcesAbsent = true;
    c.packets[1].sequenceReserved = true;
    c.packets[1].permitIssued = true;
    c.completion.value = {true, true};
    return c;
}

int main() {
    // Reserve sequences, then END/expiry before the second origin packet pops.
    auto reserved = validRun();
    const DirectedDataUnsubmittedNextSlotEvidence clean{true, true, true};
    assert(directedDataRetireUnsubmittedNextSlot(&reserved, clean));
    assert(reserved.state == TahoeP2PDirectedDataState::kCompleted);
    assert(reserved.completionObserved && !reserved.frameAttemptSucceeded);
    assert(reserved.packets[1].resourcesAbsent);
    assert(!reserved.packets[1].sequenceReserved &&
           !reserved.sequenceReservationValid);
    assert(!reserved.packets[1].permitIssued && !reserved.permitIssued &&
           !reserved.permit.valid);

    // A popped but rejected packet or a permit that never reached TX can be
    // retired only under the same exact origin/queue/ring proofs.
    for (auto state : {TahoeP2PDirectedDataState::kPermitIssued,
                       TahoeP2PDirectedDataState::kClosed}) {
        auto candidate = validRun();
        candidate.state = state;
        assert(directedDataRetireUnsubmittedNextSlot(&candidate, clean));
        assert(candidate.state == TahoeP2PDirectedDataState::kCompleted);
        assert(!candidate.frameAttemptSucceeded);
    }

    auto endRace = validRun();
    auto noInactiveOrigin = clean;
    noInactiveOrigin.originInactive = false;
    assert(!directedDataRetireUnsubmittedNextSlot(&endRace,
                                                   noInactiveOrigin));
    assert(endRace.packets[1].sequenceReserved && endRace.permit.valid);
    auto busyQueue = validRun();
    auto outstanding = clean;
    outstanding.queueCurrent = false;
    assert(!directedDataRetireUnsubmittedNextSlot(&busyQueue, outstanding));
    auto dirtyRing = validRun();
    auto ringNotDrained = clean;
    ringNotDrained.ringAndQueueDrained = false;
    assert(!directedDataRetireUnsubmittedNextSlot(&dirtyRing,
                                                   ringNotDrained));

    // A slot-one doorbell without exact completion is never converted into a
    // clean cancellation, and unknown DMA remains quarantined.
    auto unknown = validRun();
    unknown.state = TahoeP2PDirectedDataState::kQuarantined;
    assert(!directedDataRetireUnsubmittedNextSlot(&unknown, clean));
    assert(unknown.state == TahoeP2PDirectedDataState::kQuarantined);
    auto secondSubmitted = validRun();
    secondSubmitted.packets[1].doorbellIssued = true;
    secondSubmitted.packets[1].completionObserved = false;
    secondSubmitted.packets[1].resourcesAbsent = false;
    assert(!directedDataRetireUnsubmittedNextSlot(&secondSubmitted, clean));
    auto missingFirstAck = validRun();
    missingFirstAck.packets[0].completionObserved = false;
    missingFirstAck.packets[0].resourcesAbsent = false;
    assert(!directedDataRetireUnsubmittedNextSlot(&missingFirstAck, clean));

    // The real pre-doorbell cancellation record clears a permit/reservation,
    // but never claims a successful packet attempt.
    auto cancelled = validRun();
    directedDataRecordUnsubmittedSlot(&cancelled,
        TahoeP2PDirectedDataReason::kExpired);
    assert(cancelled.state == TahoeP2PDirectedDataState::kCompleted);
    assert(!cancelled.packets[1].sequenceReserved &&
           !cancelled.sequenceReservationValid);
    assert(!cancelled.packets[1].permitIssued && !cancelled.permit.valid);
    assert(cancelled.packets[1].resourcesAbsent &&
           !cancelled.frameAttemptSucceeded);

    auto quarantinedCancel = validRun();
    quarantinedCancel.state = TahoeP2PDirectedDataState::kQuarantined;
    directedDataRecordUnsubmittedSlot(&quarantinedCancel,
        TahoeP2PDirectedDataReason::kExpired);
    assert(quarantinedCancel.state == TahoeP2PDirectedDataState::kQuarantined);
}
'''

with tempfile.TemporaryDirectory(prefix="test130-cancelled-slot-") as tmp:
    cpp = Path(tmp) / "cancelled_slot.cpp"
    binary = Path(tmp) / "cancelled_slot"
    cpp.write_text(fixture)
    subprocess.run(
        ["xcrun", "clang++", "-std=c++14", "-Wall", "-Wextra", "-Werror",
         "-fsanitize=address,undefined", "-fno-sanitize-recover=all",
         str(cpp), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)

print("Test130: cancelled next-slot retirement preserves all DMA/END gates")
