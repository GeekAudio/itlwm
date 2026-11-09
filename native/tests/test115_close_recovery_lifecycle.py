#!/usr/bin/env python3
"""Run production close/snapshot/recovery fragments through lifecycle cases."""
from pathlib import Path
import re
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[2]
ACTION = (ROOT / "itlwm/hal_iwx/ItlIwxP2PAction.cpp").read_text()
DATA = (ROOT / "itlwm/hal_iwx/ItlIwxP2PData.hpp").read_text()
PROBE = (ROOT / "itlwm/hal_iwx/ItlIwxP2PProbe.cpp").read_text()


def extract_block(source: str, marker: str) -> str:
    start = source.index(marker)
    opening = source.index("{", start)
    depth = 1
    end = opening + 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[start:end]


def extract_statement(source: str, marker: str) -> str:
    start = source.index(marker)
    end = source.index(";", start) + 1
    return source[start:end]


def extract_assignment(source: str, marker: str) -> str:
    start = source.index(marker)
    end = source.index(";", start) + 1
    return source[start:end]


state_enum = extract_block(DATA, "enum class TahoeP2PDirectedDataState") + ";"
reason_enum = extract_block(DATA, "enum class TahoeP2PDirectedDataReason") + ";"
identity = extract_block(ACTION, "struct DirectedDataCloseIdentity") + ";"
commit_struct = extract_block(ACTION, "struct DirectedDataCloseCommit") + ";"
capture_identity = extract_block(
    ACTION, "static IOReturn directedDataCaptureCloseIdentityAction(")
commit_close = extract_block(
    ACTION, "static IOReturn directedDataCommitCloseAction(")
set_may_own = extract_block(ACTION, "static void directedDataSetMayOwnResource(")
can_clear = extract_block(
    ACTION, "static bool directedDataCanClearMayOwnResource(")
mark_completed = extract_block(
    ACTION, "static void directedDataMarkCompletedClosed(")
has_doorbell = extract_block(
    ACTION, "static bool directedDataHasDoorbellHistory(")
all_doorbells_completed = extract_block(
    ACTION, "static bool directedDataAllDoorbellsCompleted(")
quarantine = extract_block(
    ACTION, "void iwx_tahoe_p2p_directed_data_quarantine(")

snapshot_fn = extract_block(ACTION, "static bool directedDataCaptureSnapshot(")
packet_snapshot = extract_block(
    DATA, "struct TahoeP2PDirectedDataPacketSnapshot") + ";"
snapshot_prefix = extract_statement(
    snapshot_fn, "const auto completion = context->completion.snapshot()")
snapshot_fields = []
for field in (
    "originTicketBound", "originClosed", "completionArmed",
    "doorbellIssued", "completionObserved", "mbufHeldByRing",
):
    statement = extract_assignment(snapshot_fn, f"value.{field} =")
    assert statement, f"missing production snapshot mapping for {field}"
    snapshot_fields.append(statement)

# Snapshot completion is an aggregate of actual submitted per-slot completions
# and resource absence. A stale generic completion flag or empty set cannot
# satisfy it.
assert "if (!packet.doorbellIssued)" in all_doorbells_completed
assert "!packet.completionObserved || !packet.resourcesAbsent" in all_doorbells_completed
assert "return anyDoorbell;" in all_doorbells_completed
assert "value.doorbellIssued = directedDataHasDoorbellHistory(context);" in snapshot_fn
assert re.search(
    r"value\.completionObserved\s*=\s*value\.doorbellIssued\s*&&\s*"
    r"directedDataAllDoorbellsCompleted\(context\);", snapshot_fn)

close_fn = extract_block(ACTION, "int iwx_tahoe_p2p_directed_data_close(")
inactive_assignment = extract_statement(
    close_fn, "commit.originInactive =\n            origin.state")
inactive_expression = inactive_assignment.split("=", 1)[1].strip()[:-1]

origin_closed_expression = extract_statement(
    PROBE, "const bool originClosed = !run->directedDataTicketBound")
no_doorbell_marker = "const bool noDoorbell = dataValid && !data.doorbellIssued"
no_doorbell_expression = extract_statement(
    PROBE[PROBE.rindex(no_doorbell_marker):], no_doorbell_marker)

# These are the safety gates being covered here. The ticket-closed fix must
# not erase the separate no-doorbell, queue, and resource-retirement proofs.
assert "!run->directedDataTicketBound" in origin_closed_expression
assert "data.originClosed && !data.originTicketBound" in origin_closed_expression
assert "!data.mbufHeldByRing && !data.completionArmed" in no_doorbell_expression
assert "!data.completionObserved" in no_doorbell_expression
assert "directedDataHasNoDoorbell(owner)" in no_doorbell_expression
assert "if (identity.ticketBound && !identity.originClosed)" in close_fn
assert "directedDataCanClearMayOwnResource(context)" in commit_close
assert "context->ticketBound == identity->ticketBound" in commit_close
assert "sameTicket(" in commit_close

fixture = r"""
#include <cassert>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <initializer_list>
#include "awdl_directed_origin_tx.hpp"

using IOReturn = int;
struct OSObject {};
constexpr IOReturn kIOReturnSuccess = 0;
constexpr IOReturn kIOReturnBadArgument = -1;

""" + state_enum + "\n" + reason_enum + r"""
using TahoeP2PDirectedDataOriginTicket = NativeAwdlDirectedOriginTx::Ticket;

struct CompletionSnapshot { bool armed = false; bool completed = false; };
struct Completion {
    CompletionSnapshot value{};
    CompletionSnapshot snapshot() const { return value; }
};
struct TxWitness {
    void rememberClose(uint64_t, uint32_t) {}
};
static uint64_t directedDataMonotonicUs() { return 1000; }
static constexpr uint8_t kTahoeP2PDirectedDataMaxPackets = 2;
""" + packet_snapshot + r"""
struct TahoeP2PDirectedDataContext {
    struct Binding { uint64_t ownerSerial = 0; uint64_t runSerial = 0; } binding;
    Completion completion;
    TxWitness txWitness;
    TahoeP2PDirectedDataOriginTicket originTicket{};
    TahoeP2PDirectedDataState state = TahoeP2PDirectedDataState::kIdle;
    TahoeP2PDirectedDataReason reason = TahoeP2PDirectedDataReason::kNone;
    uint64_t armSerialHighWater = 0;
    uint8_t currentSlot = 0;
    uint32_t mayOwnResource = 0;
    bool ticketBound = false;
    bool originClosed = false;
    bool doorbellIssued = false;
    bool completionObserved = false;
    bool mbufHeldByRing = false;
    bool hardStopDrained = false;
    uint8_t packetCount = 0;
    TahoeP2PDirectedDataPacketSnapshot
        packets[kTahoeP2PDirectedDataMaxPackets]{};
};
struct TahoeP2PDirectedDataSnapshot {
    TahoeP2PDirectedDataState state = TahoeP2PDirectedDataState::kIdle;
    bool originTicketBound = false;
    bool originClosed = false;
    bool completionArmed = false;
    bool doorbellIssued = false;
    bool completionObserved = false;
    bool mbufHeldByRing = false;
};
struct ItlIwx {
    bool onMainGate = true;
    bool hardwareNoDoorbell = true;
    bool tahoeP2pOnMainGate() const { return onMainGate; }
};
static bool directedDataHasNoDoorbell(ItlIwx *owner) {
    return owner && owner->hardwareNoDoorbell;
}

""" + identity + "\n" + commit_struct + "\n" + capture_identity + "\n" + \
    mark_completed + "\n" + has_doorbell + "\n" + \
    all_doorbells_completed + "\n" + set_may_own + "\n" + can_clear + "\n" + \
    quarantine + r"""

static bool directedDataRetireUnsubmittedNextSlotOnMainGate(
    ItlIwx *, TahoeP2PDirectedDataContext *, bool) { return false; }
""" + commit_close + r"""

static TahoeP2PDirectedDataSnapshot captureSnapshot(
    const TahoeP2PDirectedDataContext *context) {
    const auto completion = context->completion.snapshot();
    TahoeP2PDirectedDataSnapshot value{};
""" + "\n".join(snapshot_fields) + r"""
    value.state = context->state;
    return value;
}

static bool actualOriginInactive(
    const NativeAwdlDirectedOriginTx::Snapshot &origin) {
    return """ + inactive_expression + r""";
}

struct Run {
    bool directedDataTicketBound = false;
    TahoeP2PDirectedDataOriginTicket directedDataOriginTicket{};
};
static bool actualTicketClosed(
    Run *run, bool dataValid, const TahoeP2PDirectedDataSnapshot &data,
    const NativeAwdlDirectedOriginTx::Snapshot &origin) {
    """ + origin_closed_expression + r"""
    return originClosed;
}
static bool actualNoDoorbell(
    ItlIwx *owner, bool dataValid, const TahoeP2PDirectedDataSnapshot &data) {
    """ + no_doorbell_expression + r"""
    return noDoorbell;
}

static TahoeP2PDirectedDataContext makeContext() {
    TahoeP2PDirectedDataContext context{};
    context.armSerialHighWater = 17;
    context.binding.ownerSerial = 21;
    context.binding.runSerial = 34;
    context.ticketBound = true;
    context.state = TahoeP2PDirectedDataState::kTicketBound;
    context.mayOwnResource = 1;
    context.originTicket.ticketSerial = 55;
    context.originTicket.ownerSerial = 21;
    context.originTicket.runSerial = 34;
    context.originTicket.interfaceIncarnation = 89;
    context.originTicket.rocStartUs = 1000;
    context.originTicket.deadlineUs = 101000;
    context.originTicket.ifindex = 7;
    context.originTicket.epochs = {3, 5, 8, 13};
    return context;
}

static void setPacket(TahoeP2PDirectedDataContext &context, uint8_t slot,
                     bool doorbell, bool completed, bool resourcesAbsent) {
    context.packets[slot].doorbellIssued = doorbell;
    context.packets[slot].completionObserved = completed;
    context.packets[slot].resourcesAbsent = resourcesAbsent;
}

static NativeAwdlDirectedOriginTx::Snapshot closedOrigin(
    const TahoeP2PDirectedDataContext &context) {
    NativeAwdlDirectedOriginTx::Snapshot origin{};
    origin.state = NativeAwdlDirectedOriginTx::State::Closed;
    origin.ticketPresent = true;
    origin.ticketSerial = context.originTicket.ticketSerial;
    origin.ownerSerial = context.originTicket.ownerSerial;
    origin.runSerial = context.originTicket.runSerial;
    return origin;
}

static DirectedDataCloseIdentity captureIdentity(
    ItlIwx &owner, TahoeP2PDirectedDataContext &context) {
    DirectedDataCloseIdentity identity{};
    identity.context = &context;
    assert(directedDataCaptureCloseIdentityAction(
        nullptr, &owner, &identity, nullptr, nullptr) == kIOReturnSuccess);
    return identity;
}

static int commitClose(ItlIwx &owner, DirectedDataCloseIdentity identity,
                       bool bsdCloseSucceeded, bool originInactive) {
    DirectedDataCloseCommit commit{};
    commit.identity = identity;
    commit.reason = TahoeP2PDirectedDataReason::kNone;
    commit.bsdCloseSucceeded = bsdCloseSucceeded;
    commit.originInactive = originInactive;
    commit.result = EBUSY;
    assert(directedDataCommitCloseAction(
        nullptr, &owner, &commit, nullptr, nullptr) == kIOReturnSuccess);
    return commit.result;
}

static bool ticketClosedFor(
    TahoeP2PDirectedDataContext &context,
    NativeAwdlDirectedOriginTx::Snapshot origin) {
    auto data = captureSnapshot(&context);
    Run run{};
    run.directedDataOriginTicket = context.originTicket;
    return actualTicketClosed(&run, true, data, origin);
}

int main() {
    ItlIwx owner{};

    // Snapshot completion is based on the actual submitted-slot ledger. A
    // stale generic completion bit cannot make the empty set look complete.
    {
        auto empty = makeContext();
        empty.packetCount = 2;
        empty.completion.value = {true, true};
        const auto data = captureSnapshot(&empty);
        assert(!data.doorbellIssued && !data.completionObserved);
    }
    {
        auto partial = makeContext();
        partial.packetCount = 2;
        setPacket(partial, 0, true, true, true);
        setPacket(partial, 1, true, false, false);
        partial.completion.value = {true, true};
        const auto data = captureSnapshot(&partial);
        assert(data.doorbellIssued && !data.completionObserved);
    }
    {
        auto oneSubmitted = makeContext();
        oneSubmitted.packetCount = 2;
        setPacket(oneSubmitted, 0, true, true, true);
        // Slot one was never submitted; its absent completion does not block
        // the aggregate, but the one real slot must be fully retired.
        oneSubmitted.completion.value = {false, false};
        const auto data = captureSnapshot(&oneSubmitted);
        assert(data.doorbellIssued && data.completionObserved);
    }
    {
        auto dmaNotRetired = makeContext();
        dmaNotRetired.packetCount = 1;
        setPacket(dmaNotRetired, 0, true, true, false);
        dmaNotRetired.completion.value = {true, true};
        const auto data = captureSnapshot(&dmaNotRetired);
        assert(data.doorbellIssued && !data.completionObserved);
    }
    {
        auto both = makeContext();
        both.packetCount = 2;
        setPacket(both, 0, true, true, true);
        setPacket(both, 1, true, true, true);
        const auto data = captureSnapshot(&both);
        assert(data.doorbellIssued && data.completionObserved);
    }

    // Positive: an exact successful close changes the snapshot's live ticket
    // bit while preserving the context's historical ticket and exact identity.
    auto completed = makeContext();
    auto ticket = completed.originTicket;
    auto identity = captureIdentity(owner, completed);
    assert(commitClose(owner, identity, true, true) == 0);
    assert(completed.ticketBound && completed.originClosed);
    assert(NativeAwdlDirectedOriginTx::sameTicket(completed.originTicket, ticket));
    assert(completed.state == TahoeP2PDirectedDataState::kClosed);
    assert(__atomic_load_n(&completed.mayOwnResource, __ATOMIC_ACQUIRE) == 0);
    auto snapshot = captureSnapshot(&completed);
    assert(!snapshot.originTicketBound && snapshot.originClosed);
    auto origin = closedOrigin(completed);
    assert(ticketClosedFor(completed, origin));
    assert(actualNoDoorbell(&owner, true, snapshot));

    // A repeated exact close is idempotent; the spent ticket remains recorded.
    auto repeated = captureIdentity(owner, completed);
    assert(repeated.originClosed && repeated.ticketBound);
    assert(commitClose(owner, repeated, true, true) == 0);
    assert(completed.ticketBound && completed.originClosed);
    assert(!captureSnapshot(&completed).originTicketBound);
    assert(ticketClosedFor(completed, closedOrigin(completed)));

    // Failed BSD close and an exact ticket that is still Open/Queued/Popping
    // cannot commit originClosed or make the snapshot look released.
    {
        auto failed = makeContext();
        auto id = captureIdentity(owner, failed);
        assert(commitClose(owner, id, false, true) == EIO);
        auto data = captureSnapshot(&failed);
        assert(!failed.originClosed && data.originTicketBound);
        assert(failed.state == TahoeP2PDirectedDataState::kQuarantined);
        assert(!ticketClosedFor(failed, closedOrigin(failed)));
    }
    const auto activeStates = {
        NativeAwdlDirectedOriginTx::State::Open,
        NativeAwdlDirectedOriginTx::State::Queued,
        NativeAwdlDirectedOriginTx::State::Popping,
    };
    for (auto state : activeStates) {
        auto active = makeContext();
        auto activeOrigin = closedOrigin(active);
        activeOrigin.state = state;
        activeOrigin.packetQueued = state ==
            NativeAwdlDirectedOriginTx::State::Queued;
        activeOrigin.packetPopping = state ==
            NativeAwdlDirectedOriginTx::State::Popping;
        assert(!actualOriginInactive(activeOrigin));
        auto id = captureIdentity(owner, active);
        assert(commitClose(owner, id, true,
                           actualOriginInactive(activeOrigin)) == EBUSY);
        auto data = captureSnapshot(&active);
        assert(!active.originClosed && data.originTicketBound);
        assert(active.state == TahoeP2PDirectedDataState::kQuarantined);
        assert(!ticketClosedFor(active, closedOrigin(active)));
    }

    // A stale close commit from a different owner, run, or ticket must not
    // close the newer context or erase its live snapshot binding.
    for (int mutation = 0; mutation < 3; ++mutation) {
        auto stale = makeContext();
        auto id = captureIdentity(owner, stale);
        if (mutation == 0)
            stale.binding.ownerSerial++;
        else if (mutation == 1)
            stale.binding.runSerial++;
        else
            stale.originTicket.ticketSerial++;
        assert(commitClose(owner, id, true, true) == ESTALE);
        auto data = captureSnapshot(&stale);
        assert(!stale.originClosed && data.originTicketBound);
        assert(stale.state == TahoeP2PDirectedDataState::kTicketBound);
        assert(!ticketClosedFor(stale, closedOrigin(stale)));
    }

    // Unknown TX/DMA ownership still fails the independent no-doorbell and
    // may-own-resource gates even when BSD exact close itself succeeded.
    {
        auto unknown = makeContext();
        unknown.packetCount = 1;
        setPacket(unknown, 0, true, false, false);
        unknown.mbufHeldByRing = true;
        auto id = captureIdentity(owner, unknown);
        assert(commitClose(owner, id, true, true) == EBUSY);
        auto data = captureSnapshot(&unknown);
        assert(unknown.originClosed && !data.originTicketBound);
        assert(unknown.state == TahoeP2PDirectedDataState::kQuarantined);
        assert(ticketClosedFor(unknown, closedOrigin(unknown)));
        assert(!actualNoDoorbell(&owner, true, data));
        assert(!directedDataCanClearMayOwnResource(&unknown));
        assert(__atomic_load_n(&unknown.mayOwnResource, __ATOMIC_ACQUIRE) == 1);
    }
    {
        auto externallyUnknown = makeContext();
        auto id = captureIdentity(owner, externallyUnknown);
        assert(commitClose(owner, id, true, true) == 0);
        auto data = captureSnapshot(&externallyUnknown);
        owner.hardwareNoDoorbell = false;
        assert(!actualNoDoorbell(&owner, true, data));
        owner.hardwareNoDoorbell = true;
    }

    // A spent BSD ticket is inactive but does not satisfy the exact Closed
    // state required by the existing recovery proof.
    auto spent = makeContext();
    auto spentId = captureIdentity(owner, spent);
    assert(commitClose(owner, spentId, true, true) == 0);
    auto spentOrigin = closedOrigin(spent);
    spentOrigin.state = NativeAwdlDirectedOriginTx::State::Spent;
    assert(actualOriginInactive(spentOrigin));
    assert(!ticketClosedFor(spent, spentOrigin));
}
"""

with tempfile.TemporaryDirectory(prefix="test115-close-recovery-") as tmp:
    source = Path(tmp) / "close_recovery.cpp"
    binary = Path(tmp) / "close_recovery"
    source.write_text(fixture)
    compiled = subprocess.run(
        ["c++", "-std=c++17", "-Wall", "-Wextra", "-Werror",
         "-fsanitize=address,undefined", "-I", str(ROOT / "native"),
         str(source), "-o", str(binary)],
        text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    if compiled.returncode:
        raise SystemExit(compiled.stdout)
    subprocess.run([str(binary)], check=True)

print("Test115 exact close and recovery lifecycle passed")
