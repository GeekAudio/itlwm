// SPDX-License-Identifier: GPL-2.0-only
#include "../awdl_discovery_admitted_binding.hpp"
#include "../awdl_mif_current_admission_test069.hpp"
#include "../p2p_action_tx.hpp"

#include <assert.h>
#include <stdint.h>
#include <string.h>

namespace {

using namespace NativeAwdlDiscoveryBinding;
using namespace Test069MifCurrentAdmission;

constexpr uint64_t kContext = 11;
constexpr uint64_t kPower = 12;
constexpr uint64_t kStation = 13;
constexpr uint64_t kRoc = 14;
constexpr uint64_t kMifRxUs = 900;
constexpr uint64_t kLeaseStartUs = 100;
constexpr uint64_t kLeaseEndUs = 2000;
constexpr uint64_t kPhaseStartUs = 1100;
constexpr uint64_t kPhaseEndUs = 1200;

Snapshot validSnapshot(uint64_t nowUs)
{
    Snapshot out{};
    out.mode = Mode::kMifCurrentSlot;
    out.psfHistorySameEntryPresent = true;
    out.historyCompatible = true;
    out.peerIncarnation = 31;
    out.psfRevision = 41;
    out.mifRevision = 51;
    out.mifRxMonotonicUs = kMifRxUs;
    out.mifAgeUs = nowUs - kMifRxUs;
    out.psfAgeUs = nowUs - kMifRxUs;
    out.hasMif = true;
    out.mifFresh = true;
    out.mifSyncConsistent = true;
    out.mifRxChannel6 = true;
    out.psf.peerToken = out.peerIncarnation;
    out.psf.scheduleRevision = out.psfRevision;
    out.psf.epochs = {kContext, kPower, kStation, kRoc};
    out.psf.rxHostUs = kMifRxUs;
    MifWitness &mif = out.mif;
    mif.peerIncarnation = out.peerIncarnation;
    mif.mifRevision = out.mifRevision;
    mif.rxMonotonicUs = kMifRxUs;
    mif.rxAgeUs = out.mifAgeUs;
    mif.epochs = {kContext, kPower, kStation, kRoc};
    mif.awPeriodTu = 16;
    mif.presenceMode = 4;
    mif.rxChannel = 6;
    for (uint8_t &channel : mif.canonicalSlots)
        channel = 6;
    mif.present = true;
    mif.complete = true;
    mif.syncConsistent = true;
    mif.fresh = true;
    mif.rxGp2Present = true;
    mif.presenceModePresent = true;
    mif.awCounterSemanticVerified = true;
    mif.type18Present = true;
    mif.type18Valid = true;
    mif.peerMifRxChannel6Confirmed = true;
    return out;
}

QueueHead validHead()
{
    QueueHead out{};
    out.token = 61;
    out.bornUs = 950;
    out.generation = static_cast<uint32_t>(kPower);
    out.queryClass = static_cast<uint8_t>(
        NativeAwdlData::MdnsQueryClass::QmMulticast);
    out.eligible = true;
    return out;
}

Window validWindow(uint64_t nowUs)
{
    Window out{};
    out.mode = Mode::kMifCurrentSlot;
    out.epochs = {kContext, kPower, kStation, kRoc};
    out.nowUs = nowUs;
    out.leaseStartUs = kLeaseStartUs;
    out.leaseEndUs = kLeaseEndUs;
    out.phaseEarliestUs = kPhaseStartUs;
    out.phaseLatestUs = kPhaseEndUs;
    out.requireRuntimeMifBinding = true;
    out.phaseCandidateValid = true;
    out.rocActive = true;
    out.windowOpen = true;
    return out;
}

void setNow(Snapshot &snapshot, uint64_t nowUs)
{
    snapshot.mifAgeUs = nowUs - snapshot.mifRxMonotonicUs;
    snapshot.mif.rxAgeUs = snapshot.mifAgeUs;
    snapshot.psfAgeUs = nowUs - snapshot.psf.rxHostUs;
}

void testWaitMaskIsNarrowAndFailClosed()
{
    assert(hasOnlyWaitableBlockers(kOwnMifIncomplete));
    assert(hasOnlyWaitableBlockers(kActionRingBusy));
    assert(hasOnlyWaitableBlockers(kStrictQmHeadUnstable));
    assert(hasOnlyWaitableBlockers(kOwnMifIncomplete |
                                   kActionRingBusy |
                                   kStrictQmHeadUnstable));
    assert(!hasOnlyWaitableBlockers(0));
    assert(!hasOnlyWaitableBlockers(kActionRingBusy |
                                    kPeerMifChannelMismatch));
    assert(!hasOnlyWaitableBlockers(kStrictQmHeadUnstable | kRocInactive));
    assert(!hasOnlyWaitableBlockers(kOwnMifIncomplete | kClosing));
    assert(!hasOnlyWaitableBlockers(kActionRingBusy | kEpochMismatch));
    assert(!hasOnlyWaitableBlockers(kScheduleRejected));
    assert(!hasOnlyWaitableBlockers(kOwnMifMissedWindow));
}

void testRealOneShotLocksOnlyAFormedCandidateAndPreservesIdentity()
{
    const uint32_t prerequisites = kOwnMifIncomplete | kActionRingBusy;
    assert(hasOnlyWaitableBlockers(prerequisites));
    OneShot notYetCandidate;
    assert(!notYetCandidate.hasPendingReservation());

    Snapshot original = validSnapshot(1000);
    QueueHead head = validHead();
    Window window = validWindow(1000);
    OneShot binding;
    assert(binding.lock(original, head, window) == Decision::kReady);
    assert(binding.hasPendingReservation());

    Snapshot beforeWindow = validSnapshot(1050);
    setNow(beforeWindow, 1050);
    Window preOpen = validWindow(1050);
    assert(binding.authorizeTake(beforeWindow, head, preOpen) ==
           Decision::kPhaseNotYetOpen);
    assert(binding.hasPendingReservation());

    Snapshot ready = validSnapshot(kPhaseStartUs);
    setNow(ready, kPhaseStartUs);
    Window open = validWindow(kPhaseStartUs);
    assert(binding.authorizeTake(ready, head, open) == Decision::kReady);
    assert(binding.attempted());
    assert(!binding.hasPendingReservation());
    assert(binding.authorizeTake(ready, head, open) ==
           Decision::kAlreadyAttempted);

    OneShot incarnation;
    assert(incarnation.lock(original, head, window) == Decision::kReady);
    Snapshot changedIncarnation = validSnapshot(kPhaseStartUs);
    setNow(changedIncarnation, kPhaseStartUs);
    changedIncarnation.peerIncarnation++;
    changedIncarnation.mif.peerIncarnation++;
    changedIncarnation.psf.peerToken++;
    assert(incarnation.authorizeTake(changedIncarnation, head, open) ==
           Decision::kPeerIncarnationChanged);

    OneShot psfRevision;
    assert(psfRevision.lock(original, head, window) == Decision::kReady);
    Snapshot changedPsf = validSnapshot(kPhaseStartUs);
    setNow(changedPsf, kPhaseStartUs);
    changedPsf.psfRevision++;
    changedPsf.psf.scheduleRevision++;
    assert(psfRevision.authorizeTake(changedPsf, head, open) ==
           Decision::kPsfRevisionChanged);

    OneShot mifRevision;
    assert(mifRevision.lock(original, head, window) == Decision::kReady);
    Snapshot changedMifRevision = validSnapshot(kPhaseStartUs);
    setNow(changedMifRevision, kPhaseStartUs);
    changedMifRevision.mifRevision++;
    changedMifRevision.mif.mifRevision++;
    assert(mifRevision.authorizeTake(changedMifRevision, head, open) ==
           Decision::kMifRevisionChanged);

    OneShot mifWitness;
    assert(mifWitness.lock(original, head, window) == Decision::kReady);
    Snapshot changedMifWitness = validSnapshot(kPhaseStartUs);
    setNow(changedMifWitness, kPhaseStartUs);
    changedMifWitness.mif.awCounter++;
    assert(mifWitness.authorizeTake(changedMifWitness, head, open) ==
           Decision::kMifWitnessMismatch);

    OneShot epoch;
    assert(epoch.lock(original, head, window) == Decision::kReady);
    Snapshot changedEpoch = validSnapshot(kPhaseStartUs);
    setNow(changedEpoch, kPhaseStartUs);
    changedEpoch.mif.epochs.power++;
    assert(epoch.authorizeTake(changedEpoch, head, open) ==
           Decision::kEpochMismatch);

    OneShot strictHead;
    assert(strictHead.lock(original, head, window) == Decision::kReady);
    QueueHead changedHead = head;
    changedHead.token++;
    assert(strictHead.authorizeTake(ready, changedHead, open) ==
           Decision::kQueueHeadChanged);

    // No older peer or earlier MIF is consulted if the selected schedule has
    // no usable candidate; the caller must reject that selected candidate.
    assert(!hasOnlyWaitableBlockers(kScheduleRejected));
}

static void put16(uint8_t *p, uint16_t value)
{
    p[0] = static_cast<uint8_t>(value);
    p[1] = static_cast<uint8_t>(value >> 8);
}

static void put32(uint8_t *p, uint32_t value)
{
    for (unsigned i = 0; i != 4; ++i)
        p[i] = static_cast<uint8_t>(value >> (i * 8));
}

static void makeTxResponse(uint8_t response[48], uint16_t status,
                           uint32_t nextSsn)
{
    memset(response, 0, 48);
    response[0] = 1;
    put16(response + 30, 100);     // frame_count byte-count witness
    put16(response + 34, 0x00d0);  // Action frame control
    put16(response + 36, 12);      // TX queue id
    put16(response + 40, status);  // TX response status
    put32(response + 44, nextSsn); // Next scheduler descriptor
}

void testRealCompletionTrackerTombstoneAndDrainTransitions()
{
    IntelP2PActionTx::CompletionTracker tracker;
    assert(tracker.arm(7, 12, 8, 0, 0x40, 100, 0x00d0) ==
           IntelP2PActionTx::Result::kReady);
    const IntelP2PActionTx::Ticket inFlight = tracker.snapshot();
    assert(inFlight.armed && !inFlight.completed);
    assert(!completedTicketHasNoInflight(inFlight.armed,
                                         inFlight.completed));

    uint8_t response[48];
    makeTxResponse(response, 1, 1);
    assert(tracker.complete(7, response, sizeof(response), 40, 28, 30, 34,
                            36, 44) ==
           IntelP2PActionTx::Result::kCompletion);
    const IntelP2PActionTx::Ticket completed = tracker.snapshot();
    // Production intentionally retains armed as a late-response tombstone.
    assert(completed.armed && completed.completed &&
           completed.frameAttemptSucceeded && !completed.peerAcknowledged);
    assert(completedTicketHasNoInflight(completed.armed,
                                        completed.completed));
    assert(tracker.complete(7, response, sizeof(response), 40, 28, 30, 34,
                            36, 44) == IntelP2PActionTx::Result::kBusy);

    // Re-arm is allowed only after completion and starts a genuinely live
    // descriptor, so the ring gate must block until its next completion.
    assert(tracker.arm(7, 12, 8, 1, 0x50, 100, 0x00d0) ==
           IntelP2PActionTx::Result::kReady);
    const IntelP2PActionTx::Ticket rearmed = tracker.snapshot();
    assert(rearmed.armed && !rearmed.completed);
    assert(!completedTicketHasNoInflight(rearmed.armed, rearmed.completed));
    makeTxResponse(response, 3, 2); // Completed FW failure is still retired.
    assert(tracker.complete(7, response, sizeof(response), 40, 28, 30, 34,
                            36, 44) ==
           IntelP2PActionTx::Result::kFrameFailed);
    const IntelP2PActionTx::Ticket failed = tracker.snapshot();
    assert(failed.armed && failed.completed && !failed.frameAttemptSucceeded);
    assert(completedTicketHasNoInflight(failed.armed, failed.completed));

    assert(tracker.firmwareDrained(8) == IntelP2PActionTx::Result::kReady);
    const IntelP2PActionTx::Ticket drained = tracker.snapshot();
    assert(!drained.armed && !drained.completed);
    assert(!completedTicketHasNoInflight(drained.armed,
                                         drained.completed));

    IntelP2PActionTx::CompletionTracker unsubmitted;
    assert(unsubmitted.arm(9, 12, 8, 2, 0x60, 100, 0x00d0) ==
           IntelP2PActionTx::Result::kReady);
    assert(unsubmitted.cancelUnsubmitted(9, 12, 2) ==
           IntelP2PActionTx::Result::kCancelled);
    const IntelP2PActionTx::Ticket canceled = unsubmitted.snapshot();
    assert(!canceled.armed && !canceled.completed);
    assert(!completedTicketHasNoInflight(canceled.armed,
                                         canceled.completed));
}

} // namespace

int main()
{
    testWaitMaskIsNarrowAndFailClosed();
    testRealOneShotLocksOnlyAFormedCandidateAndPreservesIdentity();
    testRealCompletionTrackerTombstoneAndDrainTransitions();
    return 0;
}
