// SPDX-License-Identifier: GPL-2.0-only
#include "../awdl_discovery_admitted_binding.hpp"
#include "../awdl_mif_discovery_hold_test068.hpp"

#include <assert.h>
#include <stdint.h>

using namespace NativeAwdlDiscoveryBinding;
using namespace NativeAwdlMifDiscoveryHoldTest068;

namespace {

constexpr uint64_t kContext = 11;
constexpr uint64_t kPower = 12;
constexpr uint64_t kStation = 13;
constexpr uint64_t kRoc = 14;
constexpr uint64_t kLeaseStart = 100;
constexpr uint64_t kUsableLeaseEnd = 1980;
constexpr uint64_t kEarliest = 1100;
constexpr uint64_t kLatest = 1200;

Snapshot validMifSnapshot(uint64_t nowUs)
{
    Snapshot out{};
    out.mode = Mode::kMifCurrentSlot;
    out.psfHistorySameEntryPresent = true;
    out.historyCompatible = true;
    out.peerIncarnation = 31;
    out.psfRevision = 41;
    out.mifRevision = 51;
    out.mifRxMonotonicUs = 900;
    out.mifAgeUs = nowUs - out.mifRxMonotonicUs;
    out.psfAgeUs = nowUs - 900;
    out.hasMif = true;
    out.mifFresh = true;
    out.mifSyncConsistent = true;
    out.mifRxChannel6 = true;
    out.psf.peerToken = out.peerIncarnation;
    out.psf.scheduleRevision = out.psfRevision;
    out.psf.rxHostUs = 900;
    out.psf.epochs = {kContext, kPower, kStation, kRoc};
    MifWitness &mif = out.mif;
    mif.peerIncarnation = out.peerIncarnation;
    mif.mifRevision = out.mifRevision;
    mif.rxMonotonicUs = out.mifRxMonotonicUs;
    mif.rxAgeUs = out.mifAgeUs;
    mif.epochs = {kContext, kPower, kStation, kRoc};
    mif.awPeriodTu = 16;
    mif.presenceMode = 4;
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

QueueHead validQmHead()
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
    out.leaseStartUs = kLeaseStart;
    out.leaseEndUs = 2000;
    out.phaseEarliestUs = kEarliest;
    out.phaseLatestUs = kLatest;
    out.requireRuntimeMifBinding = true;
    out.phaseCandidateValid = true;
    out.rocActive = true;
    out.windowOpen = true;
    return out;
}

Input holdInput(uint64_t nowUs)
{
    Input out{};
    out.modeSelected = true;
    out.mifCurrentMode = true;
    out.firstOwnMifCompleted = true;
    out.candidateLocked = true;
    out.runtimeMifBindingRequired = true;
    out.runtimeMifBound = true;
    out.oneShotLocked = true;
    out.targetCandidate = true;
    out.rocActive = true;
    out.epochsMatch = true;
    out.nowUs = nowUs;
    out.leaseStartUs = kLeaseStart;
    out.earliestSubmitUs = kEarliest;
    out.latestSubmitUs = kLatest;
    out.usableLeaseEndUs = kUsableLeaseEnd;
    return out;
}

void testNoCandidateOrSameEntryMifDoesNotBlockRepeatEvaluation()
{
    Input noCandidate = holdInput(1050);
    noCandidate.candidateLocked = false;
    assert(!shouldHoldMifRepeat(noCandidate));

    Snapshot missingMif = validMifSnapshot(1000);
    missingMif.hasMif = false;
    OneShot noMifBinding;
    assert(noMifBinding.lock(missingMif, validQmHead(),
                             validWindow(1000)) ==
           Decision::kMissingMifBinding);
    assert(!noMifBinding.hasPendingReservation());
    Input noMif = holdInput(1050);
    noMif.runtimeMifBound = false;
    noMif.oneShotLocked = noMifBinding.hasPendingReservation();
    assert(!shouldHoldMifRepeat(noMif));
}

void testOnlyPendingBoundWindowIsHeldAndWindowIsHalfOpen()
{
    Snapshot snapshot = validMifSnapshot(1000);
    QueueHead head = validQmHead();
    Window window = validWindow(1000);
    OneShot binding;
    assert(binding.lock(snapshot, head, window) == Decision::kReady);
    assert(binding.hasPendingReservation());

    Window beforePhase = window;
    beforePhase.nowUs = 1050;
    Snapshot beforePhaseSnapshot = validMifSnapshot(1050);
    assert(binding.authorizeTake(beforePhaseSnapshot, head, beforePhase) ==
           Decision::kPhaseNotYetOpen);
    assert(binding.hasPendingReservation());

    Input beforeTarget = holdInput(1050);
    beforeTarget.oneShotLocked = binding.hasPendingReservation();
    assert(shouldHoldMifRepeat(beforeTarget));
    Input activeTarget = holdInput(1150);
    activeTarget.oneShotLocked = binding.hasPendingReservation();
    assert(shouldHoldMifRepeat(activeTarget));

    Window atEarliest = window;
    atEarliest.nowUs = kEarliest;
    Snapshot atEarliestSnapshot = validMifSnapshot(kEarliest);
    assert(binding.authorizeTake(atEarliestSnapshot, head, atEarliest) ==
           Decision::kReady);
    assert(!binding.hasPendingReservation());
    Input consumed = holdInput(kEarliest);
    consumed.oneShotLocked = binding.hasPendingReservation();
    consumed.consumed = true;
    assert(!shouldHoldMifRepeat(consumed));
}

void testExpiredStaleClosedEndAndEpochMismatchReleaseHold()
{
    Snapshot snapshot = validMifSnapshot(1000);
    QueueHead head = validQmHead();

    OneShot expired;
    assert(expired.lock(snapshot, head, validWindow(1000)) ==
           Decision::kReady);
    Window atLatest = validWindow(kLatest);
    Snapshot atLatestSnapshot = validMifSnapshot(kLatest);
    assert(expired.authorizeTake(atLatestSnapshot, head, atLatest) ==
           Decision::kPhaseExpired);
    assert(!expired.hasPendingReservation());
    Input expiredHold = holdInput(kLatest);
    expiredHold.oneShotLocked = expired.hasPendingReservation();
    assert(!shouldHoldMifRepeat(expiredHold));

    OneShot staleMif;
    assert(staleMif.lock(snapshot, head, validWindow(1000)) ==
           Decision::kReady);
    Snapshot changedMif = validMifSnapshot(kEarliest);
    changedMif.mifRevision++;
    changedMif.mif.mifRevision++;
    changedMif.mifAgeUs = kEarliest - changedMif.mifRxMonotonicUs;
    changedMif.mif.rxAgeUs = changedMif.mifAgeUs;
    assert(staleMif.authorizeTake(changedMif, head,
                                  validWindow(kEarliest)) ==
           Decision::kMifRevisionChanged);
    assert(!staleMif.hasPendingReservation());
    Input stale = holdInput(kEarliest);
    stale.oneShotLocked = staleMif.hasPendingReservation();
    assert(!shouldHoldMifRepeat(stale));

    OneShot ended;
    assert(ended.lock(snapshot, head, validWindow(1000)) ==
           Decision::kReady);
    Window closing = validWindow(1050);
    closing.closing = true;
    Snapshot closingSnapshot = validMifSnapshot(1050);
    assert(ended.authorizeTake(closingSnapshot, head, closing) ==
           Decision::kWindowClosed);
    assert(!ended.hasPendingReservation());
    Input endHold = holdInput(1050);
    endHold.oneShotLocked = ended.hasPendingReservation();
    endHold.rocActive = false;
    endHold.windowClosed = true;
    assert(!shouldHoldMifRepeat(endHold));

    OneShot epochMismatch;
    assert(epochMismatch.lock(snapshot, head, validWindow(1000)) ==
           Decision::kReady);
    Snapshot wrongEpoch = validMifSnapshot(kEarliest);
    wrongEpoch.mif.epochs.power++;
    assert(epochMismatch.authorizeTake(wrongEpoch, head,
                                       validWindow(kEarliest)) ==
           Decision::kEpochMismatch);
    assert(!epochMismatch.hasPendingReservation());
    Input wrongEpochHold = holdInput(kEarliest);
    wrongEpochHold.oneShotLocked = epochMismatch.hasPendingReservation();
    wrongEpochHold.epochsMatch = false;
    assert(!shouldHoldMifRepeat(wrongEpochHold));
}

void testOtherReleaseGatesAndMalformedWindowDoNotHold()
{
    Input input = holdInput(1050);
    input.windowClosed = true;
    assert(!shouldHoldMifRepeat(input));
    input = holdInput(1050);
    input.consumed = true;
    assert(!shouldHoldMifRepeat(input));
    input = holdInput(1050);
    input.canceled = true;
    assert(!shouldHoldMifRepeat(input));
    input = holdInput(1050);
    input.rocActive = false;
    assert(!shouldHoldMifRepeat(input));
    input = holdInput(1050);
    input.mifCurrentMode = false;
    assert(!shouldHoldMifRepeat(input));
    input = holdInput(1050);
    input.latestSubmitUs = input.earliestSubmitUs;
    assert(!shouldHoldMifRepeat(input));
    input = holdInput(1050);
    input.usableLeaseEndUs = input.latestSubmitUs - 1;
    assert(!shouldHoldMifRepeat(input));
    input = holdInput(kLatest);
    assert(!shouldHoldMifRepeat(input));
}

} // namespace

int main()
{
    testNoCandidateOrSameEntryMifDoesNotBlockRepeatEvaluation();
    testOnlyPendingBoundWindowIsHeldAndWindowIsHalfOpen();
    testExpiredStaleClosedEndAndEpochMismatchReleaseHold();
    testOtherReleaseGatesAndMalformedWindowDoNotHold();
    return 0;
}
