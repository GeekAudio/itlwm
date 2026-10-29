// SPDX-License-Identifier: GPL-2.0-only
#include "../awdl_discovery_admitted_binding.hpp"
#include "../awdl_mif_current_phase_test066.hpp"

#include <assert.h>
#include <stdint.h>
#include <string.h>

using namespace NativeAwdlDiscoveryBinding;
using namespace Test066MifCurrentPhase;

namespace {

Input timingInput(uint64_t nowUs)
{
    Input input{};
    input.currentEpochs = {11, 12, 13, 14};
    input.mif.peerIncarnation = 0x6001;
    input.mif.mifRevision = 31;
    input.mif.rxMonotonicUs = 560563673ULL;
    input.mif.epochs = input.currentEpochs;
    input.mif.rxGp2Us = 396075820U;
    input.mif.phyTxTimestampUs = 4138107996U;
    input.mif.targetTxTimestampUs = 4138107870U;
    input.mif.awCounter = 20321;
    input.mif.txDownCounterTu = 39;
    input.mif.awPeriodTu = 16;
    input.mif.presenceMode = 4;
    input.mif.rxChannel = 6;
    input.mif.canonicalSlots[8] = 6;
    input.mif.present = true;
    input.mif.complete = true;
    input.mif.syncConsistent = true;
    input.mif.fresh = true;
    input.mif.rxGp2Present = true;
    input.mif.presenceModePresent = true;
    input.mif.awCounterSemanticVerified = true;
    input.mif.type18Present = true;
    input.mif.type18Valid = true;
    input.anchor.hostBeforeUs = 560052338ULL;
    input.anchor.hostAfterUs = 560052341ULL;
    input.anchor.rawGp2Us = 395568454U;
    input.anchor.epochs = input.currentEpochs;
    input.anchor.directReadBracket = true;
    input.anchor.occurredBeforeRoc = true;
    input.anchor.firmwareResourcesAbsent = true;
    input.binding.peerIncarnation = input.mif.peerIncarnation;
    input.binding.mifRevision = input.mif.mifRevision;
    input.binding.epochs = input.currentEpochs;
    input.binding.sameEntryVerified = true;
    input.binding.historicalPsfSameEntryPresent = true;
    input.gates.explicitlyEnabled = true;
    input.gates.hostMonotonicDomainVerified = true;
    input.gates.ownMifTxSucceeded = true;
    input.gates.rocActive = true;
    input.gates.rocChannel6Confirmed = true;
    input.gates.peerMifRxChannel6Confirmed = true;
    input.gates.ringIdle = true;
    input.gates.strictQmHeadStable = true;
    input.gates.firstOwnMifCompletionUs = 560568000ULL;
    input.nowUs = nowUs;
    input.leaseStartUs = 560500000ULL;
    input.leaseEndUs = 560700000ULL;
    input.localRocChannel = 6;
    return input;
}

Snapshot bindingSnapshot(const Input &timing, uint64_t psfAgeUs)
{
    Snapshot out{};
    out.mode = Mode::kMifCurrentSlot;
    out.psfHistorySameEntryPresent = true;
    out.historyCompatible = true;
    out.peerIncarnation = timing.mif.peerIncarnation;
    out.psfRevision = 7;
    out.mifRevision = timing.mif.mifRevision;
    out.mifRxMonotonicUs = timing.mif.rxMonotonicUs;
    out.mifAgeUs = timing.nowUs - timing.mif.rxMonotonicUs;
    out.psfAgeUs = psfAgeUs;
    out.hasMif = true;
    out.mifFresh = true;
    out.mifSyncConsistent = true;
    out.psf.peerToken = out.peerIncarnation;
    out.psf.scheduleRevision = out.psfRevision;
    out.psf.epochs = {11, 12, 13, 14};
    out.psf.rxHostUs = timing.nowUs - psfAgeUs;
    out.psf.complete = false; // Historical PSF is not a phase witness.
    out.psf.rxChannel = 149;
    out.psf.awCounter = 20324;
    out.psf.canonicalChannels[8] = 6;
    out.psf.canonicalChannels[10] = 149;
    MifWitness &mif = out.mif;
    mif.peerIncarnation = timing.mif.peerIncarnation;
    mif.mifRevision = timing.mif.mifRevision;
    mif.rxMonotonicUs = timing.mif.rxMonotonicUs;
    mif.rxAgeUs = out.mifAgeUs;
    mif.epochs = {11, 12, 13, 14};
    mif.rxGp2Us = timing.mif.rxGp2Us;
    mif.phyTxTimestampUs = timing.mif.phyTxTimestampUs;
    mif.targetTxTimestampUs = timing.mif.targetTxTimestampUs;
    mif.awCounter = timing.mif.awCounter;
    mif.txDownCounterTu = timing.mif.txDownCounterTu;
    mif.awPeriodTu = timing.mif.awPeriodTu;
    mif.presenceMode = timing.mif.presenceMode;
    mif.rxChannel = timing.mif.rxChannel;
    memcpy(mif.canonicalSlots, timing.mif.canonicalSlots,
           sizeof(mif.canonicalSlots));
    mif.present = timing.mif.present;
    mif.complete = timing.mif.complete;
    mif.syncConsistent = timing.mif.syncConsistent;
    mif.fresh = timing.mif.fresh;
    mif.rxGp2Present = timing.mif.rxGp2Present;
    mif.presenceModePresent = timing.mif.presenceModePresent;
    mif.awCounterSemanticVerified = timing.mif.awCounterSemanticVerified;
    mif.type18Present = timing.mif.type18Present;
    mif.type18Valid = timing.mif.type18Valid;
    // This host fixture represents one compatible runtime Entry. Preserve
    // the full map from its historical PSF rather than testing only slot 8.
    memcpy(mif.canonicalSlots, out.psf.canonicalChannels,
           sizeof(mif.canonicalSlots));
    mif.peerMifRxChannel6Confirmed =
        timing.gates.peerMifRxChannel6Confirmed;
    return out;
}

Window bindingWindow(const Snapshot &snapshot, const Input &input,
                     const Candidate *candidate)
{
    Window out{};
    out.mode = Mode::kMifCurrentSlot;
    out.epochs = {11, 12, 13, 14};
    out.nowUs = input.nowUs;
    out.leaseStartUs = input.leaseStartUs;
    out.leaseEndUs = input.leaseEndUs;
    out.phaseCandidateValid = candidate != nullptr;
    if (candidate) {
        out.phaseEarliestUs = candidate->earliestSubmitUs;
        out.phaseLatestUs = candidate->latestSubmitUs;
    } else {
        out.phaseEarliestUs = 560570845ULL;
        out.phaseLatestUs = 560576088ULL;
    }
    out.requireRuntimeMifBinding = true;
    out.rocActive = true;
    out.windowOpen = true;
    out.closing = input.gates.closing;
    (void)snapshot;
    return out;
}

QueueHead strictQm(uint64_t nowUs)
{
    QueueHead head{};
    head.token = 0x77;
    head.bornUs = nowUs - 100;
    head.generation = 12;
    head.queryClass = static_cast<uint8_t>(
        NativeAwdlData::MdnsQueryClass::QmMulticast);
    head.eligible = true;
    return head;
}

struct MockQueue {
    QueueHead head;
    uint32_t calls;
    uint32_t consumed;
    explicit MockQueue(const QueueHead &value)
        : head(value), calls(0), consumed(0) {}
    void take(const QueueHead &expected)
    {
        ++calls;
        if (sameQueueHead(head, expected))
            ++consumed;
    }
};

void testOldPsfIsIdentityOnlyWhenFreshMifPhaseAndQmHeadExist()
{
    Input input = timingInput(560571000ULL);
    Candidate candidate{};
    assert(Test066MifCurrentPhase::plan(input, candidate) == Status::kCandidate);
    assert(candidate.currentSlot == 8 && candidate.earliestSubmitUs == 560570845ULL);

    Snapshot snapshot = bindingSnapshot(input, 287000ULL);
    Window window = bindingWindow(snapshot, input, &candidate);
    QueueHead head = strictQm(input.nowUs);
    OneShot oneShot;
    assert(oneShot.lock(snapshot, head, window) == Decision::kReady);
    Snapshot current = snapshot;
    current.psfAgeUs += 1000;
    current.mifAgeUs += 1000;
    current.mif.rxAgeUs += 1000;
    Window currentWindow = window;
    currentWindow.nowUs += 1000;
    assert(oneShot.authorizeTake(current, head, currentWindow) ==
           Decision::kReady);
    MockQueue queue(head);
    queue.take(head);
    assert(queue.calls == 1 && queue.consumed == 1);

    // Once authorized, the same transaction cannot consume a second item.
    assert(oneShot.authorizeTake(snapshot, head, window) ==
           Decision::kAlreadyAttempted);
    assert(queue.calls == 1 && queue.consumed == 1);

    OneShot changedWindow;
    assert(changedWindow.lock(snapshot, head, window) == Decision::kReady);
    Window widened = window;
    ++widened.phaseLatestUs;
    assert(changedWindow.authorizeTake(snapshot, head, widened) ==
           Decision::kWindowChanged);
}

void testActualLateMifAndWrongQueueLeaveTheHeadUntouched()
{
    Input actual = timingInput(560619407ULL);
    Candidate output{};
    assert(Test066MifCurrentPhase::plan(actual, output) ==
           Status::kCandidateExpired);
    Snapshot snapshot = bindingSnapshot(actual, 287000ULL);
    Window window = bindingWindow(snapshot, actual, nullptr);
    QueueHead head = strictQm(actual.nowUs);
    OneShot expired;
    assert(expired.lock(snapshot, head, window) ==
           Decision::kInvalidPhaseCandidate);
    MockQueue untouched(head);
    assert(untouched.calls == 0 && untouched.consumed == 0);

    Input current = timingInput(560571000ULL);
    Candidate candidate{};
    assert(Test066MifCurrentPhase::plan(current, candidate) == Status::kCandidate);
    snapshot = bindingSnapshot(current, 287000ULL);
    window = bindingWindow(snapshot, current, &candidate);
    head = strictQm(current.nowUs);
    head.queryClass = static_cast<uint8_t>(
        NativeAwdlData::MdnsQueryClass::QuUnicastPreferred);
    OneShot nonQm;
    assert(nonQm.lock(snapshot, head, window) == Decision::kQueueHeadInvalid);
    MockQueue stillUntouched(head);
    assert(stillUntouched.calls == 0 && stillUntouched.consumed == 0);
}

} // namespace

int main()
{
    testOldPsfIsIdentityOnlyWhenFreshMifPhaseAndQmHeadExist();
    testActualLateMifAndWrongQueueLeaveTheHeadUntouched();
    return 0;
}
