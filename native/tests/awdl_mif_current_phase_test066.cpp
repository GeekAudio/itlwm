// SPDX-License-Identifier: GPL-2.0-only
#include "../awdl_mif_current_phase_test066.hpp"
#include "../awdl_mif_pacing.hpp"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

using namespace Test066MifCurrentPhase;

namespace {

Input fixture(uint64_t nowUs = 560571000ULL)
{
    Input in{};
    in.currentEpochs = {11, 12, 13, 14};
    in.mif.peerIncarnation = 0x6001;
    in.mif.mifRevision = 31;
    in.mif.rxMonotonicUs = 560563673ULL;
    in.mif.epochs = in.currentEpochs;
    in.mif.rxGp2Us = 396075820U;
    in.mif.phyTxTimestampUs = 4138107996U;
    in.mif.targetTxTimestampUs = 4138107870U;
    in.mif.awCounter = 20321;
    in.mif.txDownCounterTu = 39;
    in.mif.awPeriodTu = 16;
    in.mif.presenceMode = 4;
    in.mif.rxChannel = 6;
    in.mif.canonicalSlots[8] = 6;
    in.mif.present = true;
    in.mif.complete = true;
    in.mif.syncConsistent = true;
    in.mif.fresh = true;
    in.mif.rxGp2Present = true;
    in.mif.presenceModePresent = true;
    in.mif.awCounterSemanticVerified = true;
    in.mif.type18Present = true;
    in.mif.type18Valid = true;

    in.anchor.hostBeforeUs = 560052338ULL;
    in.anchor.hostAfterUs = 560052341ULL;
    in.anchor.rawGp2Us = 395568454U;
    in.anchor.epochs = in.currentEpochs;
    in.anchor.directReadBracket = true;
    in.anchor.occurredBeforeRoc = true;
    in.anchor.firmwareResourcesAbsent = true;

    in.binding.peerIncarnation = in.mif.peerIncarnation;
    in.binding.mifRevision = in.mif.mifRevision;
    in.binding.epochs = in.currentEpochs;
    in.binding.sameEntryVerified = true;
    // The PSF is only historical same-entry identity context in MIF mode.
    // Its 287-ms age is intentionally not supplied as a phase witness.
    in.binding.historicalPsfSameEntryPresent = true;

    in.gates.explicitlyEnabled = true;
    in.gates.hostMonotonicDomainVerified = true;
    in.gates.ownMifTxSucceeded = true;
    in.gates.rocActive = true;
    in.gates.rocChannel6Confirmed = true;
    in.gates.peerMifRxChannel6Confirmed = true;
    in.gates.ringIdle = true;
    in.gates.strictQmHeadStable = true;
    // Counterfactual successful local MIF completion before this candidate
    // phase. This is a gate in the model, not evidence it happened in capture.
    in.gates.firstOwnMifCompletionUs = 560568000ULL;
    in.nowUs = nowUs;
    in.leaseStartUs = 560500000ULL;
    in.leaseEndUs = 560700000ULL;
    in.localRocChannel = 6;
    return in;
}

Candidate candidate(const Input &in)
{
    Candidate out{};
    const Status status = plan(in, out);
    if (status != Status::kCandidate)
        fprintf(stderr, "MIF current-phase status=%u\n",
                static_cast<unsigned>(status));
    assert(status == Status::kCandidate);
    return out;
}

void expectFailure(const Input &in, Status expected)
{
    Candidate out;
    memset(&out, 0xa5, sizeof(out));
    Candidate before;
    memcpy(&before, &out, sizeof(before));
    const Status actual = plan(in, out);
    if (actual != expected)
        fprintf(stderr, "MIF current-phase expected=%u actual=%u\n",
                static_cast<unsigned>(expected),
                static_cast<unsigned>(actual));
    assert(actual == expected);
    assert(memcmp(&out, &before, sizeof(out)) == 0);
}

void testNumericFixtureAndCurrentSlotSemantics()
{
    const Input in = fixture();
    const Candidate out = candidate(in);
    assert(out.receiveHostEarliestUs == 560559704ULL);
    assert(out.receiveHostLatestUs == 560559707ULL);
    assert(in.mif.rxMonotonicUs - out.receiveHostLatestUs == 3966ULL);
    assert(out.nextEawGp2Us == 396115630U);
    assert(out.currentEawStartGp2Us == 396050094U);
    assert(out.targetAwStartGp2Us == 396082862U);
    assert(out.targetAwStartDeltaUs == 7042ULL);
    assert(out.currentSlot == 8);
    assert(out.targetAwCounter == 20322);
    assert(out.earliestSubmitUs == 560570845ULL);
    // Full guarded phase would end at 560579034. The conservative MIF
    // freshness cap is earlier and is exclusive.
    assert(out.latestSubmitUs == 560576088ULL);
    assert(out.peerIncarnation == in.mif.peerIncarnation);
    assert(out.mifRevision == in.mif.mifRevision);
    assert(!out.clockMappingVerified);
    assert(!out.airtimeVerified);
    assert(out.experimentalOnly);
}

void testObservedLateMifMustRejectAndCounterfactualWindowIsOnlyEstimate()
{
    Input actual = fixture(560619407ULL);
    expectFailure(actual, Status::kCandidateExpired);

    Input counterfactual = fixture(560571000ULL);
    const Candidate out = candidate(counterfactual);
    assert(out.earliestSubmitUs <= counterfactual.nowUs);
    assert(counterfactual.nowUs < out.latestSubmitUs);
    // A pure candidate is not proof the queue, firmware, RF, or peer could
    // complete before the window closes.
}

void testHalfOpenFreshnessAndLeaseBoundaries()
{
    Input in = fixture(560576087ULL);
    assert(candidate(in).latestSubmitUs == 560576088ULL);
    in.nowUs = 560576088ULL;
    expectFailure(in, Status::kCandidateExpired);

    in = fixture(560571000ULL);
    in.leaseEndUs = 560576088ULL + kLeaseReserveUs;
    assert(candidate(in).latestSubmitUs == 560576088ULL);
    in.leaseEndUs--;
    expectFailure(in, Status::kCandidateOutsideLease);

    in = fixture(560571000ULL);
    in.leaseEndUs = in.nowUs + kLeaseReserveUs;
    expectFailure(in, Status::kLeaseReserve);
}

void testGp2WrapAndAmbiguityFailClosed()
{
    Input in = fixture();
    in.anchor.rawGp2Us = 0xffff0000U;
    in.mif.rxGp2Us = in.anchor.rawGp2Us + 507366U;
    const Candidate wrapped = candidate(in);
    assert(wrapped.earliestSubmitUs == 560570845ULL);
    assert(wrapped.latestSubmitUs == 560576088ULL);

    in = fixture();
    in.mif.rxGp2Us = in.anchor.rawGp2Us + 0x80000000U;
    expectFailure(in, Status::kGp2HalfRange);

    in = fixture();
    in.anchor.rawGp2Us = 0;
    in.mif.rxGp2Us = 507366U;
    const Candidate zeroWrapped = candidate(in);
    assert(zeroWrapped.earliestSubmitUs == 560570845ULL);

    in = fixture();
    in.mif.rxGp2Us = in.anchor.rawGp2Us + kMaximumAnchorToMifUs;
    expectFailure(in, Status::kAnchorToMifTooOld);
}

void testAnchorEpochSourceAndBracketGuards()
{
    Input in = fixture();
    in.anchor.hostAfterUs = in.anchor.hostBeforeUs +
        kMaximumAnchorBracketUs + 1;
    in.mif.rxMonotonicUs = 560563673ULL;
    expectFailure(in, Status::kAnchorTooWide);

    in = fixture();
    in.anchor.directReadBracket = false;
    expectFailure(in, Status::kInvalidAnchor);

    in = fixture();
    in.anchor.firmwareResourcesAbsent = false;
    expectFailure(in, Status::kInvalidAnchor);

    in = fixture();
    in.anchor.hostAfterUs = in.mif.rxMonotonicUs + 1;
    in.anchor.hostBeforeUs = in.anchor.hostAfterUs;
    expectFailure(in, Status::kAnchorAfterMif);

    in = fixture();
    in.mif.rxGp2Us = in.anchor.rawGp2Us +
        static_cast<uint32_t>(in.mif.rxMonotonicUs -
                              in.anchor.hostAfterUs + 1);
    expectFailure(in, Status::kProjectedRxAfterTap);

    in = fixture();
    in.mif.epochs.roc++;
    expectFailure(in, Status::kEpochMismatch);
    in = fixture();
    in.mif.epochs.context++;
    expectFailure(in, Status::kEpochMismatch);
    in = fixture();
    in.mif.epochs.power++;
    expectFailure(in, Status::kEpochMismatch);
    in = fixture();
    in.mif.epochs.station++;
    expectFailure(in, Status::kEpochMismatch);

    in = fixture();
    in.anchor.epochs.context++;
    expectFailure(in, Status::kEpochMismatch);

    in = fixture();
    in.binding.epochs.station++;
    expectFailure(in, Status::kEpochMismatch);

    in = fixture();
    in.currentEpochs.power = 0;
    expectFailure(in, Status::kInvalidEpoch);

    in = fixture();
    in.nowUs = in.mif.rxMonotonicUs - 1;
    expectFailure(in, Status::kStaleMif);
}

void testBindingWitnessAndModeGates()
{
    Input in = fixture();
    in.mif.mifRevision++;
    expectFailure(in, Status::kBindingMismatch);

    in = fixture();
    in.binding.historicalPsfSameEntryPresent = false;
    expectFailure(in, Status::kMissingBinding);

    in = fixture();
    in.gates.explicitlyEnabled = false;
    expectFailure(in, Status::kModeNotEnabled);

    in = fixture();
    in.gates.hostMonotonicDomainVerified = false;
    expectFailure(in, Status::kTimeSourceUnverified);

    in = fixture();
    in.gates.closing = true;
    expectFailure(in, Status::kPrerequisiteMissing);

    in = fixture();
    in.gates.rocActive = false;
    expectFailure(in, Status::kPrerequisiteMissing);

    in = fixture();
    in.gates.rocChannel6Confirmed = false;
    expectFailure(in, Status::kPrerequisiteMissing);

    in = fixture();
    in.gates.peerMifRxChannel6Confirmed = false;
    expectFailure(in, Status::kPrerequisiteMissing);

    in = fixture();
    in.gates.ringIdle = false;
    expectFailure(in, Status::kPrerequisiteMissing);

    in = fixture();
    in.gates.strictQmHeadStable = false;
    expectFailure(in, Status::kPrerequisiteMissing);

    in = fixture();
    in.gates.ownMifTxSucceeded = false;
    expectFailure(in, Status::kPrerequisiteMissing);

    in = fixture();
    in.gates.firstOwnMifCompletionUs = 0;
    expectFailure(in, Status::kOwnMifNotCompletedBeforeWindow);

    in = fixture();
    in.gates.firstOwnMifCompletionUs = 560570845ULL;
    expectFailure(in, Status::kOwnMifNotCompletedBeforeWindow);

    // Source-derived actual completion is after the estimated interval. Keep
    // the timing observation at that actual time and reject the candidate
    // specifically on the local-MIF causal prerequisite.
    in = fixture(560619407ULL);
    in.gates.firstOwnMifCompletionUs = 560619407ULL;
    expectFailure(in, Status::kOwnMifNotCompletedBeforeWindow);
}

void testCanonicalCurrentSlotAndCounterSemantics()
{
    Input in = fixture();
    in.mif.canonicalSlots[8] = 149;
    expectFailure(in, Status::kWrongCurrentSlotChannel);

    in = fixture();
    in.mif.awCounter = 20323; // Next AW belongs to another EAW slot.
    expectFailure(in, Status::kNoFollowingAwInCurrentSlot);

    in = fixture();
    in.mif.awCounterSemanticVerified = false;
    expectFailure(in, Status::kIncompleteMif);

    in = fixture();
    in.mif.type18Valid = false;
    expectFailure(in, Status::kIncompleteMif);

    in = fixture();
    in.mif.awPeriodTu = 15;
    expectFailure(in, Status::kInvalidTiming);

    in = fixture();
    in.mif.phyTxTimestampUs = in.mif.targetTxTimestampUs + 65536U;
    expectFailure(in, Status::kInvalidTiming);
}

NativeAwdlProbe::MifPacingInput pacingFixture(
    NativeAwdlProbe::MifPacingPolicy policy)
{
    using namespace NativeAwdlProbe;
    MifPacingInput in{};
    in.phaseOriginUs = 1000000ULL;
    in.announcedWindowEndUs = in.phaseOriginUs + 12ULL * 64ULL * 1024ULL;
    in.hardDeadlineUs = in.phaseOriginUs + 900000ULL;
    in.frameOrdinal = 0;
    const uint64_t notBefore = in.phaseOriginUs +
        (in.announcedWindowEndUs - in.phaseOriginUs) / 4;
    in.nowUs = notBefore;
    in.peerPsfRxUs = notBefore - 9644ULL;
    in.contextGeneration = 7;
    in.powerGeneration = 11;
    in.stationGeneration = 13;
    in.peerContextGeneration = 7;
    in.peerPowerGeneration = 11;
    in.peerStationGeneration = 13;
    in.peerRxChannelIndex = 6;
    in.rocActive = true;
    in.rocChannel6Confirmed = true;
    in.peerPsfComplete = true;
    in.peerPsfSyncConsistent = true;
    in.peerPsfFresh = true;
    in.peerPsfRxChannel6Confirmed = true;
    in.policy = policy;
    return in;
}

void testOptInPacingKeepsNotBeforeAndOriginalTtl()
{
    using namespace NativeAwdlProbe;
    auto legacy = pacingFixture(MifPacingPolicy::LegacyPsfAfterNotBefore);
    assert(planMifPacing(legacy).decision == MifPacingDecision::Wait);
    assert(planMifPacing(legacy).reason == MifPacingReason::PsfBeforeNotBefore);

    auto opted = pacingFixture(MifPacingPolicy::Test066SamePeerMifTiming);
    const auto ready = planMifPacing(opted);
    assert(ready.decision == MifPacingDecision::Ready);
    assert(ready.reason == MifPacingReason::ReadyAnchor);
    assert(ready.earliestUs == opted.nowUs); // Never send before notBefore.
    assert(ready.anchorRxUs == opted.peerPsfRxUs); // Preserve the true RX.
    assert(ready.peerPsfAgeUs == 9644ULL);
    assert(ready.latestUs == opted.peerPsfRxUs + 16ULL * 1024ULL);

    opted.nowUs = opted.peerPsfRxUs + 16ULL * 1024ULL + 1;
    const auto expired = planMifPacing(opted);
    assert(expired.decision == MifPacingDecision::Wait);
    assert(expired.reason == MifPacingReason::PsfTooOld);
    assert(expired.latestUs == opted.peerPsfRxUs + 16ULL * 1024ULL);

    opted = pacingFixture(MifPacingPolicy::Test066SamePeerMifTiming);
    opted.nowUs--;
    assert(planMifPacing(opted).decision == MifPacingDecision::Wait);
    assert(planMifPacing(opted).reason == MifPacingReason::BeforeNotBefore);

    opted = pacingFixture(MifPacingPolicy::Test066SamePeerMifTiming);
    opted.lastUsedPeerPsfRxUs = opted.peerPsfRxUs;
    assert(planMifPacing(opted).decision == MifPacingDecision::Wait);
    assert(planMifPacing(opted).reason == MifPacingReason::PsfAlreadyUsed);

    opted = pacingFixture(static_cast<MifPacingPolicy>(0xff));
    assert(planMifPacing(opted).decision == MifPacingDecision::Stop);
    assert(planMifPacing(opted).reason == MifPacingReason::InvalidInput);
}

} // namespace

int main()
{
    testNumericFixtureAndCurrentSlotSemantics();
    testObservedLateMifMustRejectAndCounterfactualWindowIsOnlyEstimate();
    testHalfOpenFreshnessAndLeaseBoundaries();
    testGp2WrapAndAmbiguityFailClosed();
    testAnchorEpochSourceAndBracketGuards();
    testBindingWitnessAndModeGates();
    testCanonicalCurrentSlotAndCounterSemantics();
    testOptInPacingKeepsNotBeforeAndOriginalTtl();
    return 0;
}
