// SPDX-License-Identifier: GPL-2.0-only
#include "../awdl_mif_current_aw_fallback.hpp"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

using namespace NativeAwdlMifCurrentAw;
using LegacyStatus = Test066MifCurrentPhase::Status;

namespace {

void setAllEpochs(Test066MifCurrentPhase::Input &in,
                  Test066MifCurrentPhase::Epochs e)
{
    in.currentEpochs = e;
    in.mif.epochs = e;
    in.anchor.epochs = e;
    in.binding.epochs = e;
}

Input exactRxGeometry(uint64_t nowUs = 348933210ULL)
{
    Input in{};
    Test066MifCurrentPhase::Input &t = in.timing;
    t.currentEpochs = {11, 12, 13, 14};
    t.mif.peerIncarnation = 0x6001;
    t.mif.mifRevision = 31;
    t.mif.rxMonotonicUs = 348933210ULL;
    t.mif.epochs = t.currentEpochs;
    t.mif.rxGp2Us = 300636427U;
    t.mif.phyTxTimestampUs = 3994982196U;
    t.mif.targetTxTimestampUs = 3994981585U;
    t.mif.awCounter = 11042;
    t.mif.txDownCounterTu = 31;
    t.mif.awPeriodTu = 16;
    t.mif.presenceMode = 4;
    t.mif.rxChannel = 6;
    t.mif.canonicalSlots[8] = 6;
    t.mif.present = true;
    t.mif.complete = true;
    t.mif.syncConsistent = true;
    t.mif.fresh = true;
    t.mif.rxGp2Present = true;
    t.mif.presenceModePresent = true;
    t.mif.awCounterSemanticVerified = true;
    t.mif.type18Present = true;
    t.mif.type18Valid = true;

    t.anchor.hostBeforeUs = 348471635ULL;
    t.anchor.hostAfterUs = 348471638ULL;
    t.anchor.rawGp2Us = 300177472U;
    t.anchor.epochs = t.currentEpochs;
    t.anchor.directReadBracket = true;
    t.anchor.occurredBeforeRoc = true;
    t.anchor.firmwareResourcesAbsent = true;

    t.binding.peerIncarnation = t.mif.peerIncarnation;
    t.binding.mifRevision = t.mif.mifRevision;
    t.binding.epochs = t.currentEpochs;
    t.binding.sameEntryVerified = true;
    t.binding.historicalPsfSameEntryPresent = true;

    t.gates.explicitlyEnabled = true;
    t.gates.hostMonotonicDomainVerified = true;
    t.gates.ownMifTxSucceeded = true;
    t.gates.rocActive = true;
    t.gates.rocChannel6Confirmed = true;
    t.gates.peerMifRxChannel6Confirmed = true;
    t.gates.ringIdle = true;
    t.gates.strictQmHeadStable = true;
    t.gates.firstOwnMifCompletionUs = 348623000ULL;
    t.nowUs = nowUs;
    t.leaseStartUs = 348491144ULL;
    t.leaseEndUs = 349386238ULL;
    t.localRocChannel = 6;
    return in;
}

Test066MifCurrentPhase::Input legacyCandidateInput(uint64_t nowUs = 560571000ULL)
{
    Test066MifCurrentPhase::Input in{};
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
    in.binding.historicalPsfSameEntryPresent = true;
    in.gates.explicitlyEnabled = true;
    in.gates.hostMonotonicDomainVerified = true;
    in.gates.ownMifTxSucceeded = true;
    in.gates.rocActive = true;
    in.gates.rocChannel6Confirmed = true;
    in.gates.peerMifRxChannel6Confirmed = true;
    in.gates.ringIdle = true;
    in.gates.strictQmHeadStable = true;
    in.gates.firstOwnMifCompletionUs = 560568000ULL;
    in.nowUs = nowUs;
    in.leaseStartUs = 560500000ULL;
    in.leaseEndUs = 560700000ULL;
    in.localRocChannel = 6;
    return in;
}

void expectOldFailurePassthrough(const Input &in, LegacyStatus expected,
                                 const char *name)
{
    Test066MifCurrentPhase::Candidate oldOutput;
    memset(&oldOutput, 0xa5, sizeof(oldOutput));
    const LegacyStatus oldStatus =
        Test066MifCurrentPhase::plan(in.timing, oldOutput);
    if (oldStatus != expected) {
        fprintf(stderr, "%s: old planner expected=%u actual=%u\n", name,
                static_cast<unsigned>(expected),
                static_cast<unsigned>(oldStatus));
    }
    assert(oldStatus == expected);

    Candidate output;
    memset(&output, 0x5a, sizeof(output));
    Candidate before;
    memcpy(&before, &output, sizeof(before));
    RejectReason reason = RejectReason::kExpired;
    const LegacyStatus actual = plan(in, output, &reason);
    if (actual != oldStatus) {
        fprintf(stderr, "%s: wrapper expected=%u actual=%u\n", name,
                static_cast<unsigned>(oldStatus),
                static_cast<unsigned>(actual));
    }
    assert(actual == oldStatus);
    assert(reason == RejectReason::kNotAttempted);
    assert(memcmp(&output, &before, sizeof(output)) == 0);
}

void testRootRxNumericFixtureIsConditionalAndExact()
{
    const Input in = exactRxGeometry();
    assert(in.timing.mif.awCounter % Test066MifCurrentPhase::kAwPerEaw == 2);
    assert((Test066MifCurrentPhase::kEawPeriodTu -
            in.timing.mif.txDownCounterTu) /
           Test066MifCurrentPhase::kExpectedAwPeriodTu == 2);
    Test066MifCurrentPhase::Candidate oldOutput;
    assert(Test066MifCurrentPhase::plan(in.timing, oldOutput) ==
           LegacyStatus::kNoConservativeWindow);

    Candidate output{};
    RejectReason reason = RejectReason::kNotAttempted;
    assert(plan(in, output, &reason) == LegacyStatus::kCandidate);
    assert(reason == RejectReason::kNotAttempted);
    assert(output.fallbackUsed);
    assert(output.beforeRxUs == 1635ULL);
    assert(output.receiveHostEarliestUs == 348930590ULL);
    assert(output.receiveHostLatestUs == 348930593ULL);
    assert(output.earliestSubmitUs == 348933054ULL);
    assert(output.latestSubmitUs == 348941243ULL);
    assert(output.latestSubmitUs <
           output.receiveHostEarliestUs + Legacy::kMifFreshnessUs);
    assert(output.targetAwStartGp2Us == 300634792U);
    assert(output.targetAwStartDeltaUs == 0ULL);
    assert(output.targetAwRelation ==
           TargetAwRelation::kCurrentAwStartedBeforeMifRx);
    assert(!output.targetAwStartForwardDeltaValid);
    assert(output.targetAwStartOffsetUs == -1635);
    assert(output.targetAwCounter == 11042);
    assert(output.currentEawStartGp2Us == 300602024U);
    assert(output.currentSlot == 8);
    assert(in.timing.gates.firstOwnMifCompletionUs < output.earliestSubmitUs);
    assert(in.timing.nowUs >= output.earliestSubmitUs);
    assert(in.timing.nowUs < output.latestSubmitUs);
    assert(!output.clockMappingVerified);
    assert(!output.airtimeVerified);
    assert(output.experimentalOnly);
}

void testFreshnessEqualityAndAdjacentMicroseconds()
{
    const uint64_t freshnessUntil =
        348930590ULL + Test066MifCurrentPhase::kMifFreshnessUs;
    const uint32_t phyTargetDeltas[] = {4U, 3U, 2U};
    for (uint32_t phyMinusTarget : phyTargetDeltas) {
        Input in = exactRxGeometry();
        in.timing.mif.txDownCounterTu = 28;
        in.timing.mif.phyTxTimestampUs = 1000000U + phyMinusTarget;
        in.timing.mif.targetTxTimestampUs = 1000000U;
        // The counter low bits independently agree with floor((64-28)/16)=2.
        assert(in.timing.mif.awCounter % Test066MifCurrentPhase::kAwPerEaw == 2);
        assert((Test066MifCurrentPhase::kEawPeriodTu -
                in.timing.mif.txDownCounterTu) /
               Test066MifCurrentPhase::kExpectedAwPeriodTu == 2);

        Candidate output{};
        const LegacyStatus status = plan(in, output);
        const uint64_t d = 28ULL * 1024ULL - phyMinusTarget - 16ULL * 1024ULL;
        assert(d == 12288ULL - phyMinusTarget);
        if (phyMinusTarget == 4U) {
            // D=12,284: old E is one microsecond before freshness; the legacy
            // path returns its unchanged one-microsecond candidate.
            assert(status == LegacyStatus::kCandidate);
            assert(!output.fallbackUsed);
            assert(output.targetAwStartDeltaUs == d);
            assert(output.latestSubmitUs == freshnessUntil);
            assert(freshnessUntil - output.earliestSubmitUs == 1ULL);
        } else if (phyMinusTarget == 3U) {
            // D=12,285 with a 3-us bracket: old E equals freshness exactly,
            // so its half-open window is empty and fallback runs.
            assert(status == LegacyStatus::kCandidate);
            assert(output.fallbackUsed);
            assert(output.beforeRxUs == 4099U);
            assert(output.earliestSubmitUs == 348930590ULL);
        } else {
            // D=12,286 moves old E one microsecond beyond freshness.
            assert(status == LegacyStatus::kCandidate);
            assert(output.fallbackUsed);
            assert(output.beforeRxUs == 4098U);
            assert(output.earliestSubmitUs == 348930591ULL);
        }
    }
}

void testCounterDownCounterMismatchFailsClosed()
{
    Input in = exactRxGeometry();
    in.timing.mif.txDownCounterTu = 33;
    in.timing.mif.phyTxTimestampUs = 1001635U;
    in.timing.mif.targetTxTimestampUs = 1000000U;
    assert(in.timing.mif.awCounter % Test066MifCurrentPhase::kAwPerEaw == 2);
    assert((Test066MifCurrentPhase::kEawPeriodTu -
            in.timing.mif.txDownCounterTu) /
           Test066MifCurrentPhase::kExpectedAwPeriodTu == 1);

    Test066MifCurrentPhase::Candidate oldOutput{};
    assert(Test066MifCurrentPhase::plan(in.timing, oldOutput) ==
           LegacyStatus::kNoConservativeWindow);
    Candidate output;
    memset(&output, 0x78, sizeof(output));
    Candidate before;
    memcpy(&before, &output, sizeof(before));
    RejectReason reason = RejectReason::kNotAttempted;
    assert(plan(in, output, &reason) == LegacyStatus::kNoConservativeWindow);
    assert(reason == RejectReason::kLegacyStatus26NotProven);
    assert(memcmp(&output, &before, sizeof(output)) == 0);
}

void testWindowIsStableAcrossConditionalPlannerTimes()
{
    Input atTap = exactRxGeometry(348933210ULL);
    Input beforeLatest = exactRxGeometry(348941242ULL);
    Candidate first{};
    Candidate second{};
    assert(plan(atTap, first) == LegacyStatus::kCandidate);
    assert(plan(beforeLatest, second) == LegacyStatus::kCandidate);
    assert(first.earliestSubmitUs == second.earliestSubmitUs);
    assert(first.latestSubmitUs == second.latestSubmitUs);
    assert(first.targetAwStartGp2Us == second.targetAwStartGp2Us);
    assert(first.targetAwCounter == second.targetAwCounter);

    // Move the current AW's inner start just after the RX tap. The returned
    // E is fixed at the physical boundary; it is never clamped to plannerNow.
    Input futureStart = exactRxGeometry(348933210ULL);
    futureStart.timing.mif.txDownCounterTu = 32;
    Candidate future{};
    assert(plan(futureStart, future) == LegacyStatus::kCandidate);
    assert(future.earliestSubmitUs == 348934078ULL);
    assert(future.earliestSubmitUs > futureStart.timing.nowUs);
    assert(future.targetAwStartOffsetUs == -611);
    assert(!future.targetAwStartForwardDeltaValid);
    // A returned future window is fixed; the caller must wait for E before
    // any real submission. This counterfactual planner time is not a send.
    futureStart.timing.nowUs = future.earliestSubmitUs;
    Candidate atStart{};
    assert(plan(futureStart, atStart) == LegacyStatus::kCandidate);
    assert(atStart.earliestSubmitUs == future.earliestSubmitUs);
    assert(atStart.latestSubmitUs == future.latestSubmitUs);
}

void testNowExclusiveEndAndOwnMifCompletionBoundaries()
{
    Input in = exactRxGeometry(348941242ULL);
    Candidate atLastUs{};
    assert(plan(in, atLastUs) == LegacyStatus::kCandidate);

    in.timing.nowUs = 348941243ULL;
    Candidate output;
    memset(&output, 0x69, sizeof(output));
    Candidate before;
    memcpy(&before, &output, sizeof(before));
    RejectReason reason = RejectReason::kNotAttempted;
    assert(plan(in, output, &reason) == LegacyStatus::kNoConservativeWindow);
    assert(reason == RejectReason::kExpired);
    assert(memcmp(&output, &before, sizeof(output)) == 0);

    in = exactRxGeometry();
    in.timing.gates.firstOwnMifCompletionUs = 348933053ULL;
    Candidate beforeOwnCompletion{};
    assert(plan(in, beforeOwnCompletion) == LegacyStatus::kCandidate);
    in.timing.gates.firstOwnMifCompletionUs = 348933054ULL;
    reason = RejectReason::kNotAttempted;
    assert(plan(in, output, &reason) == LegacyStatus::kNoConservativeWindow);
    assert(reason == RejectReason::kOwnMifCompletionNotBeforeWindow);
    assert(memcmp(&output, &before, sizeof(output)) == 0);

    in.timing.gates.firstOwnMifCompletionUs = 0;
    reason = RejectReason::kNotAttempted;
    assert(plan(in, output, &reason) == LegacyStatus::kNoConservativeWindow);
    assert(reason == RejectReason::kOwnMifCompletionMissing);
    assert(memcmp(&output, &before, sizeof(output)) == 0);
}

void testLeaseReserveAndWholeWindowBoundaries()
{
    Input in = exactRxGeometry();
    Candidate output;
    memset(&output, 0x44, sizeof(output));
    Candidate before;
    memcpy(&before, &output, sizeof(before));
    RejectReason reason = RejectReason::kNotAttempted;

    in.timing.leaseEndUs = in.timing.nowUs + Legacy::kLeaseReserveUs;
    assert(plan(in, output, &reason) == LegacyStatus::kNoConservativeWindow);
    assert(reason == RejectReason::kLeaseReserve);
    assert(memcmp(&output, &before, sizeof(output)) == 0);

    in = exactRxGeometry();
    in.timing.leaseStartUs = 348933055ULL;
    reason = RejectReason::kNotAttempted;
    assert(plan(in, output, &reason) == LegacyStatus::kNoConservativeWindow);
    assert(reason == RejectReason::kOutsideLease);
    assert(memcmp(&output, &before, sizeof(output)) == 0);

    in = exactRxGeometry();
    in.timing.leaseEndUs = 348941243ULL + Legacy::kLeaseReserveUs;
    reason = RejectReason::kNotAttempted;
    assert(plan(in, output, &reason) == LegacyStatus::kCandidate);
    assert(output.latestSubmitUs == 348941243ULL);

    in.timing.leaseEndUs--;
    reason = RejectReason::kNotAttempted;
    assert(plan(in, output, &reason) == LegacyStatus::kNoConservativeWindow);
    assert(reason == RejectReason::kOutsideLease);
    assert(output.latestSubmitUs == 348941243ULL); // Failure preserved output.
}

void testGp2WrapKeepsPastStartOutOfUnsignedForwardDelta()
{
    Input in = exactRxGeometry();
    in.timing.anchor.rawGp2Us = 0xfffffff0U;
    in.timing.mif.rxGp2Us = in.timing.anchor.rawGp2Us + 458955U;
    Candidate output{};
    assert(plan(in, output) == LegacyStatus::kCandidate);
    assert(output.targetAwStartGp2Us == in.timing.mif.rxGp2Us - 1635U);
    assert(output.beforeRxUs == 1635U);
    assert(output.targetAwStartDeltaUs == 0U);
    assert(output.targetAwRelation ==
           TargetAwRelation::kCurrentAwStartedBeforeMifRx);
    assert(!output.targetAwStartForwardDeltaValid);
    assert(output.targetAwStartOffsetUs == -1635);
    assert(output.targetAwCounter == in.timing.mif.awCounter);

    // Wrap the RX counter itself below the elapsed-current-AW value. The
    // helper must keep the signed host offset while applying GP2 modulo wrap.
    in = exactRxGeometry();
    in.timing.mif.rxGp2Us = 1000U;
    in.timing.anchor.rawGp2Us = static_cast<uint32_t>(1000U - 458955U);
    Candidate lowWrapped{};
    assert(plan(in, lowWrapped) == LegacyStatus::kCandidate);
    assert(lowWrapped.targetAwStartGp2Us ==
           static_cast<uint32_t>(1000U - 1635U));
    assert(lowWrapped.targetAwStartOffsetUs == -1635);
    assert(lowWrapped.beforeRxUs == 1635U);
    assert(!lowWrapped.targetAwStartForwardDeltaValid);
}

void testDescribeIsPureAndMarksOutputValidity()
{
    Input in = exactRxGeometry();
    const Input before = in;
    PlanObservation observation = describe(in);
    assert(memcmp(&in, &before, sizeof(in)) == 0);
    assert(observation.status == LegacyStatus::kCandidate);
    assert(observation.why == RejectReason::kNotAttempted);
    assert(observation.plannerNowValid);
    assert(observation.plannerNowUs == in.timing.nowUs);
    assert(observation.geometryValid);
    assert(observation.freshnessUntilValid);
    assert(observation.windowValid);
    assert(observation.candidateAvailable);
    assert(observation.fallbackAttempted);
    assert(observation.receiveHostEarliestUs == 348930590ULL);
    assert(observation.receiveHostLatestUs == 348930593ULL);
    assert(observation.freshnessUntilUs == 348946974ULL);
    assert(observation.earliestSubmitUs == 348933054ULL);
    assert(observation.latestSubmitUs == 348941243ULL);
    assert(observation.selectedRelationValid);
    assert(observation.selectedRelation ==
           TargetAwRelation::kCurrentAwStartedBeforeMifRx);
    assert(!observation.forwardDeltaValid);

    Input expired = exactRxGeometry(348941243ULL);
    PlanObservation expiredObservation = describe(expired);
    assert(expiredObservation.status == LegacyStatus::kNoConservativeWindow);
    assert(expiredObservation.why == RejectReason::kExpired);
    assert(expiredObservation.fallbackAttempted);
    assert(expiredObservation.geometryValid);
    assert(expiredObservation.windowValid);
    assert(!expiredObservation.candidateAvailable);
    assert(expiredObservation.earliestSubmitUs == 348933054ULL);
    assert(expiredObservation.latestSubmitUs == 348941243ULL);

    Test066MifCurrentPhase::Input legacy = legacyCandidateInput();
    PlanObservation legacyObservation = describe(Input{legacy});
    assert(legacyObservation.status == LegacyStatus::kCandidate);
    assert(legacyObservation.candidateAvailable);
    assert(!legacyObservation.fallbackAttempted);
    assert(legacyObservation.selectedRelation ==
           TargetAwRelation::kFutureFromMifRx);
    assert(legacyObservation.forwardDeltaValid);

    legacy.gates.firstOwnMifCompletionUs = 0;
    PlanObservation oldFailure = describe(Input{legacy});
    assert(oldFailure.status == LegacyStatus::kOwnMifNotCompletedBeforeWindow);
    assert(!oldFailure.candidateAvailable);
    assert(!oldFailure.fallbackAttempted);
    assert(!oldFailure.geometryValid);
}

void testCheckedSubtractionAndAddition()
{
    Window output{123, 456};
    const Window before = output;
    RejectReason reason = RejectReason::kNotAttempted;
    assert(!calculateWindow(100, 101, 102, output, reason));
    assert(reason == RejectReason::kProjectedRxSubtractionUnderflow);
    assert(output.earliestSubmitUs == before.earliestSubmitUs);
    assert(output.latestSubmitUs == before.latestSubmitUs);

    reason = RejectReason::kNotAttempted;
    assert(!calculateWindow(UINT64_MAX - 1000, UINT64_MAX - 997,
                            0, output, reason));
    assert(reason == RejectReason::kTimeAdditionOverflow);
    assert(output.earliestSubmitUs == before.earliestSubmitUs);
    assert(output.latestSubmitUs == before.latestSubmitUs);

    Window valid{};
    reason = RejectReason::kNotAttempted;
    assert(calculateWindow(348930590ULL, 348930593ULL, 1635ULL,
                          valid, reason));
    assert(reason == RejectReason::kNotAttempted);
    assert(valid.earliestSubmitUs == 348933054ULL);
    assert(valid.latestSubmitUs == 348941243ULL);
}

void testLegacyCandidateAndEveryLegacyFailurePassThrough()
{
    Test066MifCurrentPhase::Input oldInput = legacyCandidateInput();
    Test066MifCurrentPhase::Candidate oldCandidate{};
    assert(Test066MifCurrentPhase::plan(oldInput, oldCandidate) ==
           LegacyStatus::kCandidate);
    Input wrapped{oldInput};
    Candidate wrappedCandidate{};
    assert(plan(wrapped, wrappedCandidate) == LegacyStatus::kCandidate);
    assert(!wrappedCandidate.fallbackUsed);
    assert(wrappedCandidate.beforeRxUs == 0);
    assert(wrappedCandidate.targetAwRelation ==
           TargetAwRelation::kFutureFromMifRx);
    assert(wrappedCandidate.targetAwStartForwardDeltaValid);
    assert(wrappedCandidate.targetAwStartOffsetUs ==
           static_cast<int32_t>(oldCandidate.targetAwStartDeltaUs));
    assert(memcmp(static_cast<const Test066MifCurrentPhase::Candidate *>(
                      &wrappedCandidate),
                  &oldCandidate, sizeof(oldCandidate)) == 0);

    Input in = exactRxGeometry();
    in.timing.nowUs = 0;
    expectOldFailurePassthrough(in, LegacyStatus::kInvalidInput, "invalid_input");

    in = exactRxGeometry();
    in.timing.gates.explicitlyEnabled = false;
    expectOldFailurePassthrough(in, LegacyStatus::kModeNotEnabled, "mode");

    in = exactRxGeometry();
    in.timing.gates.hostMonotonicDomainVerified = false;
    expectOldFailurePassthrough(in, LegacyStatus::kTimeSourceUnverified, "time_source");

    in = exactRxGeometry();
    in.timing.gates.ownMifTxSucceeded = false;
    expectOldFailurePassthrough(in, LegacyStatus::kPrerequisiteMissing, "gates");

    in = exactRxGeometry();
    setAllEpochs(in.timing, {0, 12, 13, 14});
    expectOldFailurePassthrough(in, LegacyStatus::kInvalidEpoch, "zero_epoch");

    in = exactRxGeometry();
    in.timing.mif.epochs.roc++;
    expectOldFailurePassthrough(in, LegacyStatus::kEpochMismatch, "epoch_mismatch");

    in = exactRxGeometry();
    in.timing.binding.sameEntryVerified = false;
    expectOldFailurePassthrough(in, LegacyStatus::kMissingBinding, "missing_binding");

    in = exactRxGeometry();
    in.timing.binding.peerIncarnation++;
    expectOldFailurePassthrough(in, LegacyStatus::kBindingMismatch, "binding_mismatch");

    in = exactRxGeometry();
    in.timing.mif.present = false;
    expectOldFailurePassthrough(in, LegacyStatus::kMissingMif, "missing_mif");

    in = exactRxGeometry();
    in.timing.mif.complete = false;
    expectOldFailurePassthrough(in, LegacyStatus::kIncompleteMif, "incomplete_mif");

    in = exactRxGeometry();
    in.timing.mif.fresh = false;
    expectOldFailurePassthrough(in, LegacyStatus::kStaleMif, "stale_mif");

    in = exactRxGeometry();
    in.timing.anchor.directReadBracket = false;
    expectOldFailurePassthrough(in, LegacyStatus::kInvalidAnchor, "anchor_provenance");

    in = exactRxGeometry();
    in.timing.anchor.hostAfterUs = in.timing.anchor.hostBeforeUs - 1;
    expectOldFailurePassthrough(in, LegacyStatus::kAnchorBracket, "anchor_bracket");

    in = exactRxGeometry();
    in.timing.anchor.hostAfterUs = in.timing.anchor.hostBeforeUs +
        Test066MifCurrentPhase::kMaximumAnchorBracketUs + 1;
    expectOldFailurePassthrough(in, LegacyStatus::kAnchorTooWide, "anchor_width");

    in = exactRxGeometry();
    in.timing.anchor.hostAfterUs = in.timing.mif.rxMonotonicUs + 1;
    in.timing.anchor.hostBeforeUs = in.timing.anchor.hostAfterUs;
    expectOldFailurePassthrough(in, LegacyStatus::kAnchorAfterMif, "anchor_after_mif");

    in = exactRxGeometry();
    in.timing.mif.rxGp2Us = in.timing.anchor.rawGp2Us + 461955U;
    expectOldFailurePassthrough(in, LegacyStatus::kProjectedRxAfterTap, "rx_after_tap");

    in = exactRxGeometry();
    in.timing.mif.rxGp2Us = in.timing.anchor.rawGp2Us + 0x80000000U;
    expectOldFailurePassthrough(in, LegacyStatus::kGp2HalfRange, "gp2_half_range");

    in = exactRxGeometry();
    in.timing.mif.rxGp2Us = in.timing.anchor.rawGp2Us +
        Test066MifCurrentPhase::kMaximumAnchorToMifUs;
    expectOldFailurePassthrough(in, LegacyStatus::kAnchorToMifTooOld, "anchor_age");

    in = exactRxGeometry();
    in.timing.mif.presenceMode = 3;
    expectOldFailurePassthrough(in, LegacyStatus::kInvalidTiming, "timing");

    in = exactRxGeometry();
    in.timing.mif.canonicalSlots[0] = 234;
    expectOldFailurePassthrough(in, LegacyStatus::kInvalidSchedule, "schedule_range");

    in = exactRxGeometry();
    in.timing.mif.canonicalSlots[8] = 11;
    expectOldFailurePassthrough(in, LegacyStatus::kWrongCurrentSlotChannel, "schedule_channel");

    in = exactRxGeometry();
    in.timing.mif.awCounter = 11043;
    expectOldFailurePassthrough(in, LegacyStatus::kNoFollowingAwInCurrentSlot, "last_aw_in_slot");

    in = exactRxGeometry();
    in.timing.mif.txDownCounterTu = 49;
    expectOldFailurePassthrough(in, LegacyStatus::kFutureAwOutOfRange, "future_aw_range");

    in = exactRxGeometry();
    in.timing.anchor.hostBeforeUs = UINT64_MAX - 460000ULL;
    in.timing.anchor.hostAfterUs = in.timing.anchor.hostBeforeUs + 3;
    in.timing.mif.rxMonotonicUs = UINT64_MAX - 500ULL;
    in.timing.nowUs = UINT64_MAX - 400ULL;
    in.timing.leaseStartUs = UINT64_MAX - 20000ULL;
    in.timing.leaseEndUs = UINT64_MAX - 1ULL;
    expectOldFailurePassthrough(in, LegacyStatus::kArithmeticOverflow, "overflow");

    oldInput = legacyCandidateInput();
    oldInput.leaseEndUs = oldInput.nowUs + Legacy::kLeaseReserveUs;
    expectOldFailurePassthrough(Input{oldInput}, LegacyStatus::kLeaseReserve,
                                "legacy_lease_reserve");

    oldInput = legacyCandidateInput();
    oldInput.leaseStartUs = 560570846ULL;
    expectOldFailurePassthrough(Input{oldInput}, LegacyStatus::kCandidateOutsideLease,
                                "legacy_lease_start");

    oldInput = legacyCandidateInput(560576088ULL);
    expectOldFailurePassthrough(Input{oldInput}, LegacyStatus::kCandidateExpired,
                                "legacy_expired");

    oldInput = legacyCandidateInput();
    oldInput.leaseEndUs = 560576088ULL + Legacy::kLeaseReserveUs - 1;
    expectOldFailurePassthrough(Input{oldInput}, LegacyStatus::kCandidateOutsideLease,
                                "legacy_lease_end");

    oldInput = legacyCandidateInput();
    oldInput.gates.firstOwnMifCompletionUs = 0;
    expectOldFailurePassthrough(
        Input{oldInput}, LegacyStatus::kOwnMifNotCompletedBeforeWindow,
        "legacy_missing_own_mif_completion");

    oldInput = legacyCandidateInput();
    oldInput.gates.firstOwnMifCompletionUs = 560570845ULL;
    expectOldFailurePassthrough(
        Input{oldInput}, LegacyStatus::kOwnMifNotCompletedBeforeWindow,
        "legacy_own_mif_completion_at_window_start");
}

} // namespace

int main()
{
    testRootRxNumericFixtureIsConditionalAndExact();
    testFreshnessEqualityAndAdjacentMicroseconds();
    testCounterDownCounterMismatchFailsClosed();
    testWindowIsStableAcrossConditionalPlannerTimes();
    testNowExclusiveEndAndOwnMifCompletionBoundaries();
    testLeaseReserveAndWholeWindowBoundaries();
    testGp2WrapKeepsPastStartOutOfUnsignedForwardDelta();
    testDescribeIsPureAndMarksOutputValidity();
    testCheckedSubtractionAndAddition();
    testLegacyCandidateAndEveryLegacyFailurePassThrough();
    puts("Test077 current-AW fallback tests passed");
    return 0;
}
