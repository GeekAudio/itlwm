// SPDX-License-Identifier: GPL-2.0-only
#include "../awdl_mif_pacing.hpp"

#include <assert.h>
#include <stdint.h>
#include <limits.h>

using namespace NativeAwdlProbe;

namespace {

constexpr uint64_t kPhaseOriginUs = 1000000ULL;
constexpr uint64_t kThirteenChannel6SlotsUs = 13ULL * 65536ULL;
constexpr uint64_t kShortWindowUs = 40000ULL;

uint64_t quarterThreshold(uint64_t phaseOriginUs, uint64_t durationUs,
                          uint32_t ordinal)
{
    const uint64_t numerator = static_cast<uint64_t>(ordinal) + 1;
    return phaseOriginUs + (durationUs * numerator + 3) / 4;
}

MifPacingInput readyInput(uint32_t ordinal, MifPacingPolicy policy,
                          uint64_t durationUs = kThirteenChannel6SlotsUs)
{
    MifPacingInput input{};
    input.phaseOriginUs = kPhaseOriginUs;
    input.announcedWindowEndUs = kPhaseOriginUs + durationUs;
    input.hardDeadlineUs = input.announcedWindowEndUs + 50000ULL;
    input.frameOrdinal = ordinal;
    input.contextGeneration = 7;
    input.powerGeneration = 11;
    input.stationGeneration = 13;
    input.peerContextGeneration = 7;
    input.peerPowerGeneration = 11;
    input.peerStationGeneration = 13;
    input.rocActive = true;
    input.rocChannel6Confirmed = true;
    input.peerPsfComplete = true;
    input.peerPsfSyncConsistent = true;
    input.peerPsfFresh = true;
    input.peerRxChannelIndex = 6;
    input.peerPsfRxChannel6Confirmed = true;
    input.policy = policy;
    return input;
}

void setAnchor(MifPacingInput *input, uint64_t rxUs, uint64_t ageUs = 0)
{
    assert(input);
    input->peerPsfRxUs = rxUs;
    input->nowUs = rxUs + ageUs;
}

void testSharedEarliestPolicyAcrossAllOrdinals()
{
    constexpr MifPacingPolicy policies[] = {
        MifPacingPolicy::LegacyPsfAfterNotBefore,
        MifPacingPolicy::Test066SamePeerMifTiming,
        MifPacingPolicy::Test069EarlyFirstMif
    };
    for (const auto policy : policies) {
        for (uint32_t ordinal = 0; ordinal < kMifPacingMaximumFrames;
             ++ordinal) {
            const uint64_t expected =
                policy == MifPacingPolicy::Test069EarlyFirstMif &&
                ordinal == 0 ? kPhaseOriginUs :
                quarterThreshold(kPhaseOriginUs,
                                 kThirteenChannel6SlotsUs, ordinal);
            uint64_t cheapEarliest = 0;
            assert(mifPacingNotBeforeUs(kPhaseOriginUs,
                kPhaseOriginUs + kThirteenChannel6SlotsUs, ordinal,
                &cheapEarliest, policy));
            assert(cheapEarliest == expected);

            auto input = readyInput(ordinal, policy);
            setAnchor(&input, expected);
            const auto plan = planMifPacing(input);
            assert(plan.earliestUs == cheapEarliest);
            assert(plan.decision == MifPacingDecision::Ready);
        }
    }

    // Omitting the policy remains the original legacy behavior.
    uint64_t defaultEarliest = 0;
    assert(mifPacingNotBeforeUs(kPhaseOriginUs,
        kPhaseOriginUs + kThirteenChannel6SlotsUs, 0, &defaultEarliest));
    assert(defaultEarliest == quarterThreshold(
        kPhaseOriginUs, kThirteenChannel6SlotsUs, 0));
}

void testLegacyAndTest066SemanticsRemainDistinct()
{
    auto legacy = readyInput(0,
        MifPacingPolicy::LegacyPsfAfterNotBefore, kShortWindowUs);
    const uint64_t quarter = quarterThreshold(
        kPhaseOriginUs, kShortWindowUs, 0);
    setAnchor(&legacy, quarter - 1);
    legacy.nowUs = quarter;
    auto plan = planMifPacing(legacy);
    assert(plan.decision == MifPacingDecision::Wait);
    assert(plan.reason == MifPacingReason::PsfBeforeNotBefore);

    auto test066 = readyInput(0,
        MifPacingPolicy::Test066SamePeerMifTiming, kShortWindowUs);
    setAnchor(&test066, quarter - 1);
    test066.nowUs = quarter;
    plan = planMifPacing(test066);
    assert(plan.decision == MifPacingDecision::Ready);
    assert(plan.anchorRxUs == quarter - 1);

    // Test066 retains its pre-phase behavior for compatibility. Test069 adds
    // an explicit phase-origin floor without changing either older policy.
    test066.peerPsfRxUs = kPhaseOriginUs - 1;
    test066.nowUs = quarter;
    plan = planMifPacing(test066);
    assert(plan.decision == MifPacingDecision::Ready);
}

void testTest069AllowsFreshPreQuarterAnchorOnlyInsidePhase()
{
    constexpr uint64_t durationUs = 100000ULL;
    for (uint32_t ordinal = 0; ordinal < kMifPacingMaximumFrames;
         ++ordinal) {
        auto input = readyInput(ordinal,
            MifPacingPolicy::Test069EarlyFirstMif, durationUs);
        const uint64_t earliest = ordinal == 0 ? kPhaseOriginUs :
            quarterThreshold(kPhaseOriginUs, durationUs, ordinal);
        if (ordinal == 0) {
            setAnchor(&input, kPhaseOriginUs);
        } else {
            // A same-phase PSF just before a later ordinal's quarter remains
            // usable while the 16-TU freshness lease is live.
            setAnchor(&input, earliest - 1);
            input.nowUs = earliest;
        }
        auto plan = planMifPacing(input);
        assert(plan.decision == MifPacingDecision::Ready);
        assert(plan.earliestUs == earliest);

        input.peerPsfRxUs = kPhaseOriginUs - 1;
        input.nowUs = earliest;
        plan = planMifPacing(input);
        assert(plan.decision == MifPacingDecision::Wait);
        assert(plan.reason == MifPacingReason::PsfBeforePhaseOrigin);
    }
}

void testTest069FreshnessBoundaryAndExpiredAnchor()
{
    auto input = readyInput(0, MifPacingPolicy::Test069EarlyFirstMif,
                            kShortWindowUs);
    setAnchor(&input, kPhaseOriginUs, kMifPacingMaximumPeerPsfAgeUs);
    auto plan = planMifPacing(input);
    assert(plan.decision == MifPacingDecision::Ready);
    assert(plan.peerPsfAgeUs == kMifPacingMaximumPeerPsfAgeUs);
    assert(plan.latestUs == kPhaseOriginUs +
        kMifPacingMaximumPeerPsfAgeUs);

    ++input.nowUs;
    plan = planMifPacing(input);
    assert(plan.decision == MifPacingDecision::Wait);
    assert(plan.reason == MifPacingReason::PsfTooOld);
}

void testTest069KeepsEpochChannelAndRocFences()
{
    auto input = readyInput(0, MifPacingPolicy::Test069EarlyFirstMif,
                            kShortWindowUs);
    setAnchor(&input, kPhaseOriginUs);
    input.peerContextGeneration++;
    assert(planMifPacing(input).reason == MifPacingReason::WrongEpoch);

    input = readyInput(0, MifPacingPolicy::Test069EarlyFirstMif,
                       kShortWindowUs);
    setAnchor(&input, kPhaseOriginUs);
    input.peerPowerGeneration++;
    assert(planMifPacing(input).reason == MifPacingReason::WrongEpoch);

    input = readyInput(0, MifPacingPolicy::Test069EarlyFirstMif,
                       kShortWindowUs);
    setAnchor(&input, kPhaseOriginUs);
    input.peerStationGeneration++;
    assert(planMifPacing(input).reason == MifPacingReason::WrongEpoch);

    input = readyInput(0, MifPacingPolicy::Test069EarlyFirstMif,
                       kShortWindowUs);
    setAnchor(&input, kPhaseOriginUs);
    input.peerPsfRxChannel6Confirmed = false;
    assert(planMifPacing(input).reason == MifPacingReason::PsfWrongChannel);

    input = readyInput(0, MifPacingPolicy::Test069EarlyFirstMif,
                       kShortWindowUs);
    setAnchor(&input, kPhaseOriginUs);
    input.rocActive = false;
    assert(planMifPacing(input).reason == MifPacingReason::RocInactive);

    input = readyInput(0, MifPacingPolicy::Test069EarlyFirstMif,
                       kShortWindowUs);
    setAnchor(&input, kPhaseOriginUs);
    input.rocChannel6Confirmed = false;
    assert(planMifPacing(input).reason ==
           MifPacingReason::RocChannelUnconfirmed);

    input = readyInput(0, MifPacingPolicy::Test069EarlyFirstMif,
                       kShortWindowUs);
    setAnchor(&input, kPhaseOriginUs);
    input.endSeen = true;
    assert(planMifPacing(input).reason == MifPacingReason::RocEnded);

    input = readyInput(0, MifPacingPolicy::Test069EarlyFirstMif,
                       kShortWindowUs);
    setAnchor(&input, kPhaseOriginUs);
    input.outcomeUnknown = true;
    assert(planMifPacing(input).reason == MifPacingReason::RocUnknown);
}

void testUsedAnchorDeadlineAndFrameLimitRemainEnforced()
{
    auto input = readyInput(1, MifPacingPolicy::Test069EarlyFirstMif,
                            100000ULL);
    const uint64_t earliest = quarterThreshold(
        kPhaseOriginUs, 100000ULL, 1);
    setAnchor(&input, earliest);
    input.lastUsedPeerPsfRxUs = earliest;
    assert(planMifPacing(input).reason == MifPacingReason::PsfAlreadyUsed);

    input = readyInput(3, MifPacingPolicy::Test069EarlyFirstMif,
                       kShortWindowUs);
    assert(planMifPacing(input).reason == MifPacingReason::FrameLimit);
    uint64_t ignored = 0;
    assert(!mifPacingNotBeforeUs(kPhaseOriginUs,
        kPhaseOriginUs + kShortWindowUs, 3, &ignored,
        MifPacingPolicy::Test069EarlyFirstMif));

    input = readyInput(0, MifPacingPolicy::Test069EarlyFirstMif,
                       kShortWindowUs);
    input.nowUs = input.announcedWindowEndUs -
        kMifPacingMinimumLeaseReserveUs;
    input.peerPsfRxUs = input.nowUs;
    assert(planMifPacing(input).reason ==
           MifPacingReason::InsufficientLease);
}

void testUnknownPolicyAndOverflowBoundariesFailClosed()
{
    const auto unknown = static_cast<MifPacingPolicy>(0xff);
    uint64_t output = 0x12345678ULL;
    assert(!mifPacingNotBeforeUs(kPhaseOriginUs,
        kPhaseOriginUs + kShortWindowUs, 0, &output, unknown));
    assert(output == 0x12345678ULL);

    auto input = readyInput(0, unknown, kShortWindowUs);
    setAnchor(&input, kPhaseOriginUs);
    auto plan = planMifPacing(input);
    assert(plan.decision == MifPacingDecision::Stop);
    assert(plan.reason == MifPacingReason::InvalidInput);

    const uint64_t nearMaxOrigin = UINT64_MAX - 10ULL;
    uint64_t nearMaxEarliest = 0;
    uint64_t maximumQuarterOffset = 0;
    assert(MifPacingDetail::quarterOffset(
        UINT64_MAX, 2, &maximumQuarterOffset));
    assert(maximumQuarterOffset == UINT64_C(13835058055282163712));
    assert(mifPacingNotBeforeUs(nearMaxOrigin, UINT64_MAX, 2,
        &nearMaxEarliest, MifPacingPolicy::Test069EarlyFirstMif));
    assert(nearMaxEarliest == UINT64_MAX - 2ULL);

    auto nearMax = readyInput(0, MifPacingPolicy::Test069EarlyFirstMif,
                              40000ULL);
    nearMax.phaseOriginUs = UINT64_MAX - 50000ULL;
    nearMax.announcedWindowEndUs = UINT64_MAX - 10000ULL;
    nearMax.hardDeadlineUs = UINT64_MAX;
    nearMax.nowUs = nearMax.phaseOriginUs + 1;
    nearMax.peerPsfRxUs = nearMax.nowUs;
    plan = planMifPacing(nearMax);
    assert(plan.decision == MifPacingDecision::Ready);
    assert(plan.earliestUs == nearMax.phaseOriginUs);
}

} // namespace

int main()
{
    testSharedEarliestPolicyAcrossAllOrdinals();
    testLegacyAndTest066SemanticsRemainDistinct();
    testTest069AllowsFreshPreQuarterAnchorOnlyInsidePhase();
    testTest069FreshnessBoundaryAndExpiredAnchor();
    testTest069KeepsEpochChannelAndRocFences();
    testUsedAnchorDeadlineAndFrameLimitRemainEnforced();
    testUnknownPolicyAndOverflowBoundariesFailClosed();
    return 0;
}
