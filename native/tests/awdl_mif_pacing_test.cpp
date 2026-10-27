// SPDX-License-Identifier: GPL-2.0-only
#include "../awdl_mif_pacing.hpp"

#include <assert.h>
#include <stdint.h>
#include <limits.h>

using namespace NativeAwdlProbe;

namespace {

constexpr uint64_t kStartUs = 1000000;
constexpr uint64_t kRocDurationUs = 900000;
constexpr uint64_t kTuUs = 1024;
constexpr uint64_t kAdvertisedWindowDurationUs = 12 * 64 * kTuUs;

MifPacingInput readyInput(uint32_t ordinal = 0)
{
    MifPacingInput input{};
    input.phaseOriginUs = kStartUs;
    input.announcedWindowEndUs =
        kStartUs + kAdvertisedWindowDurationUs;
    input.hardDeadlineUs = kStartUs + kRocDurationUs;
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
    return input;
}

uint64_t threshold(uint32_t ordinal)
{
    return kStartUs +
        ((ordinal + 1) * kAdvertisedWindowDurationUs + 3) / 4;
}

void setFreshAnchor(MifPacingInput *input, uint64_t rxUs, uint64_t ageUs = 0)
{
    assert(input);
    input->peerPsfRxUs = rxUs;
    input->nowUs = rxUs + ageUs;
}

void testPostNotBeforeThresholds()
{
    for (uint32_t ordinal = 0; ordinal < 3; ++ordinal) {
        auto input = readyInput(ordinal);
        const uint64_t earliest = threshold(ordinal);
        uint64_t cheapNotBefore = 0;
        assert(mifPacingNotBeforeUs(input.phaseOriginUs,
            input.announcedWindowEndUs, ordinal, &cheapNotBefore));
        assert(cheapNotBefore == earliest);
        setFreshAnchor(&input, earliest);
        const auto plan = planMifPacing(input);
        assert(plan.decision == MifPacingDecision::Ready);
        assert(plan.earliestUs == earliest);
        assert(plan.latestUs == earliest + 16 * kTuUs);

        input.peerPsfRxUs = earliest - 1;
        input.nowUs = earliest;
        assert(planMifPacing(input).decision == MifPacingDecision::Wait);

        input.peerPsfRxUs = earliest;
        input.nowUs = earliest - 1;
        assert(planMifPacing(input).decision == MifPacingDecision::Wait);
        assert(planMifPacing(input).earliestUs == cheapNotBefore);
    }
    auto exhausted = readyInput(3);
    setFreshAnchor(&exhausted, threshold(2));
    assert(planMifPacing(exhausted).decision == MifPacingDecision::Stop);
}

void testPositiveFreshPsfWindowBoundary()
{
    auto input = readyInput();
    const uint64_t rxUs = threshold(0);
    setFreshAnchor(&input, rxUs, 16 * kTuUs);
    auto plan = planMifPacing(input);
    assert(plan.decision == MifPacingDecision::Ready);
    assert(plan.peerPsfAgeUs == 16 * kTuUs);
    assert(plan.latestUs == rxUs + 16 * kTuUs);

    ++input.nowUs;
    plan = planMifPacing(input);
    assert(plan.decision == MifPacingDecision::Wait);
    assert(plan.latestUs == rxUs + 16 * kTuUs);
}

void testPsfReceivedDuringGateUsesPostDrainTime()
{
    auto input = readyInput();
    const uint64_t earliest = threshold(0);
    input.peerPsfRxUs = earliest + 1;
    input.nowUs = earliest; // Worker sample taken before the gate drain.
    auto plan = planMifPacing(input);
    assert(plan.decision == MifPacingDecision::Stop);
    assert(plan.reason == MifPacingReason::InvalidTime);

    input.nowUs = input.peerPsfRxUs; // Main-gate sample taken after RX drain.
    plan = planMifPacing(input);
    assert(plan.decision == MifPacingDecision::Ready);
    assert(plan.anchorRxUs == input.peerPsfRxUs);
}

void testOneFreshAnchorPerFrame()
{
    auto input = readyInput(1);
    const uint64_t earliest = threshold(1);
    setFreshAnchor(&input, earliest);
    input.lastUsedPeerPsfRxUs = earliest;
    assert(planMifPacing(input).decision == MifPacingDecision::Wait);

    input.peerPsfRxUs = earliest + 1;
    input.nowUs = earliest + 1;
    assert(planMifPacing(input).decision == MifPacingDecision::Ready);
}

void testChannelMustBeMappedByProduction()
{
    auto input = readyInput();
    setFreshAnchor(&input, threshold(0));
    // The raw RX index is diagnostic only. Index 6 is not by itself proof
    // that the received peer frame arrived on IEEE channel 6.
    input.peerRxChannelIndex = 6;
    input.peerPsfRxChannel6Confirmed = false;
    assert(planMifPacing(input).decision == MifPacingDecision::Wait);

    input.peerPsfRxChannel6Confirmed = true;
    assert(planMifPacing(input).decision == MifPacingDecision::Ready);
}

void testStrictEpochAndRocFences()
{
    auto input = readyInput();
    setFreshAnchor(&input, threshold(0));
    input.peerPowerGeneration++;
    assert(planMifPacing(input).decision == MifPacingDecision::Stop);

    input = readyInput();
    setFreshAnchor(&input, threshold(0));
    input.rocActive = false;
    assert(planMifPacing(input).decision == MifPacingDecision::Stop);

    input = readyInput();
    setFreshAnchor(&input, threshold(0));
    input.endSeen = true;
    assert(planMifPacing(input).decision == MifPacingDecision::Stop);

    input = readyInput();
    setFreshAnchor(&input, threshold(0));
    input.outcomeUnknown = true;
    assert(planMifPacing(input).decision == MifPacingDecision::Stop);
}

void testIncompleteAndInconsistentPsfNeverReady()
{
    auto input = readyInput();
    setFreshAnchor(&input, threshold(0));
    input.peerPsfComplete = false;
    assert(planMifPacing(input).decision == MifPacingDecision::Wait);

    input = readyInput();
    setFreshAnchor(&input, threshold(0));
    input.peerPsfSyncConsistent = false;
    assert(planMifPacing(input).decision == MifPacingDecision::Wait);

    input = readyInput();
    setFreshAnchor(&input, threshold(0));
    input.peerPsfFresh = false;
    assert(planMifPacing(input).decision == MifPacingDecision::Wait);
}

void testDeadlineAndShortLeaseFailClosed()
{
    auto input = readyInput();
    input.announcedWindowEndUs = input.phaseOriginUs + 1000;
    input.nowUs = input.phaseOriginUs;
    assert(planMifPacing(input).decision == MifPacingDecision::Stop);

    input = readyInput();
    const uint64_t effectiveEnd = input.announcedWindowEndUs;
    input.nowUs = effectiveEnd - kMifPacingMinimumLeaseReserveUs;
    input.peerPsfRxUs = input.nowUs;
    auto plan = planMifPacing(input);
    assert(plan.decision == MifPacingDecision::Stop);
    assert(plan.reason == MifPacingReason::InsufficientLease);

    input = readyInput();
    input.nowUs = input.announcedWindowEndUs;
    input.peerPsfComplete = false;
    assert(planMifPacing(input).decision == MifPacingDecision::Stop);

    input = readyInput();
    input.nowUs = input.hardDeadlineUs - 1;
    input.peerPsfComplete = false;
    assert(planMifPacing(input).decision == MifPacingDecision::Stop);
}

void testInvalidAndNearUint64TimesSafe()
{
    auto input = readyInput();
    input.nowUs = input.phaseOriginUs - 1;
    input.peerPsfRxUs = threshold(0);
    assert(planMifPacing(input).decision == MifPacingDecision::Stop);

    input = readyInput(2);
    input.phaseOriginUs = UINT64_MAX - 500000;
    input.announcedWindowEndUs = input.phaseOriginUs + 400000;
    input.hardDeadlineUs = UINT64_MAX;
    input.nowUs = input.phaseOriginUs + 300000;
    input.peerPsfRxUs = input.nowUs;
    auto plan = planMifPacing(input);
    assert(plan.decision == MifPacingDecision::Ready);
    assert(plan.earliestUs == input.nowUs);
    assert(plan.latestUs == input.nowUs + 16 * kTuUs);

    input = readyInput();
    input.phaseOriginUs = UINT64_MAX - 50000;
    input.announcedWindowEndUs = input.phaseOriginUs + 40000;
    input.hardDeadlineUs = UINT64_MAX;
    input.nowUs = input.phaseOriginUs + 10000;
    input.peerPsfRxUs = input.nowUs;
    plan = planMifPacing(input);
    assert(plan.decision == MifPacingDecision::Ready);
    assert(plan.latestUs == input.nowUs + 16 * kTuUs);
    assert(MifPacingDetail::saturatingAdd(UINT64_MAX - 10, 20) == UINT64_MAX);
}

void testMissingPsfWaitsThenStopsAtEnd()
{
    auto input = readyInput();
    input.peerPsfComplete = false;
    input.nowUs = threshold(0);
    assert(planMifPacing(input).decision == MifPacingDecision::Wait);

    input.nowUs = input.announcedWindowEndUs -
        kMifPacingMinimumLeaseReserveUs - 1;
    assert(planMifPacing(input).decision == MifPacingDecision::Wait);

    input.nowUs = input.announcedWindowEndUs -
        kMifPacingMinimumLeaseReserveUs;
    assert(planMifPacing(input).decision == MifPacingDecision::Stop);

    input.nowUs = input.announcedWindowEndUs;
    assert(planMifPacing(input).decision == MifPacingDecision::Stop);
}

} // namespace

int main()
{
    testPostNotBeforeThresholds();
    testPositiveFreshPsfWindowBoundary();
    testPsfReceivedDuringGateUsesPostDrainTime();
    testOneFreshAnchorPerFrame();
    testChannelMustBeMappedByProduction();
    testStrictEpochAndRocFences();
    testIncompleteAndInconsistentPsfNeverReady();
    testDeadlineAndShortLeaseFailClosed();
    testInvalidAndNearUint64TimesSafe();
    testMissingPsfWaitsThenStopsAtEnd();
    return 0;
}
