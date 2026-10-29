// SPDX-License-Identifier: GPL-2.0-only
#include "../awdl_shared_window.hpp"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

using namespace NativeAwdlSharedWindow;

static const Epoch kEpoch = {11, 12, 13, 14};

static Request validRequest()
{
    Request request{};
    request.currentEpoch = kEpoch;
    request.nowUs = 1060000;

    request.peer.epoch = kEpoch;
    request.peer.peerToken = 0x31415926;
    request.peer.scheduleRevision = 7;
    request.peer.mifPeerValid = true;
    request.peer.identityWitnessVerified = true;
    request.peer.identityMatchesCurrentPeer = true;
    request.peer.scheduleWitnessVerified = true;
    request.peer.channel = 6;
    request.peer.mifObservedAtUs = 900000;
    request.peer.mifValidUntilUs = 2000000;
    request.peer.scheduleObservedAtUs = 950000;
    request.peer.scheduleValidUntilUs = 1900000;

    request.peerWindow.epoch = kEpoch;
    request.peerWindow.peerToken = 0x31415926;
    request.peerWindow.scheduleRevision = 7;
    request.peerWindow.channel = 6;
    request.peerWindow.mappingVerified = true;
    request.peerWindow.mappedStartUs = {1100000, 1100100};
    request.peerWindow.mappedEndUs = {1299900, 1300000};
    request.peerWindow.verifiedErrorBoundUs = 100;
    request.peerWindow.mappingObservedAtUs = 990000;
    request.peerWindow.mappingValidUntilUs = 1800000;

    request.localLease.epoch = kEpoch;
    request.localLease.channel = 6;
    request.localLease.known = true;
    request.localLease.active = true;
    request.localLease.startUs = {1049900, 1050000};
    request.localLease.endUs = {1500000, 1500100};

    request.guard.trafficSchedulePolicyVerified = true;
    request.guard.requiredGuardVerified = true;
    request.guard.beforeUs = kThreeTuUs;
    request.guard.afterUs = kThreeTuUs;

    request.txBudget.verified = true;
    request.txBudget.commitToAirWorstCaseUs = 500;
    request.txBudget.packetAirtimeUs = 1000;
    return request;
}

static void testConservativeIntersectionAndBoundary()
{
    Request request = validRequest();
    Candidate candidate = {0, 0};
    assert(plan(&request, &candidate) == Status::CandidateReady);
    assert(candidate.earliestCommitUs == 1103272);
    assert(candidate.latestCommitUs == 1295228);

    // An exact single-microsecond candidate is retained as an inclusive
    // commit interval. Packet airtime plus trailing guard ends at the half-open
    // peer-window end; the local lease continues beyond that peer boundary.
    request.peerWindow.mappedStartUs = {2000000, 2000000};
    request.peerWindow.mappedEndUs = {2000000 + 2 * kThreeTuUs + 1500,
                                      2000000 + 2 * kThreeTuUs + 1500};
    request.peerWindow.verifiedErrorBoundUs = 0;
    request.localLease.startUs = {1900000, 1900000};
    request.localLease.endUs = {2100000, 2100000};
    request.peer.mifObservedAtUs = 1000000;
    request.peer.mifValidUntilUs = 2100000;
    request.peer.scheduleObservedAtUs = 1000000;
    request.peer.scheduleValidUntilUs = 2100000;
    request.peerWindow.mappingObservedAtUs = 1000000;
    request.peerWindow.mappingValidUntilUs = 2100000;
    request.nowUs = 1900000;
    assert(plan(&request, &candidate) == Status::CandidateReady);
    assert(candidate.earliestCommitUs == 2000000 + kThreeTuUs);
    assert(candidate.latestCommitUs == candidate.earliestCommitUs);
    assert(candidate.latestCommitUs +
               request.txBudget.commitToAirWorstCaseUs +
               request.txBudget.packetAirtimeUs + request.guard.afterUs ==
           request.peerWindow.mappedEndUs.earliestUs);
    assert(request.peerWindow.mappedEndUs.earliestUs <
           request.localLease.endUs.earliestUs);
}

static void testNowInsideGuardedWindowKeepsShortCommitRange()
{
    Request request = validRequest();
    request.nowUs = 1103500;
    request.peerWindow.mappedEndUs = {1108600, 1108600};
    request.peerWindow.verifiedErrorBoundUs = 100;
    request.localLease.endUs = {1120000, 1120100};

    Candidate candidate{};
    assert(plan(&request, &candidate) == Status::CandidateReady);
    assert(candidate.earliestCommitUs == 1103500);
    assert(candidate.latestCommitUs == 1103928);
}

static void testUncertaintyShrinksWindowMonotonically()
{
    Request request = validRequest();
    Candidate baseline{};
    assert(plan(&request, &baseline) == Status::CandidateReady);

    request.peerWindow.verifiedErrorBoundUs = 200;
    Candidate widerError{};
    assert(plan(&request, &widerError) == Status::CandidateReady);
    assert(widerError.earliestCommitUs == baseline.earliestCommitUs + 100);
    assert(widerError.latestCommitUs == baseline.latestCommitUs - 100);

    request.peerWindow.verifiedErrorBoundUs = 150000;
    Candidate untouched = {77, 88};
    assert(plan(&request, &untouched) == Status::UncertaintyCoversWindow);
    assert(untouched.earliestCommitUs == 77 &&
           untouched.latestCommitUs == 88);
}

static void testEpochAndChannelRefusals()
{
    Request request = validRequest();
    Candidate output = {7, 8};
    request.peer.epoch.stationGeneration++;
    assert(plan(&request, &output) == Status::EpochMismatch);
    assert(output.earliestCommitUs == 7 && output.latestCommitUs == 8);

    request = validRequest();
    request.localLease.epoch.rocGeneration++;
    assert(plan(&request, &output) == Status::EpochMismatch);

    request = validRequest();
    request.peerWindow.channel = 149;
    assert(plan(&request, &output) == Status::ChannelMismatch);
}

static void testPeerIncarnationTokenRefusals()
{
    Request request = validRequest();
    Candidate output = {17, 18};

    request.peerWindow.peerToken = 0;
    assert(plan(&request, &output) == Status::InvalidPeerToken);
    assert(output.earliestCommitUs == 17 && output.latestCommitUs == 18);

    request = validRequest();
    request.peerWindow.peerToken++;
    assert(plan(&request, &output) == Status::PeerMismatch);
    assert(output.earliestCommitUs == 17 && output.latestCommitUs == 18);
}

static void testScheduleRevisionBindingRefusals()
{
    Request request = validRequest();
    Candidate output = {27, 28};

    // Same peer, epoch, and channel do not permit using a mapping derived from
    // an older schedule snapshot.
    request.peer.scheduleRevision = 8;
    assert(request.peer.peerToken == request.peerWindow.peerToken);
    assert(request.peer.epoch.contextGeneration ==
           request.peerWindow.epoch.contextGeneration);
    assert(request.peer.channel == request.peerWindow.channel);
    assert(plan(&request, &output) == Status::ScheduleRevisionMismatch);
    assert(output.earliestCommitUs == 27 && output.latestCommitUs == 28);

    request = validRequest();
    request.peer.scheduleRevision = 0;
    assert(plan(&request, &output) == Status::InvalidScheduleRevision);

    request = validRequest();
    request.peerWindow.scheduleRevision = 0;
    assert(plan(&request, &output) == Status::InvalidScheduleRevision);
    assert(output.earliestCommitUs == 27 && output.latestCommitUs == 28);
}

static void testExpirationAndInactiveLease()
{
    Request request = validRequest();
    Candidate output = {9, 10};
    request.nowUs = request.peer.scheduleValidUntilUs;
    assert(plan(&request, &output) == Status::ExpiredPeerWitness);
    assert(output.earliestCommitUs == 9 && output.latestCommitUs == 10);

    request = validRequest();
    request.nowUs = request.peerWindow.mappingValidUntilUs;
    assert(plan(&request, &output) == Status::ExpiredClockMapping);

    request = validRequest();
    request.nowUs = request.localLease.endUs.earliestUs;
    assert(plan(&request, &output) == Status::InactiveLocalLease);

    request = validRequest();
    request.nowUs = 1400000;
    assert(plan(&request, &output) == Status::EmptyIntersection);
}

static void testWitnessAndPolicyRefusals()
{
    Request request = validRequest();
    Candidate output = {19, 20};
    request.peer.mifPeerValid = false;
    assert(plan(&request, &output) == Status::MissingMifPeerWitness);

    request = validRequest();
    request.peer.identityWitnessVerified = false;
    assert(plan(&request, &output) == Status::MissingIdentityWitness);

    request = validRequest();
    request.peer.identityMatchesCurrentPeer = false;
    assert(plan(&request, &output) == Status::IdentityMismatch);

    request = validRequest();
    request.peer.scheduleWitnessVerified = false;
    assert(plan(&request, &output) == Status::MissingScheduleWitness);

    request = validRequest();
    request.peerWindow.mappingVerified = false;
    assert(plan(&request, &output) == Status::UnverifiedClockMapping);

    request = validRequest();
    request.localLease.known = false;
    assert(plan(&request, &output) == Status::UnknownLocalLease);

    request = validRequest();
    request.localLease.active = false;
    assert(plan(&request, &output) == Status::InactiveLocalLease);

    request = validRequest();
    request.guard.trafficSchedulePolicyVerified = false;
    assert(plan(&request, &output) == Status::MissingGuardPolicy);

    request = validRequest();
    request.guard.beforeUs = kThreeTuUs - 1;
    assert(plan(&request, &output) == Status::GuardBelowMinimum);

    request = validRequest();
    request.txBudget.verified = false;
    assert(plan(&request, &output) == Status::MissingTxBudget);
}

static void testStricterGuardAndNoCommitWindow()
{
    Request request = validRequest();
    Candidate base{};
    assert(plan(&request, &base) == Status::CandidateReady);

    request.guard.beforeUs = 16 * kTuUs;
    request.guard.afterUs = 16 * kTuUs;
    Candidate stricter{};
    assert(plan(&request, &stricter) == Status::CandidateReady);
    assert(stricter.earliestCommitUs == base.earliestCommitUs +
                                         (16 * kTuUs - kThreeTuUs));
    assert(stricter.latestCommitUs == base.latestCommitUs -
                                        (16 * kTuUs - kThreeTuUs));

    request.guard.beforeUs = 500000;
    request.guard.afterUs = 500000;
    Candidate output = {21, 22};
    assert(plan(&request, &output) == Status::NoCommitWindow);
    assert(output.earliestCommitUs == 21 && output.latestCommitUs == 22);
}

static void testOverflowAndInvalidIntervals()
{
    Request request = validRequest();
    Candidate output = {31, 32};
    request.peerWindow.mappedStartUs = {UINT64_MAX - 5, UINT64_MAX - 5};
    request.peerWindow.verifiedErrorBoundUs = 6;
    assert(plan(&request, &output) == Status::ArithmeticOverflow);

    request = validRequest();
    request.txBudget.commitToAirWorstCaseUs = UINT64_MAX - 500;
    assert(plan(&request, &output) == Status::ArithmeticOverflow);

    request = validRequest();
    request.localLease.endUs.earliestUs =
        request.localLease.startUs.latestUs;
    assert(plan(&request, &output) == Status::InvalidInterval);

    request = validRequest();
    request.peerWindow.mappedStartUs = {1300000, 1300000};
    request.peerWindow.mappedEndUs = {1200000, 1200000};
    assert(plan(&request, &output) == Status::UncertaintyCoversWindow);
}

static void testCurrentTest062EvidenceFailsClosed()
{
    // Test062 has late-RX paired tuples, but no admitted MIF peer and no
    // verified peer-to-local clock map. Keep these missing witnesses explicit.
    Request request = validRequest();
    request.peer.mifPeerValid = false;
    Candidate output = {41, 42};
    assert(plan(&request, &output) == Status::MissingMifPeerWitness);

    request = validRequest();
    request.peerWindow.mappingVerified = false;
    assert(plan(&request, &output) == Status::UnverifiedClockMapping);
    assert(output.earliestCommitUs == 41 && output.latestCommitUs == 42);
}

int main()
{
    testConservativeIntersectionAndBoundary();
    testNowInsideGuardedWindowKeepsShortCommitRange();
    testUncertaintyShrinksWindowMonotonically();
    testEpochAndChannelRefusals();
    testPeerIncarnationTokenRefusals();
    testScheduleRevisionBindingRefusals();
    testExpirationAndInactiveLease();
    testWitnessAndPolicyRefusals();
    testStricterGuardAndNoCommitWindow();
    testOverflowAndInvalidIntervals();
    testCurrentTest062EvidenceFailsClosed();
    puts("PASS: conservative AWDL shared-window interval planner");
    return 0;
}
