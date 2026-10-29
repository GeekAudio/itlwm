// SPDX-License-Identifier: GPL-2.0-only
#include "../awdl_discovery_phase_experiment.hpp"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

using NativeAwdlDiscoveryPhase::EstimatedTarget;
using NativeAwdlDiscoveryPhase::Input;
using NativeAwdlDiscoveryPhase::Status;

static Input test063Input()
{
    Input input{};
    input.psf.peerToken = 0xabc001;
    input.psf.scheduleRevision = 17;
    input.psf.epochs = {11, 12, 13, 14};
    input.psf.rxHostUs = 741024377ULL;
    input.psf.rxGp2 = 676227262U;
    input.psf.phyTxTimestampUs = 1328926346U;
    input.psf.targetTxTimestampUs = 1328926240U;
    input.psf.awCounter = 20190;
    input.psf.txDownTu = 21;
    input.psf.awPeriodTu = 16;
    input.psf.presenceMode = 4;
    input.psf.rxChannel = 6;
    input.psf.complete = true;
    const uint8_t test063Channels[16] = {
        36, 36, 149, 0, 0, 0, 0, 36, 6, 36, 149, 36, 0, 0, 0, 36
    };
    memcpy(input.psf.canonicalChannels, test063Channels,
           sizeof(test063Channels));

    input.current.snapshot = input.psf;
    input.current.peerStillCurrent = true;

    input.preRocAnchor.hostBeforeUs = 740711353ULL;
    input.preRocAnchor.hostAfterUs = 740711356ULL;
    input.preRocAnchor.rawGp2 = 675917609U;
    input.preRocAnchor.epochs = input.psf.epochs;
    input.preRocAnchor.directReadBracket = true;
    input.preRocAnchor.occurredBeforeRoc = true;
    input.preRocAnchor.firmwareResourcesAbsent = true;

    input.nowUs = 741030000ULL;
    input.leaseStartUs = 741040000ULL;
    input.leaseEndUs = 741100000ULL;
    input.localRocChannel = 6;
    return input;
}

static EstimatedTarget estimate(const Input &input)
{
    EstimatedTarget output{};
    const Status status =
        NativeAwdlDiscoveryPhase::estimateTarget(input, output);
    if (status != Status::kEstimatedCandidate)
        fprintf(stderr, "discovery phase candidate status=%u\n",
                static_cast<unsigned>(status));
    assert(status == Status::kEstimatedCandidate);
    return output;
}

static void refreshCurrentSnapshot(Input &input)
{
    input.current.snapshot = input.psf;
}

static void expectFailureUnchanged(const Input &input, Status expected)
{
    EstimatedTarget output;
    memset(&output, 0xa5, sizeof(output));
    EstimatedTarget before;
    memcpy(&before, &output, sizeof(before));
    const Status actual =
        NativeAwdlDiscoveryPhase::estimateTarget(input, output);
    if (actual != expected) {
        fprintf(stderr, "discovery phase status expected=%u actual=%u\n",
                static_cast<unsigned>(expected),
                static_cast<unsigned>(actual));
    }
    assert(actual == expected);
    assert(memcmp(&output, &before, sizeof(output)) == 0);
}

static void testTest063CandidateAndProofBoundary()
{
    Input input = test063Input();
    const EstimatedTarget output = estimate(input);
    assert(output.status == Status::kEstimatedCandidate);
    assert(output.earliestSubmitUs == 741046503ULL);
    assert(output.latestSubmitUs == 741054692ULL);
    assert(output.targetGp2Raw == 676256852U);
    assert(output.peerToken == input.psf.peerToken);
    assert(output.scheduleRevision == input.psf.scheduleRevision);
    assert(output.epochs.context == input.psf.epochs.context);
    assert(output.epochs.power == input.psf.epochs.power);
    assert(output.epochs.station == input.psf.epochs.station);
    assert(output.epochs.roc == input.psf.epochs.roc);
    assert(!output.clockMappingVerified);
    assert(!output.airtimeVerified);
    assert(output.experimentalOnly);

    // A future candidate and a candidate whose interval is currently open
    // return the same bounded interval; expiry rejects without editing output.
    input.nowUs = input.psf.rxHostUs + 1;
    const EstimatedTarget future = estimate(input);
    assert(future.earliestSubmitUs == output.earliestSubmitUs);
    input.nowUs = output.earliestSubmitUs + 1;
    const EstimatedTarget waitingWindow = estimate(input);
    assert(waitingWindow.latestSubmitUs == output.latestSubmitUs);
    input.nowUs = output.latestSubmitUs;
    expectFailureUnchanged(input, Status::kCandidateAlreadyExpired);
}

static void testAwCounterWrapAndNoNextHintDependency()
{
    Input input = test063Input();
    input.psf.awCounter = 65535;
    input.psf.canonicalChannels[0] = 6;
    refreshCurrentSnapshot(input);
    // The helper has no `nextAwChannel` hint in its input. Only the computed
    // next canonical slot controls eligibility.
    const EstimatedTarget output = estimate(input);
    assert(output.status == Status::kEstimatedCandidate);
}

static void testGp2WrapAndHalfRange()
{
    Input input = test063Input();
    input.preRocAnchor.rawGp2 = 0xfffffff0U;
    input.psf.rxGp2 = input.preRocAnchor.rawGp2 + 309653U;
    refreshCurrentSnapshot(input);
    assert(estimate(input).status == Status::kEstimatedCandidate);

    input.psf.rxGp2 = input.preRocAnchor.rawGp2 + 0x80000000U;
    refreshCurrentSnapshot(input);
    expectFailureUnchanged(input, Status::kGp2HalfRangeAmbiguous);

    input = test063Input();
    input.preRocAnchor.rawGp2 = 0xffff0000U;
    input.psf.rxGp2 = 0xfffffff0U;
    input.psf.rxHostUs = input.preRocAnchor.hostAfterUs + 90000ULL;
    input.nowUs = input.psf.rxHostUs + 100ULL;
    input.leaseStartUs = 740700000ULL;
    input.leaseEndUs = 740900000ULL;
    refreshCurrentSnapshot(input);
    const EstimatedTarget wrappedTarget = estimate(input);
    assert(wrappedTarget.targetGp2Raw ==
           static_cast<uint32_t>(0xfffffff0U + 21398U + 8192U));
}

static void testPhyTargetCorrectionAndUnderflow()
{
    Input input = test063Input();
    input.psf.phyTxTimestampUs = input.psf.targetTxTimestampUs + 2672U;
    refreshCurrentSnapshot(input);
    const EstimatedTarget corrected = estimate(input);
    assert(corrected.earliestSubmitUs == 741043937ULL);
    assert(corrected.latestSubmitUs == 741052126ULL);
    assert(corrected.targetGp2Raw == 676254286U);

    input.psf.phyTxTimestampUs = input.psf.targetTxTimestampUs + 21505U;
    refreshCurrentSnapshot(input);
    expectFailureUnchanged(input, Status::kInvalidPsfTiming);

    input = test063Input();
    input.psf.txDownTu = 64;
    input.psf.phyTxTimestampUs = input.psf.targetTxTimestampUs + 65535U;
    input.nowUs = input.psf.rxHostUs + 1;
    input.leaseStartUs = 741000000ULL;
    refreshCurrentSnapshot(input);
    const EstimatedTarget widest = estimate(input);
    assert(widest.earliestSubmitUs == 741025106ULL);
    assert(widest.latestSubmitUs == 741033295ULL);
    assert(widest.targetGp2Raw == 676235455U);
}

static void testPsfIdentityFreshnessAndEpochs()
{
    Input input = test063Input();
    input.psf.complete = false;
    expectFailureUnchanged(input, Status::kIncompletePsf);

    input = test063Input();
    input.nowUs = input.psf.rxHostUs +
        NativeAwdlDiscoveryPhase::kMaximumPsfAgeUs + 1;
    expectFailureUnchanged(input, Status::kStalePsf);

    input = test063Input();
    input.current.snapshot.peerToken++;
    expectFailureUnchanged(input, Status::kPeerIncarnationMismatch);

    input = test063Input();
    input.current.snapshot.scheduleRevision++;
    expectFailureUnchanged(input, Status::kScheduleRevisionMismatch);

    input = test063Input();
    input.current.snapshot.epochs.power++;
    expectFailureUnchanged(input, Status::kEpochMismatch);

    input = test063Input();
    input.current.snapshot.canonicalChannels[8] = 11;
    expectFailureUnchanged(input, Status::kCurrentSnapshotMismatch);

    input = test063Input();
    input.preRocAnchor.epochs.roc++;
    expectFailureUnchanged(input, Status::kEpochMismatch);
}

static void testEveryEpochMustBeNonzero()
{
    Input input = test063Input();

    input.psf.epochs.context = 0;
    input.current.snapshot.epochs.context = 0;
    input.preRocAnchor.epochs.context = 0;
    expectFailureUnchanged(input, Status::kZeroEpoch);

    input = test063Input();
    input.psf.epochs.power = 0;
    input.current.snapshot.epochs.power = 0;
    input.preRocAnchor.epochs.power = 0;
    expectFailureUnchanged(input, Status::kZeroEpoch);

    input = test063Input();
    input.psf.epochs.station = 0;
    input.current.snapshot.epochs.station = 0;
    input.preRocAnchor.epochs.station = 0;
    expectFailureUnchanged(input, Status::kZeroEpoch);

    input = test063Input();
    input.psf.epochs.roc = 0;
    input.current.snapshot.epochs.roc = 0;
    input.preRocAnchor.epochs.roc = 0;
    expectFailureUnchanged(input, Status::kZeroEpoch);
}

static void testPreRocAnchorRequirements()
{
    Input input = test063Input();
    input.preRocAnchor.directReadBracket = false;
    expectFailureUnchanged(input, Status::kInvalidPreRocAnchor);

    input = test063Input();
    input.preRocAnchor.occurredBeforeRoc = false;
    expectFailureUnchanged(input, Status::kInvalidPreRocAnchor);

    input = test063Input();
    input.preRocAnchor.firmwareResourcesAbsent = false;
    expectFailureUnchanged(input, Status::kResourcesPresentAtAnchor);

    input = test063Input();
    input.preRocAnchor.hostAfterUs = input.preRocAnchor.hostBeforeUs - 1;
    expectFailureUnchanged(input, Status::kInvalidAnchorBracket);

    input = test063Input();
    input.preRocAnchor.hostAfterUs =
        input.preRocAnchor.hostBeforeUs +
        NativeAwdlDiscoveryPhase::kMaximumAnchorBracketUs + 1;
    expectFailureUnchanged(input, Status::kAnchorBracketTooWide);

    input = test063Input();
    input.preRocAnchor.hostBeforeUs = input.psf.rxHostUs - 1;
    input.preRocAnchor.hostAfterUs = input.psf.rxHostUs + 1;
    expectFailureUnchanged(input, Status::kAnchorAfterPsf);

    input = test063Input();
    input.psf.rxGp2 = input.preRocAnchor.rawGp2 - 1U;
    refreshCurrentSnapshot(input);
    expectFailureUnchanged(input, Status::kGp2HalfRangeAmbiguous);

    input = test063Input();
    input.psf.rxGp2 = input.preRocAnchor.rawGp2 +
        NativeAwdlDiscoveryPhase::kMaximumAnchorToRxUs;
    refreshCurrentSnapshot(input);
    expectFailureUnchanged(input, Status::kAnchorToRxTooOld);
}

static void testScheduleAndPsfTimingRejections()
{
    Input input = test063Input();
    input.psf.canonicalChannels[8] = 11;
    refreshCurrentSnapshot(input);
    expectFailureUnchanged(input, Status::kNoLocalChannel6NextSlot);

    input = test063Input();
    input.psf.canonicalChannels[3] = 0;
    refreshCurrentSnapshot(input);
    assert(estimate(input).status == Status::kEstimatedCandidate);

    input = test063Input();
    input.psf.canonicalChannels[3] = 255;
    refreshCurrentSnapshot(input);
    expectFailureUnchanged(input, Status::kInvalidSchedule);

    input = test063Input();
    input.psf.rxChannel = 11;
    refreshCurrentSnapshot(input);
    expectFailureUnchanged(input, Status::kInvalidPsfTiming);

    input = test063Input();
    input.localRocChannel = 11;
    expectFailureUnchanged(input, Status::kInvalidArgument);

    input = test063Input();
    input.psf.presenceMode = 3;
    refreshCurrentSnapshot(input);
    expectFailureUnchanged(input, Status::kInvalidPsfTiming);

    input = test063Input();
    input.psf.awPeriodTu = 15;
    refreshCurrentSnapshot(input);
    expectFailureUnchanged(input, Status::kInvalidPsfTiming);

    input = test063Input();
    input.psf.txDownTu = 0;
    refreshCurrentSnapshot(input);
    expectFailureUnchanged(input, Status::kInvalidPsfTiming);

    input = test063Input();
    input.psf.txDownTu = 65;
    refreshCurrentSnapshot(input);
    expectFailureUnchanged(input, Status::kInvalidPsfTiming);

    input = test063Input();
    input.psf.phyTxTimestampUs = input.psf.targetTxTimestampUs - 1U;
    refreshCurrentSnapshot(input);
    expectFailureUnchanged(input, Status::kInvalidPsfTiming);

    input = test063Input();
    input.psf.phyTxTimestampUs = input.psf.targetTxTimestampUs + 65536U;
    refreshCurrentSnapshot(input);
    expectFailureUnchanged(input, Status::kInvalidPsfTiming);

    input = test063Input();
    input.psf.phyTxTimestampUs = input.psf.targetTxTimestampUs + 2048U;
    input.psf.txDownTu = 1;
    refreshCurrentSnapshot(input);
    expectFailureUnchanged(input, Status::kInvalidPsfTiming);
}

static void testLeaseReserveAndWindowBounds()
{
    Input input = test063Input();
    const EstimatedTarget candidate = estimate(input);

    input.leaseEndUs = candidate.latestSubmitUs +
        NativeAwdlDiscoveryPhase::kLeaseReserveUs;
    assert(estimate(input).latestSubmitUs == candidate.latestSubmitUs);

    input.leaseEndUs--;
    expectFailureUnchanged(input, Status::kCandidateNotInLease);

    input = test063Input();
    input.leaseStartUs = candidate.earliestSubmitUs + 1;
    expectFailureUnchanged(input, Status::kCandidateNotInLease);

    input = test063Input();
    input.leaseStartUs = 0;
    input.leaseEndUs = NativeAwdlDiscoveryPhase::kLeaseReserveUs;
    expectFailureUnchanged(input, Status::kLeaseTooShort);

    input = test063Input();
    input.leaseStartUs = candidate.latestSubmitUs;
    input.leaseEndUs = candidate.latestSubmitUs + 50000;
    expectFailureUnchanged(input, Status::kCandidateNotInLease);
}

static void testArithmeticOverflowAndInvalidCurrentState()
{
    Input input = test063Input();
    input.preRocAnchor.hostBeforeUs = UINT64_MAX - 200000ULL;
    input.preRocAnchor.hostAfterUs = input.preRocAnchor.hostBeforeUs + 3;
    input.psf.rxHostUs = input.preRocAnchor.hostAfterUs + 100000;
    input.nowUs = input.psf.rxHostUs + 100;
    input.psf.rxGp2 = input.preRocAnchor.rawGp2 + 180000U;
    refreshCurrentSnapshot(input);
    input.leaseStartUs = UINT64_MAX - 100000ULL;
    input.leaseEndUs = UINT64_MAX;
    expectFailureUnchanged(input, Status::kArithmeticOverflow);

    input = test063Input();
    input.current.peerStillCurrent = false;
    expectFailureUnchanged(input, Status::kInvalidArgument);

    input = test063Input();
    input.nowUs = 0;
    expectFailureUnchanged(input, Status::kInvalidArgument);
}

int main()
{
    testTest063CandidateAndProofBoundary();
    testAwCounterWrapAndNoNextHintDependency();
    testGp2WrapAndHalfRange();
    testPhyTargetCorrectionAndUnderflow();
    testPsfIdentityFreshnessAndEpochs();
    testEveryEpochMustBeNonzero();
    testPreRocAnchorRequirements();
    testScheduleAndPsfTimingRejections();
    testLeaseReserveAndWindowBounds();
    testArithmeticOverflowAndInvalidCurrentState();
    puts("PASS: isolated experimental AWDL discovery-phase candidate planner");
    return 0;
}
