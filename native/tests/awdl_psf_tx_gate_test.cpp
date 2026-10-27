// SPDX-License-Identifier: GPL-2.0-only
#include "../awdl_action_frame.hpp"
#include "../awdl_action_encode.hpp"
#include "../p2p_action_tx.hpp"
#include "../awdl_psf_tx_gate.hpp"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

using namespace NativeAwdlProbe;

static Request request(uint64_t sampleUs, uint16_t sequence)
{
    Request value{};
    const uint8_t mac[6] = {0x02, 0x5a, 0x71, 0x23, 0x45, 0x67};
    memcpy(value.p2pMac.bytes, mac, sizeof(mac));
    value.monotonicSampleUs = sampleUs;
    value.ieee80211SequenceNumber = sequence;
    value.ht.capabilityInfo = 0x1234;
    value.ht.ampduParameters = 0x87;
    value.ht.rxMcsMask[0] = 0xff;
    value.ht.rxMcsMask[1] = 0xff;
    value.ht.rxMcsLength = 4;
    value.ht.confirmed = true;
    return value;
}

static PsfRuntimeWitness witness(uint64_t startUs, uint64_t sampleUs,
                                 uint64_t deadlineUs)
{
    PsfRuntimeWitness value{};
    value.expectedGeneration = 8;
    value.sessionGeneration = 8;
    value.startObservedUs = startUs;
    value.hardDeadlineUs = deadlineUs;
    value.sampleUs = sampleUs;
    value.matchingSuccessfulStart = true;
    value.activeAtSample = true;
    return value;
}

static void testEncodedCandidateStillFailsClosedFor900ms()
{
    const uint64_t startUs = 100000;
    const uint64_t sampleUs = startUs + 1000;
    auto input = request(sampleUs, 0x123);
    auto live = witness(startUs, sampleUs, startUs + 900000 -
                        kPsfLeaseSafetyMarginUs);
    PsfCandidate candidate{};
    assert(prepareExperimentalPsfCandidate(&input, &live, &candidate) ==
           PsfCandidateStatus::Encoded);

    NativeAwdl::ActionFrameInfo parsed{};
    NativeAwdl::ParseDiagnostics parseDiagnostics{};
    assert(NativeAwdl::parseActionFrame(candidate.bytes, candidate.length,
        &parsed, &parseDiagnostics) == NativeAwdl::ParseStatus::Ok);
    assert(parsed.subtype == 0 && parsed.version == 0x10);
    IntelP2PActionFrame::FrameInfo txInfo{};
    assert(IntelP2PActionFrame::inspectActionFrame(
        candidate.bytes, candidate.length, input.p2pMac.bytes, &txInfo));
    assert(txInfo.category == IntelP2PActionFrame::kVendorSpecificCategory);
    assert(candidate.bytes[25] == 0x00 && candidate.bytes[26] == 0x17 &&
           candidate.bytes[27] == 0xf2);
    assert(parseDiagnostics.dataPathFlagsPresent == 1);
    assert(parseDiagnostics.dataPathFlags == 0);
    assert(parsed.phyTx == static_cast<uint32_t>(sampleUs));
    assert(parsed.targetTx == static_cast<uint32_t>(sampleUs));
    assert(candidate.bytes[10] == input.p2pMac.bytes[0]);
    assert(memcmp(candidate.bytes + 10, input.p2pMac.bytes, 6) == 0);
    assert((uint16_t(candidate.bytes[22]) |
            uint16_t(candidate.bytes[23]) << 8) ==
           static_cast<uint16_t>(input.ieee80211SequenceNumber << 4));

    const uint32_t blockers = p2pPsfTxBlockers(&candidate, &live, sampleUs);
    assert(blockers & kPsfTxSequenceOutlivesLease);
    assert(blockers & kPsfTxCyclicExpiryUnbounded);
    assert(blockers & kPsfTxClockMappingUnavailable);
    assert(!(blockers & kPsfTxPreparedFrameStale));
    assert(blockers != kPsfTxNoBlocker);

    // The explicit observation-only mode can probe a single control PSF only
    // if the contiguous channel-6 dwell fits before the conservative deadline.
    const uint64_t timelySubmit = sampleUs + 1000;
    const uint32_t observationBlockers = p2pPsfObservationTxBlockers(
        &candidate, &live, timelySubmit);
    assert(observationBlockers == kPsfTxNoBlocker);
    assert(p2pPsfTxBlockers(&candidate, &live, timelySubmit) !=
           kPsfTxNoBlocker); // strict production gate remains closed
    assert(p2pPsfObservationTxBlockers(&candidate, &live,
        sampleUs + 30000) & kPsfTxAdvertisedResidenceOutlivesLease);
}

static void testSyntheticCompleteLeaseCanPassOnlyWithAllWitnesses()
{
    const uint64_t startUs = 1000000;
    const uint64_t sampleUs = startUs + 10;
    const uint64_t deadlineUs = sampleUs + 1024ULL * 1024ULL;
    auto input = request(sampleUs, 7);
    auto live = witness(startUs, sampleUs, deadlineUs);
    live.clockMappingConfirmed = true;
    live.cyclicExpiryRepresentable = true;

    PsfCandidate candidate{};
    assert(prepareExperimentalPsfCandidate(&input, &live, &candidate) ==
           PsfCandidateStatus::Encoded);
    assert(candidate.blockers == kPsfTxNoBlocker);
    assert(p2pPsfTxBlockers(&candidate, &live, sampleUs + 100) ==
           kPsfTxNoBlocker);

    // This is planner/guard coverage only; a synthetic true clock/expiry
    // witness is not available from the live 900 ms HAL profile.
}

static void testLateStartAndInvalidWitnessLeaveOutputUntouched()
{
    auto input = request(900001, 1);
    auto late = witness(1000, input.monotonicSampleUs, 900000);
    PsfCandidate candidate;
    memset(&candidate, 0xa5, sizeof(candidate));
    PsfCandidate unchanged = candidate;
    assert(prepareExperimentalPsfCandidate(&input, &late, &candidate) ==
           PsfCandidateStatus::InvalidRocWitness);
    assert(memcmp(&candidate, &unchanged, sizeof(candidate)) == 0);

    late = witness(1000, 2000, 1000000);
    late.matchingSuccessfulStart = false;
    input = request(2000, 1);
    assert(prepareExperimentalPsfCandidate(&input, &late, &candidate) ==
           PsfCandidateStatus::InvalidRocWitness);
    assert(memcmp(&candidate, &unchanged, sizeof(candidate)) == 0);
}

static void testSubmitRejectsStaleEndedAndChangedEpoch()
{
    const uint64_t startUs = 100000;
    const uint64_t sampleUs = startUs + 1000;
    auto input = request(sampleUs, 9);
    auto live = witness(startUs, sampleUs, startUs + 900000);
    PsfCandidate candidate{};
    assert(prepareExperimentalPsfCandidate(&input, &live, &candidate) ==
           PsfCandidateStatus::Encoded);

    assert(p2pPsfTxBlockers(&candidate, &live,
             sampleUs + kMaximumPreparedPsfAgeUs + 1) &
           kPsfTxPreparedFrameStale);
    live.endSeen = true;
    assert(p2pPsfTxBlockers(&candidate, &live, sampleUs + 1) &
           kPsfTxRocEnded);
    live.endSeen = false;
    live.sessionGeneration++;
    assert(p2pPsfTxBlockers(&candidate, &live, sampleUs + 1) &
           kPsfTxGenerationMismatch);
}

static void testSerializationFailureFromInvalidHtIsFailClosed()
{
    const uint64_t startUs = 1000;
    const uint64_t sampleUs = 2000;
    auto input = request(sampleUs, 3);
    input.ht.confirmed = false;
    auto live = witness(startUs, sampleUs,
                        sampleUs + 1024ULL * 1024ULL);
    PsfCandidate candidate;
    memset(&candidate, 0x6d, sizeof(candidate));
    PsfCandidate unchanged = candidate;
    assert(prepareExperimentalPsfCandidate(&input, &live, &candidate) ==
           PsfCandidateStatus::PlannerRejected);
    assert(memcmp(&candidate, &unchanged, sizeof(candidate)) == 0);
}

int main()
{
    testEncodedCandidateStillFailsClosedFor900ms();
    testSyntheticCompleteLeaseCanPassOnlyWithAllWitnesses();
    testLateStartAndInvalidWitnessLeaveOutputUntouched();
    testSubmitRejectsStaleEndedAndChangedEpoch();
    testSerializationFailureFromInvalidHtIsFailClosed();
    puts("PASS: PSF candidate encoding, 900 ms blockers, and submit gate");
}
