// SPDX-License-Identifier: GPL-2.0-only
#include "awdl_action_frame.hpp"
#include "awdl_bounded_psf_plan.hpp"
#include "awdl_mif_burst.hpp"
#include "awdl_mif_tx_gate.hpp"

#include <assert.h>
#include <stdint.h>
#include <string.h>

static constexpr uint32_t IWX_SESSION_PROTECT_CONF_P2P_GO_NEGOTIATION = 3;
enum class TahoeP2PActionTxState : uint32_t { kIdle, kInFlight };
struct iwx_softc {
    uint32_t sc_generation = 88;
    uint32_t sc_tx_rate_generation = 99;
};
struct ItlIwx {
    iwx_softc com{};
    uint32_t nativeP2pProbeGeneration_ = 77;
};
namespace IntelROCEvent {
struct SessionSnapshot {
    uint32_t generation = 77;
    uint32_t configuration = IWX_SESSION_PROTECT_CONF_P2P_GO_NEGOTIATION;
    int commandResult = 0;
    uint32_t startStatus = 1;
    bool commandReturned = true;
    bool startSeen = true;
    bool endSeen = false;
    bool outcomeUnknown = false;
    uint64_t startObservedMonotonicUs = 990000;
};
}
struct P2PTxDiagnosticSnapshot {
    uint32_t actionState = 0;
    uint32_t outstandingTx = 0;
    uint32_t ticketStatus = 1;
    uint32_t ticketSequenceControl = 0;
    uint32_t ticketByteCount = 0;
    uint32_t ticketFrameControl = 0x00d0;
    uint16_t nextSequenceNumber = 0;
    bool ticketArmed = true;
    bool ticketCompleted = true;
    bool frameAttemptSucceeded = true;
    bool queueLeaseActive = true;
    bool txRingEmpty = true;
    bool ringIndicesConsistent = true;
};
struct P2PProbeRun {
    ItlIwx *owner = nullptr;
    uint32_t nativeDataAttempts = 0;
    uint32_t contextGeneration = 77;
    uint32_t powerGeneration = 88;
    uint32_t stationGeneration = 99;
    uint32_t mifBurstPreparedFrames = 1;
    uint32_t mifBurstSubmittedFrames = 1;
    uint32_t mifBurstCompletedFrames = 1;
    uint32_t mifBurstSucceededFrames = 1;
    uint32_t mifBurstEpoch = 77;
    uint32_t mifBurstLastTicketStatus = 1;
    uint32_t mifBurstLastTicketSequenceControl = 0;
    uint32_t mifBurstLastTicketByteCount = 0;
    uint32_t mifBurstLastTicketFrameControl = 0x00d0;
    uint16_t mifBurstLastNextSequenceNumber = 0;
    uint64_t mifBurstLastCompletionUs = 1020000;
    bool mifBurstCandidateIsRepeat = true;
    NativeAwdlProbe::PsfCandidate psfCandidate{};
    NativeAwdlProbe::PsfRuntimeWitness psfWitness{};
    NativeAwdlProbe::MifCandidate mifCandidate{};
};

// PRODUCTION_MIF_BURST_HELPERS

static NativeAwdlProbe::PsfCandidate firstPsfCandidate()
{
    NativeAwdlProbe::Request request{};
    const uint8_t address[] = {0x02, 0x10, 0x20, 0x30, 0x40, 0x50};
    memcpy(request.p2pMac.bytes, address, sizeof(address));
    request.monotonicSampleUs = 1000000;
    request.ieee80211SequenceNumber = 9;
    request.ht.confirmed = true;
    request.ht.capabilityInfo = 0x11ce;
    request.ht.ampduParameters = 0x1b;
    request.ht.rxMcsMask[0] = 0xff;
    request.ht.rxMcsLength = 1;

    NativeAwdlProbe::RocWitness roc{};
    roc.channel = 6;
    roc.startUs = 990000;
    roc.deadlineUs = 1890000;
    roc.startConfirmed = true;
    roc.activeAtSampleConfirmed = true;
    NativeAwdlProbe::PsfCandidate candidate{};
    NativeAwdlProbe::Summary summary{};
    assert(NativeAwdlProbe::buildObservationOnlyPsfInput(
        &request, &roc, &candidate.input, &summary) ==
        NativeAwdlProbe::PlanStatus::ObservationOnly);
    size_t written = 0;
    assert(NativeAwdl::encodePsf(&candidate.input, candidate.bytes,
        sizeof(candidate.bytes), &written) == NativeAwdl::EncodeStatus::Ok);
    candidate.length = written;
    candidate.contextGeneration = 77;
    candidate.startObservedUs = roc.startUs;
    candidate.sampleUs = request.monotonicSampleUs;
    candidate.hardDeadlineUs = roc.deadlineUs;
    return candidate;
}

static NativeAwdlProbe::MifCandidate firstMifCandidate(
    const NativeAwdlProbe::PsfCandidate &psf)
{
    NativeAwdlProbe::MifFollowupWitness witness{};
    witness.roc.expectedGeneration = 77;
    witness.roc.sessionGeneration = 77;
    witness.roc.startObservedUs = psf.startObservedUs;
    witness.roc.hardDeadlineUs = psf.hardDeadlineUs;
    witness.roc.sampleUs = psf.sampleUs + 1024;
    witness.roc.matchingSuccessfulStart = true;
    witness.roc.activeAtSample = true;
    witness.nextSequenceNumber = 10;
    witness.firstPsfTicketStatus = 1;
    witness.firstPsfTicketSequenceControl = 9u << 4;
    witness.firstPsfTicketByteCount = static_cast<uint16_t>(psf.length);
    witness.firstPsfTicketFrameControl = 0x00d0;
    witness.firstPsfTicketCompleted = true;
    witness.firstPsfTicketSucceeded = true;
    witness.queueLeaseActive = true;
    witness.txRingEmpty = true;
    witness.ringIndicesConsistent = true;
    const char hostname[] = "intel-awdl-probe";
    NativeAwdlProbe::MifCandidate candidate{};
    assert(NativeAwdlProbe::prepareExperimentalMifFollowupCandidate(
        &psf, &witness, 1, hostname, sizeof(hostname) - 1, &candidate) ==
        NativeAwdlProbe::MifCandidateStatus::Encoded);
    return candidate;
}

static void installCompletedTicket(P2PProbeRun *probe,
                                   P2PTxDiagnosticSnapshot *tx,
                                   uint16_t sequence, uint16_t byteCount)
{
    tx->ticketArmed = true; // CompletionTracker retains this bit on success.
    tx->ticketCompleted = true;
    tx->actionState = static_cast<uint32_t>(TahoeP2PActionTxState::kIdle);
    tx->ticketStatus = 1;
    tx->ticketSequenceControl = uint32_t(sequence) << 4;
    tx->ticketByteCount = byteCount;
    tx->ticketFrameControl = 0x00d0;
    tx->nextSequenceNumber = static_cast<uint16_t>((sequence + 1u) & 0x0fffu);
    tx->frameAttemptSucceeded = true;
    tx->queueLeaseActive = true;
    tx->outstandingTx = 0;
    tx->txRingEmpty = true;
    tx->ringIndicesConsistent = true;
    probe->mifBurstLastTicketStatus = tx->ticketStatus;
    probe->mifBurstLastTicketSequenceControl = tx->ticketSequenceControl;
    probe->mifBurstLastTicketByteCount = tx->ticketByteCount;
    probe->mifBurstLastTicketFrameControl = tx->ticketFrameControl;
    probe->mifBurstLastNextSequenceNumber = tx->nextSequenceNumber;
}

int main()
{
    ItlIwx owner{};
    auto psf = firstPsfCandidate();
    P2PProbeRun probe{};
    probe.owner = &owner;
    probe.psfCandidate = psf;
    probe.psfWitness.startObservedUs = psf.startObservedUs;
    probe.mifCandidate = firstMifCandidate(psf);
    P2PTxDiagnosticSnapshot tx{};
    installCompletedTicket(&probe, &tx, 10,
        static_cast<uint16_t>(probe.mifCandidate.length));

    // Second MIF: prepared=1/submitted=1 is the pre-build state. A completed
    // armed ticket is reusable only after ActionIdle and ring-idle evidence.
    NativeAwdlProbe::MifCandidate second{};
    const uint64_t secondSampleUs = probe.mifBurstLastCompletionUs +
        NativeAwdlProbe::kMifBurstRepeatIntervalUs;
    assert(buildFreshMifBurstCandidate(&probe,
        IntelROCEvent::SessionSnapshot{}, tx, secondSampleUs, &second, false));
    NativeAwdl::ActionFrameInfo info{};
    assert(NativeAwdl::parseActionFrame(second.bytes, second.length, &info) ==
           NativeAwdl::ParseStatus::Ok);
    assert(info.subtype == 3 && second.input.sequenceNumber == 11);
    assert(second.sampleUs == secondSampleUs &&
           second.input.phyTxTimestampUs == static_cast<uint32_t>(secondSampleUs));
    assert(second.hardDeadlineUs == psf.hardDeadlineUs &&
           second.phaseOriginUs == psf.sampleUs);

    // Third MIF: the candidate is already prepared at the gate. A successful
    // retained ticket (armed=completed=1) passes; the burst cap applies to
    // additional submissions, not to this reserved third candidate.
    probe.mifBurstPreparedFrames = 3;
    probe.mifBurstSubmittedFrames = 2;
    probe.mifBurstCompletedFrames = 2;
    probe.mifBurstSucceededFrames = 2;
    probe.mifBurstLastCompletionUs = secondSampleUs + 1000;
    installCompletedTicket(&probe, &tx, 11,
        static_cast<uint16_t>(second.length));
    NativeAwdlProbe::MifCandidate third{};
    const uint64_t thirdSampleUs = probe.mifBurstLastCompletionUs +
        NativeAwdlProbe::kMifBurstRepeatIntervalUs;
    assert(buildFreshMifBurstCandidate(&probe,
        IntelROCEvent::SessionSnapshot{}, tx, thirdSampleUs, &third, true));
    assert(third.input.sequenceNumber == 12 && third.sampleUs == thirdSampleUs);
    const auto doorbell = mifBurstDoorbellPlan(&probe,
        IntelROCEvent::SessionSnapshot{}, tx, thirdSampleUs);
    assert(doorbell.decision == NativeAwdlProbe::MifBurstDecision::Prepare);

    // An armed but incomplete ticket is not reusable.
    tx.ticketCompleted = false;
    tx.actionState = static_cast<uint32_t>(TahoeP2PActionTxState::kInFlight);
    tx.frameAttemptSucceeded = false;
    assert(!buildFreshMifBurstCandidate(&probe,
        IntelROCEvent::SessionSnapshot{}, tx, thirdSampleUs, &third, true));
}
