// SPDX-License-Identifier: GPL-2.0-only
#ifndef NATIVE_AWDL_MIF_BURST_HPP
#define NATIVE_AWDL_MIF_BURST_HPP

#include <stdint.h>

namespace NativeAwdlProbe {

constexpr uint32_t kMifBurstMaximumFrames = 3;
constexpr uint64_t kMifBurstRepeatIntervalUs = 64ULL * 1024ULL;

enum class MifBurstDecision : uint8_t {
    Wait,
    Prepare,
    Stop
};

enum class MifBurstStopReason : uint8_t {
    None,
    FrameLimit,
    EpochMismatch,
    RocEnded,
    RocUnknown,
    DataStarted,
    FrameNotEmpty,
    RocInactive,
    PreviousTicketFailed,
    PreviousTicketIncomplete,
    QueueNotIdle,
    InvalidTime,
    CandidatePreparationFailed,
    DoorbellRejected,
    FrameSubmissionFailed
};

struct MifBurstRepeatState {
    uint32_t preparedFrames;
    uint32_t submittedFrames;
    uint32_t nativeDataAttempts;
    uint64_t nowUs;
    uint64_t lastCompletionUs;
    bool sameEpoch;
    bool rocActive;
    bool endSeen;
    bool outcomeUnknown;
    bool previousMifSucceeded;
    bool ticketCompleted;
    bool ticketSucceeded;
    bool actionIdle;
    bool queueLeaseActive;
    bool ringEmpty;
    bool ringIndicesConsistent;
    bool frameEmpty;
    bool candidateAlreadyPrepared;
};

struct MifBurstRepeatPlan {
    MifBurstDecision decision;
    MifBurstStopReason reason;
};

// A repeat is eligible only after a successful, fully drained MIF ticket in
// the same live ROC epoch. The 64-TU interval is an experimental local pacing
// bound; it does not claim a shared AWDL slot or guarantee peer reception.
inline MifBurstRepeatPlan planMifBurstRepeat(
    const MifBurstRepeatState &state)
{
    if (state.submittedFrames >= kMifBurstMaximumFrames ||
        (!state.candidateAlreadyPrepared &&
         state.preparedFrames >= kMifBurstMaximumFrames) ||
        (state.candidateAlreadyPrepared &&
         (state.preparedFrames == 0 ||
          state.preparedFrames > kMifBurstMaximumFrames ||
          state.preparedFrames <= state.submittedFrames)))
        return {MifBurstDecision::Stop, MifBurstStopReason::FrameLimit};
    if (!state.sameEpoch)
        return {MifBurstDecision::Stop, MifBurstStopReason::EpochMismatch};
    if (state.outcomeUnknown)
        return {MifBurstDecision::Stop, MifBurstStopReason::RocUnknown};
    if (state.endSeen)
        return {MifBurstDecision::Stop, MifBurstStopReason::RocEnded};
    if (state.nativeDataAttempts != 0)
        return {MifBurstDecision::Stop, MifBurstStopReason::DataStarted};
    if (!state.frameEmpty)
        return {MifBurstDecision::Stop, MifBurstStopReason::FrameNotEmpty};
    if (!state.rocActive)
        return {MifBurstDecision::Stop, MifBurstStopReason::RocInactive};
    if (!state.previousMifSucceeded || !state.ticketSucceeded)
        return {MifBurstDecision::Stop,
                MifBurstStopReason::PreviousTicketFailed};
    if (!state.ticketCompleted || !state.actionIdle)
        return {MifBurstDecision::Stop,
                MifBurstStopReason::PreviousTicketIncomplete};
    if (!state.queueLeaseActive || !state.ringEmpty ||
        !state.ringIndicesConsistent)
        return {MifBurstDecision::Stop, MifBurstStopReason::QueueNotIdle};
    if (!state.lastCompletionUs || state.nowUs < state.lastCompletionUs)
        return {MifBurstDecision::Stop, MifBurstStopReason::InvalidTime};
    if (state.nowUs - state.lastCompletionUs < kMifBurstRepeatIntervalUs)
        return {MifBurstDecision::Wait, MifBurstStopReason::None};
    return {MifBurstDecision::Prepare, MifBurstStopReason::None};
}

} // namespace NativeAwdlProbe

#endif
