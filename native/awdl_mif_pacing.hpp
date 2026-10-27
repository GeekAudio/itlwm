// SPDX-License-Identifier: GPL-2.0-only
#ifndef NATIVE_AWDL_MIF_PACING_HPP
#define NATIVE_AWDL_MIF_PACING_HPP

#include <stdint.h>

namespace NativeAwdlProbe {

constexpr uint32_t kMifPacingMaximumFrames = 3;
constexpr uint64_t kMifPacingTuUs = 1024ULL;
constexpr uint64_t kMifPacingMaximumPeerPsfAgeUs = 16ULL * kMifPacingTuUs;
// Match the existing conservative PSF lease margin. This is a minimum
// submission reserve, not an airtime or completion guarantee.
constexpr uint64_t kMifPacingMinimumLeaseReserveUs = 20000ULL;

enum class MifPacingDecision : uint8_t {
    Wait,
    Ready,
    Stop
};

enum class MifPacingReason : uint8_t {
    None,
    InvalidInput,
    BeforeNotBefore,
    WaitingForFreshPsf,
    PsfIncomplete,
    PsfInconsistent,
    PsfNotFresh,
    PsfWrongChannel,
    PsfBeforeNotBefore,
    PsfAlreadyUsed,
    PsfTooOld,
    ReadyAnchor,
    WrongEpoch,
    RocInactive,
    RocChannelUnconfirmed,
    RocEnded,
    RocUnknown,
    Deadline,
    InsufficientLease,
    FrameLimit,
    InvalidTime,
    PreparedFrameStale
};

struct MifPacingInput {
    uint64_t phaseOriginUs;
    uint64_t announcedWindowEndUs;
    uint64_t hardDeadlineUs;
    uint64_t nowUs;
    uint64_t peerPsfRxUs;
    uint64_t lastUsedPeerPsfRxUs;
    uint64_t contextGeneration;
    uint64_t powerGeneration;
    uint64_t stationGeneration;
    uint64_t peerContextGeneration;
    uint64_t peerPowerGeneration;
    uint64_t peerStationGeneration;
    uint32_t frameOrdinal;
    uint16_t peerRxChannelIndex;
    bool rocActive;
    bool rocChannel6Confirmed;
    bool endSeen;
    bool outcomeUnknown;
    bool peerPsfComplete;
    bool peerPsfSyncConsistent;
    bool peerPsfFresh;
    bool peerPsfRxChannel6Confirmed;
};

struct MifPacingPlan {
    MifPacingDecision decision;
    MifPacingReason reason;
    uint64_t earliestUs;
    uint64_t latestUs;
    uint64_t peerPsfAgeUs;
    uint64_t anchorRxUs;
};

namespace MifPacingDetail {

inline bool quarterOffset(uint64_t durationUs, uint32_t ordinal,
                          uint64_t *offsetUs)
{
    if (!offsetUs || ordinal >= kMifPacingMaximumFrames)
        return false;

    const uint64_t numerator = static_cast<uint64_t>(ordinal) + 1;
    const uint64_t quotient = durationUs / 4;
    const uint64_t remainder = durationUs % 4;
    const uint64_t whole = quotient * numerator;
    const uint64_t partialNumerator = remainder * numerator;
    const uint64_t partial = (partialNumerator + 3) / 4;
    if (whole > UINT64_MAX - partial)
        return false;
    *offsetUs = whole + partial;
    return true;
}

inline uint64_t saturatingAdd(uint64_t a, uint64_t b)
{
    return a > UINT64_MAX - b ? UINT64_MAX : a + b;
}

inline MifPacingPlan result(MifPacingDecision decision,
                            MifPacingReason reason,
                            uint64_t earliestUs,
                            uint64_t latestUs,
                            uint64_t ageUs = 0,
                            uint64_t anchorRxUs = 0)
{
    return {decision, reason, earliestUs, latestUs, ageUs, anchorRxUs};
}

} // namespace MifPacingDetail

inline bool mifPacingNotBeforeUs(uint64_t phaseOriginUs,
                                 uint64_t announcedWindowEndUs,
                                 uint32_t frameOrdinal,
                                 uint64_t *notBeforeUs)
{
    if (!notBeforeUs || !phaseOriginUs ||
        announcedWindowEndUs <= phaseOriginUs ||
        frameOrdinal >= kMifPacingMaximumFrames)
        return false;
    uint64_t offsetUs = 0;
    if (!MifPacingDetail::quarterOffset(
            announcedWindowEndUs - phaseOriginUs, frameOrdinal, &offsetUs) ||
        phaseOriginUs > UINT64_MAX - offsetUs)
        return false;
    *notBeforeUs = phaseOriginUs + offsetUs;
    return true;
}

// Pace at most three MIF candidates within the locally advertised full-slot
// window and the original bounded ROC lease.
// A valid peer PSF is only a receive-time/channel witness: this helper never
// admits a peer, follows its election, or consumes its advertised schedule.
inline MifPacingPlan planMifPacing(const MifPacingInput &input)
{
    using namespace MifPacingDetail;

    if (input.frameOrdinal >= kMifPacingMaximumFrames)
        return result(MifPacingDecision::Stop, MifPacingReason::FrameLimit,
                      0, input.hardDeadlineUs);
    if (!input.phaseOriginUs || !input.announcedWindowEndUs ||
        !input.hardDeadlineUs || !input.nowUs ||
        input.announcedWindowEndUs <= input.phaseOriginUs ||
        input.announcedWindowEndUs > input.hardDeadlineUs ||
        input.hardDeadlineUs <= input.phaseOriginUs ||
        !input.contextGeneration || !input.powerGeneration ||
        !input.stationGeneration)
        return result(MifPacingDecision::Stop, MifPacingReason::InvalidInput,
                      0, input.hardDeadlineUs);

    uint64_t offsetUs = 0;
    if (!quarterOffset(input.announcedWindowEndUs - input.phaseOriginUs,
                       input.frameOrdinal, &offsetUs) ||
        input.phaseOriginUs > UINT64_MAX - offsetUs)
        return result(MifPacingDecision::Stop, MifPacingReason::InvalidInput,
                      0, input.hardDeadlineUs);
    const uint64_t earliestUs = input.phaseOriginUs + offsetUs;
    const uint64_t effectiveEndUs = input.announcedWindowEndUs <
        input.hardDeadlineUs ? input.announcedWindowEndUs :
                               input.hardDeadlineUs;

    if (input.nowUs < input.phaseOriginUs)
        return result(MifPacingDecision::Stop, MifPacingReason::InvalidTime,
                      earliestUs, effectiveEndUs);
    if (input.outcomeUnknown)
        return result(MifPacingDecision::Stop, MifPacingReason::RocUnknown,
                      earliestUs, effectiveEndUs);
    if (input.endSeen)
        return result(MifPacingDecision::Stop, MifPacingReason::RocEnded,
                      earliestUs, effectiveEndUs);
    if (!input.rocActive)
        return result(MifPacingDecision::Stop, MifPacingReason::RocInactive,
                      earliestUs, effectiveEndUs);
    if (!input.rocChannel6Confirmed)
        return result(MifPacingDecision::Stop,
                      MifPacingReason::RocChannelUnconfirmed,
                      earliestUs, effectiveEndUs);
    if (input.nowUs >= effectiveEndUs)
        return result(MifPacingDecision::Stop, MifPacingReason::Deadline,
                      earliestUs, effectiveEndUs);
    if (effectiveEndUs - input.nowUs <=
        kMifPacingMinimumLeaseReserveUs)
        return result(MifPacingDecision::Stop,
                      MifPacingReason::InsufficientLease,
                      earliestUs, effectiveEndUs);
    if (input.nowUs < earliestUs)
        return result(MifPacingDecision::Wait,
                      MifPacingReason::BeforeNotBefore,
                      earliestUs, effectiveEndUs);
    if (!input.peerPsfComplete)
        return result(MifPacingDecision::Wait, MifPacingReason::PsfIncomplete,
                      earliestUs, effectiveEndUs);

    if (input.peerContextGeneration != input.contextGeneration ||
        input.peerPowerGeneration != input.powerGeneration ||
        input.peerStationGeneration != input.stationGeneration)
        return result(MifPacingDecision::Stop, MifPacingReason::WrongEpoch,
                      earliestUs, effectiveEndUs);
    if (!input.peerPsfSyncConsistent)
        return result(MifPacingDecision::Wait,
                      MifPacingReason::PsfInconsistent,
                      earliestUs, effectiveEndUs);
    if (!input.peerPsfFresh)
        return result(MifPacingDecision::Wait, MifPacingReason::PsfNotFresh,
                      earliestUs, effectiveEndUs);
    if (!input.peerPsfRxChannel6Confirmed)
        return result(MifPacingDecision::Wait,
                      MifPacingReason::PsfWrongChannel,
                      earliestUs, effectiveEndUs);
    if (!input.peerPsfRxUs || input.peerPsfRxUs > input.nowUs)
        return result(MifPacingDecision::Stop, MifPacingReason::InvalidTime,
                      earliestUs, effectiveEndUs);
    if (input.peerPsfRxUs < earliestUs)
        return result(MifPacingDecision::Wait,
                      MifPacingReason::PsfBeforeNotBefore,
                      earliestUs, effectiveEndUs);
    if (input.peerPsfRxUs <= input.lastUsedPeerPsfRxUs)
        return result(MifPacingDecision::Wait, MifPacingReason::PsfAlreadyUsed,
                      earliestUs, effectiveEndUs);

    const uint64_t ageUs = input.nowUs - input.peerPsfRxUs;
    const uint64_t freshUntilUs = saturatingAdd(
        input.peerPsfRxUs, kMifPacingMaximumPeerPsfAgeUs);
    const uint64_t latestUs = freshUntilUs < effectiveEndUs ?
        freshUntilUs : effectiveEndUs;
    if (ageUs > kMifPacingMaximumPeerPsfAgeUs)
        return result(MifPacingDecision::Wait, MifPacingReason::PsfTooOld,
                      earliestUs, latestUs, ageUs);

    return result(MifPacingDecision::Ready, MifPacingReason::ReadyAnchor,
                  earliestUs, latestUs, ageUs, input.peerPsfRxUs);
}

} // namespace NativeAwdlProbe

#endif
