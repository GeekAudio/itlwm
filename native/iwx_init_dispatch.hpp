// SPDX-License-Identifier: GPL-2.0-only
#ifndef GEEK_IWX_INIT_DISPATCH_HPP
#define GEEK_IWX_INIT_DISPATCH_HPP

#include <stdint.h>

namespace IwxInitDispatch {

static constexpr uint32_t kPowerStateKnown = 1U << 0;
static constexpr uint32_t kPowerRequestedOn = 1U << 1;
static constexpr uint32_t kFaultRecovery = 1U << 0;

struct Token {
    uint64_t dispatchId;
    uint32_t driverGeneration;
    uint32_t faultSerial;
    uint32_t powerEpoch;
    uint32_t powerFlags;
    uint32_t dispatchFlags;
};

struct CurrentState {
    uint32_t driverGeneration;
    uint32_t faultSerial;
    uint32_t powerEpoch;
    uint32_t powerFlags;
};

enum class Decision : uint32_t {
    Run = 0,
    InvalidToken,
    PowerEpochChanged,
    DriverGenerationChanged,
    FaultAdvanced,
    Superseded,
    ExplicitlyOff
};

inline Decision validate(const Token &token, const CurrentState &current,
                         bool queueDispatchIsCurrent)
{
    if (token.dispatchId == 0)
        return Decision::InvalidToken;
    if (token.powerEpoch != current.powerEpoch ||
        token.powerFlags != current.powerFlags)
        return Decision::PowerEpochChanged;
    if (token.faultSerial != current.faultSerial)
        return Decision::FaultAdvanced;
    if (!queueDispatchIsCurrent)
        return Decision::Superseded;
    if ((current.powerFlags & kPowerStateKnown) != 0 &&
        (current.powerFlags & kPowerRequestedOn) == 0)
        return Decision::ExplicitlyOff;
    // Only an explicitly fault-tagged dispatch may survive a stop/reset
    // generation advance. An ordinary task can carry a historical fault
    // serial for supersession checks without inheriting recovery privilege.
    if (token.driverGeneration != current.driverGeneration) {
        const bool currentFaultRecovery =
            (token.dispatchFlags & kFaultRecovery) != 0 &&
            token.faultSerial != 0;
        if (!currentFaultRecovery)
            return Decision::DriverGenerationChanged;
    }
    return Decision::Run;
}

inline uint64_t nextDispatchId(uint64_t previous)
{
    uint64_t next = previous + 1U;
    if (next == 0)
        next = 1U;
    return next;
}

inline bool dispatchIdIsNewer(uint64_t candidate, uint64_t baseline)
{
    const uint64_t distance = candidate - baseline;
    return candidate != baseline && distance < (UINT64_C(1) << 63);
}

inline uint32_t nextFaultSerial(uint32_t previous)
{
    uint32_t next = previous + 1U;
    if (next == 0)
        next = 1U;
    return next;
}

} // namespace IwxInitDispatch

#endif // GEEK_IWX_INIT_DISPATCH_HPP
