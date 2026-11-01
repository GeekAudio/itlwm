// SPDX-License-Identifier: GPL-2.0-only
#ifndef GEEK_IWX_ADD_STA_KEY_STATUS_HPP
#define GEEK_IWX_ADD_STA_KEY_STATUS_HPP

#include <stddef.h>
#include <stdint.h>

// Address-free decoder for the generic firmware status returned with
// ADD_STA_KEY. This reports only the local firmware response payload; it is
// not evidence of peer acknowledgement or end-to-end key installation.
namespace IwxAddStaKeyStatus {

constexpr size_t kStatusBytes = sizeof(uint32_t);

enum class Outcome : uint8_t {
    NotApplicable = 0,
    StatusUnavailable = 1,
    StatusPresent = 2
};

struct Observation {
    Outcome outcome;
    uint32_t status;
    bool commandResponseFailed;
};

inline bool isPendingCommandQueueIndex(size_t ringCount, int currentIndex,
                                       int queued, size_t responseIndex)
{
    if (ringCount == 0 || (ringCount & (ringCount - 1U)) != 0U ||
        currentIndex < 0 || static_cast<size_t>(currentIndex) >= ringCount ||
        queued <= 0 || static_cast<size_t>(queued) >= ringCount ||
        responseIndex >= ringCount)
        return false;

    const size_t pendingStart =
        (static_cast<size_t>(currentIndex) + ringCount -
         static_cast<size_t>(queued)) % ringCount;
    const size_t distance = (responseIndex + ringCount - pendingStart) % ringCount;
    return distance < static_cast<size_t>(queued);
}

inline uint32_t loadLittleEndian32(const uint8_t *bytes)
{
    return uint32_t(bytes[0]) |
        (uint32_t(bytes[1]) << 8) |
        (uint32_t(bytes[2]) << 16) |
        (uint32_t(bytes[3]) << 24);
}

inline Observation decode(uint32_t normalizedCommandId,
                          uint32_t addStaKeyCommandId, uint32_t qid,
                          uint32_t commandQueueId,
                          bool commandResponseFailed,
                          const uint8_t *payload,
                          size_t declaredPayloadLength,
                          size_t actualPayloadCapacity)
{
    Observation observation{};
    observation.outcome = Outcome::NotApplicable;
    if (normalizedCommandId != addStaKeyCommandId || qid != commandQueueId)
        return observation;

    observation.commandResponseFailed = commandResponseFailed;
    if (!payload || declaredPayloadLength != kStatusBytes ||
        actualPayloadCapacity < kStatusBytes ||
        declaredPayloadLength > actualPayloadCapacity) {
        observation.outcome = Outcome::StatusUnavailable;
        return observation;
    }

    observation.status = loadLittleEndian32(payload);
    observation.outcome = Outcome::StatusPresent;
    return observation;
}

} // namespace IwxAddStaKeyStatus

#endif // GEEK_IWX_ADD_STA_KEY_STATUS_HPP
