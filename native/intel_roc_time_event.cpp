#include "intel_roc_time_event.hpp"

#include <algorithm>

namespace IntelROC {
namespace {

constexpr std::uint32_t kActionAdd = 1;
constexpr std::uint32_t kP2pDeviceDiscoverable = 4;
constexpr std::uint32_t kP2pClientAssociation = 9;
constexpr std::uint16_t kNotifyHostEventStart = 1u << 0;
constexpr std::uint16_t kNotifyHostEventEnd = 1u << 1;
constexpr std::uint16_t kStartImmediately = 1u << 11;
constexpr std::uint8_t kNoFragment = 0;
constexpr std::uint8_t kRepeatOnce = 1;
constexpr std::uint8_t kFragmentEndless = 0xff;

std::uint32_t MillisecondsToTu(std::uint32_t milliseconds)
{
    return static_cast<std::uint32_t>(
        (static_cast<std::uint64_t>(milliseconds) * 1000u) / 1024u);
}

void StoreLe16(std::uint8_t* out, std::uint16_t value)
{
    out[0] = static_cast<std::uint8_t>(value);
    out[1] = static_cast<std::uint8_t>(value >> 8);
}

void StoreLe32(std::uint8_t* out, std::uint32_t value)
{
    out[0] = static_cast<std::uint8_t>(value);
    out[1] = static_cast<std::uint8_t>(value >> 8);
    out[2] = static_cast<std::uint8_t>(value >> 16);
    out[3] = static_cast<std::uint8_t>(value >> 24);
}

std::uint32_t LoadLe32(const std::uint8_t* in)
{
    return static_cast<std::uint32_t>(in[0]) |
           (static_cast<std::uint32_t>(in[1]) << 8) |
           (static_cast<std::uint32_t>(in[2]) << 16) |
           (static_cast<std::uint32_t>(in[3]) << 24);
}

bool GetEventType(RocKind kind, std::uint32_t* eventType)
{
    if (!eventType)
        return false;
    switch (kind) {
    case RocKind::kNormal:
        *eventType = kP2pDeviceDiscoverable;
        return true;
    case RocKind::kManagementTx:
        *eventType = kP2pClientAssociation;
        return true;
    }
    return false;
}

} // namespace

bool BuildTimeEventCommand(std::uint8_t macId,
                           std::uint8_t macColor,
                           RocKind kind,
                           std::uint32_t durationMs,
                           TimeEventCommand* command)
{
    std::uint32_t eventType = 0;
    if (!command || !durationMs || !GetEventType(kind, &eventType))
        return false;

    // 0xffffffff is FW_CTXT_INVALID in if_iwxreg.h.
    const std::uint32_t idAndColor = static_cast<std::uint32_t>(macId) |
        (static_cast<std::uint32_t>(macColor) << 8);

    const std::uint32_t durationTu = MillisecondsToTu(durationMs);
    if (!durationTu)
        return false;

    const std::uint32_t maxDelayTu = MillisecondsToTu(durationMs / 2);
    const std::uint8_t maxFrags = static_cast<std::uint8_t>(std::min(
        durationTu / 50, static_cast<std::uint32_t>(kFragmentEndless)));
    const std::uint16_t policy = kNotifyHostEventStart |
                                 kNotifyHostEventEnd |
                                 kStartImmediately;

    std::array<std::uint8_t, kTimeEventCommandSize>& bytes = command->bytes;
    bytes.fill(0);
    // Offsets follow struct iwx_time_event_cmd in if_iwxreg.h.
    StoreLe32(&bytes[0], idAndColor);
    StoreLe32(&bytes[4], kActionAdd);
    StoreLe32(&bytes[8], eventType);
    StoreLe32(&bytes[12], 0); // apply_time: schedule as soon as possible
    StoreLe32(&bytes[16], maxDelayTu);
    StoreLe32(&bytes[20], 0); // no dependency on another time event
    StoreLe32(&bytes[24], 1); // interval
    StoreLe32(&bytes[28], durationTu);
    bytes[32] = kRepeatOnce;
    bytes[33] = maxFrags ? maxFrags : kNoFragment;
    StoreLe16(&bytes[34], policy);
    return true;
}

ResponseResult DecodeRawTimeEventResponse(const std::uint8_t* bytes,
                                          std::size_t length,
                                          TimeEventResponse* response)
{
    if (!bytes || !response)
        return ResponseResult::kInvalidArgument;
    if (length != kTimeEventResponseSize)
        return ResponseResult::kInvalidLength;

    response->rawStatus = LoadLe32(&bytes[0]);
    response->rawEventType = LoadLe32(&bytes[4]);
    response->uniqueId = LoadLe32(&bytes[8]);
    response->rawMacIdAndColor = LoadLe32(&bytes[12]);
    return ResponseResult::kDecoded;
}

} // namespace IntelROC
