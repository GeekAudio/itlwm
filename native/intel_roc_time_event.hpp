#ifndef INTEL_ROC_TIME_EVENT_HPP
#define INTEL_ROC_TIME_EVENT_HPP

#include <array>
#include <cstddef>
#include <cstdint>

namespace IntelROC {

// Firmware command 0x29, API v2. These values match the local if_iwxreg.h
// definitions used by ItlIwx.cpp.
constexpr std::size_t kTimeEventCommandSize = 36;
constexpr std::size_t kTimeEventResponseSize = 16;

enum class RocKind : std::uint8_t {
    kNormal,
    kManagementTx,
};

struct TimeEventCommand {
    std::array<std::uint8_t, kTimeEventCommandSize> bytes;
};

struct TimeEventResponse {
    std::uint32_t rawStatus;
    std::uint32_t rawEventType;
    std::uint32_t uniqueId;
    std::uint32_t rawMacIdAndColor;
};

enum class ResponseResult : std::uint8_t {
    kDecoded,
    kInvalidArgument,
    kInvalidLength,
};

// Build the legacy TIME_EVENT_CMD API-v2 ROC payload. The caller still owns
// MAC/PHY/binding setup, channel selection, command submission, and TE state.
bool BuildTimeEventCommand(std::uint8_t macId,
                           std::uint8_t macColor,
                           RocKind kind,
                           std::uint32_t durationMs,
                           TimeEventCommand* command);

// Decode only the fixed-size response fields. This does not determine whether
// firmware accepted the command: status semantics conflict across the local
// call site and API documentation, and UID zero is not proven invalid.
ResponseResult DecodeRawTimeEventResponse(const std::uint8_t* bytes,
                                          std::size_t length,
                                          TimeEventResponse* response);

} // namespace IntelROC

#endif // INTEL_ROC_TIME_EVENT_HPP
