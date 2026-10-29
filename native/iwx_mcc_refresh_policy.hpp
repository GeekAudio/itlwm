#pragma once

#include <stddef.h>
#include <stdint.h>

/*
 * Small, platform-independent gates for the Tahoe MCC refresh path.
 * These helpers deliberately do not infer permission from channel flags and
 * never rewrite a firmware-provided regulatory profile.
 */
namespace IwxMccRefreshPolicy {

constexpr uint32_t kMaximumChannelCount = 110;
constexpr uint32_t kResponseFormatV3 = 3;
constexpr uint32_t kResponseFormatV4 = 4;
constexpr uint32_t kResponseHeaderV3Size = 16;
constexpr uint32_t kResponseHeaderV4Size = 20;
constexpr uint32_t kRequestOriginInitGetCurrent = 1;
constexpr uint32_t kRequestOriginChubNotification = 2;
constexpr uint32_t kGateRetiredByStop = 10;

/* A private, bounded copy of MCC_UPDATE_CMD response data. The host IRQ/RX
 * buffer is released before this object is dispatched through the command
 * gate for stale-generation validation and map application. */
struct ProfileResponse {
    uint32_t requestSequence;
    uint32_t requestMcc;
    uint32_t requestSource;
    uint32_t requestOrigin;
    uint32_t noticeGeneration;
    uint32_t firmwareGeneration;
    uint32_t status;
    uint32_t mcc;
    uint32_t capabilities;
    uint32_t time;
    uint32_t geoInfo;
    uint32_t source;
    uint32_t channelCount;
    uint32_t commandVersion;
    uint32_t notificationVersion;
    uint32_t responseFormat;
    uint32_t mccUpdate11axCapability;
    uint32_t responseValid;
    uint32_t commandAttempted;
    uint32_t profileAction;
    uint32_t channelFlags[kMaximumChannelCount];
    uint32_t profile149Flags;
    bool profile149Present;
};

enum class ProfileAction : uint32_t;
constexpr ProfileAction profileAction(uint32_t, uint32_t, uint32_t, uint32_t,
                                      uint32_t, uint32_t, uint32_t);
constexpr int channelProfileIndex(const uint8_t *, size_t, uint8_t);

/* Decode the two documented MCC_UPDATE response layouts. Firmware command
 * directory notification version is intentionally not used to select this
 * layout: capability 89 is the firmware contract for the 11ax/v4 header. */
inline uint16_t readLE16(const uint8_t *bytes)
{
    return static_cast<uint16_t>(bytes[0]) |
        static_cast<uint16_t>(static_cast<uint16_t>(bytes[1]) << 8);
}

inline uint32_t readLE32(const uint8_t *bytes)
{
    return static_cast<uint32_t>(bytes[0]) |
        (static_cast<uint32_t>(bytes[1]) << 8) |
        (static_cast<uint32_t>(bytes[2]) << 16) |
        (static_cast<uint32_t>(bytes[3]) << 24);
}

inline bool validMcc(uint32_t mcc)
{
    const uint8_t first = static_cast<uint8_t>((mcc >> 8) & 0xffU);
    const uint8_t second = static_cast<uint8_t>(mcc & 0xffU);
    return (first >= 'A' && first <= 'Z' &&
            second >= 'A' && second <= 'Z') ||
           (first == '0' && second == '0');
}

inline bool validChubSource(uint32_t source)
{
    /* Source IDs that may legitimately identify a CHUB-provided MCC. Keep
     * OLD_FW, reserved, uninitialized, GET_CURRENT and test-mode sources out
     * of this asynchronous refresh path. */
    return source == 1U || source == 2U || source == 3U || source == 4U ||
           source == 5U || source == 7U || source == 9U;
}

inline bool validResponseSource(uint32_t source)
{
    return source == 0U || source == 1U || source == 2U || source == 3U ||
           source == 4U || source == 5U || source == 7U || source == 9U ||
           source == 0x10U || source == 0x11U;
}

inline bool parseResponse(const uint8_t *payload, size_t payloadLength,
                          bool capability89,
                          const uint8_t *knownChannels,
                          size_t knownChannelCount, uint8_t channel149,
                          ProfileResponse *out)
{
    if (!payload || !out || !knownChannels || knownChannelCount == 0 ||
        knownChannelCount > kMaximumChannelCount)
        return false;

    const size_t headerSize = capability89 ? kResponseHeaderV4Size :
                                             kResponseHeaderV3Size;
    if (payloadLength < headerSize)
        return false;

    const uint32_t channelCount = capability89 ? readLE32(payload + 16) :
                                                readLE32(payload + 12);
    if (channelCount > kMaximumChannelCount ||
        channelCount > (SIZE_MAX - headerSize) / sizeof(uint32_t) ||
        payloadLength != headerSize + channelCount * sizeof(uint32_t))
        return false;

    const uint32_t status = readLE32(payload);
    const uint32_t profileActionValue = static_cast<uint32_t>(
        profileAction(status, channelCount,
        static_cast<uint32_t>(knownChannelCount), kMaximumChannelCount,
        0U, 1U, 4U));
    if (profileActionValue == 0U)
        return false;

    const uint32_t mcc = readLE16(payload + 4);
    const uint32_t source = capability89 ? payload[12] : payload[7];
    if (!validMcc(mcc) || !validResponseSource(source))
        return false;

    ProfileResponse parsed{};
    parsed.status = status;
    parsed.mcc = mcc;
    parsed.mccUpdate11axCapability = capability89 ? 1U : 0U;
    parsed.capabilities = capability89 ? readLE16(payload + 6) : payload[6];
    parsed.time = readLE16(payload + 8);
    parsed.geoInfo = readLE16(payload + 10);
    parsed.source = source;
    parsed.channelCount = channelCount;
    parsed.responseFormat = capability89 ? kResponseFormatV4 :
                                           kResponseFormatV3;
    parsed.profileAction = profileActionValue;
    parsed.responseValid = 1;

    const size_t channelOffset = headerSize;
    for (uint32_t index = 0; index < channelCount; ++index) {
        const uint32_t raw = readLE32(payload + channelOffset +
                                      index * sizeof(uint32_t));
        parsed.channelFlags[index] = capability89 ? raw : (raw & 0xffffU);
    }
    const int channel149Index = channelProfileIndex(knownChannels,
        knownChannelCount, channel149);
    if (channel149Index >= 0 &&
        static_cast<uint32_t>(channel149Index) < channelCount) {
        parsed.profile149Flags = parsed.channelFlags[channel149Index];
        parsed.profile149Present = true;
    }
    *out = parsed;
    return true;
}

enum class RequestBlock : uint32_t {
    kReady = 0,
    kNoPending = 1,
    kLarDisabled = 2,
    kMultiSourceUnsupported = 3,
    kInterfaceNotRunning = 4,
    kShuttingDown = 5,
};

struct RequestInputs {
    bool pending;
    bool larEnabled;
    bool multiSourceSupported;
    bool interfaceRunning;
    bool shuttingDown;
};

constexpr RequestBlock requestBlock(const RequestInputs &input)
{
    return input.shuttingDown ? RequestBlock::kShuttingDown :
        !input.pending ? RequestBlock::kNoPending :
        !input.larEnabled ? RequestBlock::kLarDisabled :
        !input.multiSourceSupported ? RequestBlock::kMultiSourceUnsupported :
        !input.interfaceRunning ? RequestBlock::kInterfaceNotRunning :
        RequestBlock::kReady;
}

constexpr bool chubRequestValid(uint32_t mcc, uint32_t source)
{
    return validMcc(mcc) && validChubSource(source);
}

/* A query result is only applicable to the exact firmware and notice epoch
 * that initiated it. Check again after the synchronous response arrives. */
constexpr bool responseMayApply(uint32_t requestFirmwareGeneration,
                                uint32_t currentFirmwareGeneration,
                                uint32_t requestNoticeGeneration,
                                uint32_t currentNoticeGeneration,
                                bool interfaceRunning,
                                bool shuttingDown,
                                bool responseValid)
{
    return responseValid && interfaceRunning && !shuttingDown &&
        requestFirmwareGeneration != 0 &&
        requestFirmwareGeneration == currentFirmwareGeneration &&
        requestNoticeGeneration != 0 &&
        requestNoticeGeneration == currentNoticeGeneration;
}

enum class ProfileAction : uint32_t {
    kReject = 0,
    kNoChange = 1,
    kApplyComplete = 2,
};

/* Firmware replies may omit a profile when it reports that the profile is
 * unchanged. Any partial map is rejected: applying only its prefix would
 * leave the tail of the previous channel map in place. */
constexpr ProfileAction profileAction(uint32_t status,
                                      uint32_t nChannels,
                                      uint32_t minimumKnownChannels,
                                      uint32_t maximumChannels,
                                      uint32_t newProfileStatus,
                                      uint32_t sameProfileStatus,
                                      uint32_t illegalStatus)
{
    if (status == sameProfileStatus && nChannels == 0)
        return ProfileAction::kNoChange;
    if (minimumKnownChannels != 0 &&
        nChannels >= minimumKnownChannels &&
        nChannels <= maximumChannels &&
        (status == newProfileStatus || status == sameProfileStatus ||
         status == illegalStatus))
        return ProfileAction::kApplyComplete;
    return ProfileAction::kReject;
}

constexpr int channelProfileIndex(const uint8_t *channels, size_t count,
                                  uint8_t channel)
{
    if (!channels)
        return -1;
    for (size_t index = 0; index < count; ++index) {
        if (channels[index] == channel)
            return static_cast<int>(index);
    }
    return -1;
}

} // namespace IwxMccRefreshPolicy
