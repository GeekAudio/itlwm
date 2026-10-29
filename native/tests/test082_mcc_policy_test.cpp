#include <cassert>
#include <cstdint>
#include <cstring>
#include <vector>
#include "native/iwx_mcc_refresh_policy.hpp"

using IwxMccRefreshPolicy::ProfileAction;
using IwxMccRefreshPolicy::RequestBlock;
using IwxMccRefreshPolicy::RequestInputs;

static void testRequestPreconditions()
{
    assert(IwxMccRefreshPolicy::requestBlock(
        {true, true, true, true, false}) == RequestBlock::kReady);
    assert(IwxMccRefreshPolicy::requestBlock(
        {false, true, true, true, false}) == RequestBlock::kNoPending);
    assert(IwxMccRefreshPolicy::requestBlock(
        {true, false, true, true, false}) == RequestBlock::kLarDisabled);
    assert(IwxMccRefreshPolicy::requestBlock(
        {true, true, false, true, false}) == RequestBlock::kMultiSourceUnsupported);
    assert(IwxMccRefreshPolicy::requestBlock(
        {true, true, true, false, false}) == RequestBlock::kInterfaceNotRunning);
    assert(IwxMccRefreshPolicy::requestBlock(
        {true, true, true, true, true}) == RequestBlock::kShuttingDown);
}

static void testMccAndSourceValidation()
{
    using namespace IwxMccRefreshPolicy;
    constexpr uint32_t kUs = static_cast<uint32_t>(('U' << 8) | 'S');
    assert(kUs == 0x5553U);
    assert(validMcc(kUs));
    assert(validMcc(static_cast<uint32_t>('0' | ('0' << 8))));
    assert(!validMcc(static_cast<uint32_t>('u' | ('s' << 8))));
    assert(!validMcc(static_cast<uint32_t>('U' | ('1' << 8))));
    assert(!validMcc(0x00000053U));

    for (uint32_t source : {1U, 2U, 3U, 4U, 5U, 7U, 9U})
        assert(validChubSource(source));
    for (uint32_t source : {0U, 6U, 8U, 10U, 16U, 17U, 0xffffffffU})
        assert(!validChubSource(source));
    for (uint32_t source : {0U, 1U, 2U, 3U, 4U, 5U, 7U, 9U, 16U, 17U})
        assert(validResponseSource(source));
    for (uint32_t source : {6U, 8U, 10U, 11U, 12U, 18U, 0xffffffffU})
        assert(!validResponseSource(source));

    constexpr uint32_t us = static_cast<uint32_t>(('U' << 8) | 'S');
    const uint32_t zero = static_cast<uint32_t>('0' | ('0' << 8));
    assert(chubRequestValid(us, 5));
    assert(chubRequestValid(zero, 9));
    assert(!chubRequestValid(us, 16)); // GET_CURRENT is not a CHUB source.
    assert(!chubRequestValid(0, 5));
}

static void testGenerationAndLifecycleFence()
{
    assert(IwxMccRefreshPolicy::responseMayApply(7, 7, 3, 3,
                                                 true, false, true));
    assert(!IwxMccRefreshPolicy::responseMayApply(7, 8, 3, 3,
                                                  true, false, true));
    assert(!IwxMccRefreshPolicy::responseMayApply(7, 7, 3, 4,
                                                  true, false, true));
    assert(!IwxMccRefreshPolicy::responseMayApply(7, 7, 3, 3,
                                                  false, false, true));
    assert(!IwxMccRefreshPolicy::responseMayApply(7, 7, 3, 3,
                                                  true, true, true));
    assert(!IwxMccRefreshPolicy::responseMayApply(7, 7, 3, 3,
                                                  true, false, false));
    assert(!IwxMccRefreshPolicy::responseMayApply(0, 0, 3, 3,
                                                  true, false, true));
    assert(!IwxMccRefreshPolicy::responseMayApply(7, 7, 0, 0,
                                                  true, false, true));
}

static ProfileAction profile(uint32_t status, uint32_t count,
                             uint32_t minimumKnown = 51,
                             uint32_t maximum = 110)
{
    constexpr uint32_t kNew = 1;
    constexpr uint32_t kSame = 2;
    constexpr uint32_t kIllegal = 3;
    return IwxMccRefreshPolicy::profileAction(status, count, minimumKnown,
        maximum, kNew, kSame, kIllegal);
}

static void testStrictProfileShape()
{
    assert(profile(2, 0) == ProfileAction::kNoChange);
    assert(profile(1, 51) == ProfileAction::kApplyComplete);
    assert(profile(2, 51) == ProfileAction::kApplyComplete);
    assert(profile(3, 51) == ProfileAction::kApplyComplete);
    // Extra channel records are retained for evidence but callers may map
    // only their known channel-array prefix.
    assert(profile(1, 60) == ProfileAction::kApplyComplete);
    assert(profile(1, 50) == ProfileAction::kReject);
    assert(profile(2, 1) == ProfileAction::kReject);
    assert(profile(1, 0) == ProfileAction::kReject);
    assert(profile(1, 111) == ProfileAction::kReject);
    assert(profile(99, 51) == ProfileAction::kReject);
    assert(profile(1, 51, 0, 110) == ProfileAction::kReject);
}

static void testDynamicChannel149Index()
{
    uint8_t channels[51]{};
    channels[42] = 149;
    channels[50] = 177;
    assert(IwxMccRefreshPolicy::channelProfileIndex(channels, 51, 149) == 42);
    assert(IwxMccRefreshPolicy::channelProfileIndex(channels, 51, 177) == 50);
    assert(IwxMccRefreshPolicy::channelProfileIndex(channels, 51, 165) == -1);
    assert(IwxMccRefreshPolicy::channelProfileIndex(nullptr, 51, 149) == -1);
    assert(sizeof(IwxMccRefreshPolicy::ProfileResponse::channelFlags) /
           sizeof(uint32_t) == IwxMccRefreshPolicy::kMaximumChannelCount);
}

static void putLE16(std::vector<uint8_t> &bytes, size_t offset, uint16_t value)
{
    bytes[offset] = static_cast<uint8_t>(value);
    bytes[offset + 1] = static_cast<uint8_t>(value >> 8);
}

static void putLE32(std::vector<uint8_t> &bytes, size_t offset, uint32_t value)
{
    bytes[offset] = static_cast<uint8_t>(value);
    bytes[offset + 1] = static_cast<uint8_t>(value >> 8);
    bytes[offset + 2] = static_cast<uint8_t>(value >> 16);
    bytes[offset + 3] = static_cast<uint8_t>(value >> 24);
}

static std::vector<uint8_t> makeResponse(bool v4, uint32_t status,
                                        uint32_t channelCount)
{
    const size_t header = v4 ? IwxMccRefreshPolicy::kResponseHeaderV4Size :
                               IwxMccRefreshPolicy::kResponseHeaderV3Size;
    std::vector<uint8_t> bytes(header + channelCount * sizeof(uint32_t), 0);
    putLE32(bytes, 0, status);
    putLE16(bytes, 4, static_cast<uint16_t>(('U' << 8) | 'S'));
    if (v4) {
        putLE16(bytes, 6, 0x1234);
        putLE16(bytes, 8, 30);
        putLE16(bytes, 10, 2);
        bytes[12] = 0x10; // GET_CURRENT source, distinct from CHUB notification.
        putLE32(bytes, 16, channelCount);
    } else {
        bytes[6] = 0x34; // v3 cap byte
        bytes[7] = 0x05; // notification response source
        putLE16(bytes, 8, 30);
        putLE16(bytes, 10, 2);
        putLE32(bytes, 12, channelCount);
    }
    const size_t start = header;
    for (uint32_t i = 0; i < channelCount; ++i)
        putLE32(bytes, start + static_cast<size_t>(i) * 4,
                0x10000U + i);
    if (channelCount > 42)
        putLE32(bytes, start + 42 * 4, 0x00008800U);
    return bytes;
}

static void testCapabilitySelectsV3OrV4AndPayloadIsStrict()
{
    constexpr size_t kKnownCount = 51;
    uint8_t channels[kKnownCount]{};
    channels[42] = 149;
    IwxMccRefreshPolicy::ProfileResponse parsed{};

    // Core 66 command-directory evidence is cmd=1/notif=5. The caller passes
    // capability 89, which is the wire layout selector; notification version
    // 5 does not force the parser back to v3.
    const uint32_t commandVersion = 1;
    const uint32_t notificationVersion = 5;
    assert(commandVersion == 1 && notificationVersion == 5);
    const auto v4 = makeResponse(true, 0, 51);
    assert(IwxMccRefreshPolicy::parseResponse(v4.data(), v4.size(), true,
        channels, kKnownCount, 149, &parsed));
    assert(parsed.responseFormat == IwxMccRefreshPolicy::kResponseFormatV4);
    assert(parsed.mccUpdate11axCapability == 1);
    assert(parsed.mcc == static_cast<uint16_t>(('U' << 8) | 'S'));
    assert(v4[4] == 'S' && v4[5] == 'U'); // LE bytes carry high-byte-first MCC "US".
    assert(parsed.source == 0x10 && parsed.channelCount == 51);
    assert(parsed.responseValid == 1 && parsed.profileAction == 2);
    assert(parsed.profile149Present && parsed.profile149Flags == 0x8800);

    auto invalidV4Source = v4;
    invalidV4Source[12] = 6; // reserved/unknown response source
    assert(!IwxMccRefreshPolicy::parseResponse(invalidV4Source.data(),
        invalidV4Source.size(), true, channels, kKnownCount, 149, &parsed));
    auto invalidV4Mcc = v4;
    putLE16(invalidV4Mcc, 4, static_cast<uint16_t>('U' | ('1' << 8)));
    assert(!IwxMccRefreshPolicy::parseResponse(invalidV4Mcc.data(),
        invalidV4Mcc.size(), true, channels, kKnownCount, 149, &parsed));

    const auto v3 = makeResponse(false, 0, 51);
    assert(IwxMccRefreshPolicy::parseResponse(v3.data(), v3.size(), false,
        channels, kKnownCount, 149, &parsed));
    assert(parsed.responseFormat == IwxMccRefreshPolicy::kResponseFormatV3);
    assert(parsed.mccUpdate11axCapability == 0);
    assert(parsed.source == 5 && parsed.channelCount == 51);
    assert(parsed.channelFlags[0] == 0); // v3 exposes only low 16 bits.
    assert(parsed.profile149Flags == 0x8800);
    auto invalidV3Source = v3;
    invalidV3Source[7] = 8;
    assert(!IwxMccRefreshPolicy::parseResponse(invalidV3Source.data(),
        invalidV3Source.size(), false, channels, kKnownCount, 149, &parsed));

    // A longer complete profile is accepted, but channel lookup remains tied
    // to the current known array; the unknown firmware tail is not channel 149.
    const auto tail = makeResponse(true, 0, 60);
    assert(IwxMccRefreshPolicy::parseResponse(tail.data(), tail.size(), true,
        channels, kKnownCount, 149, &parsed));
    assert(parsed.channelCount == 60 && parsed.profile149Flags == 0x8800);
    assert(parsed.channelFlags[59] == 0x1003bU);

    const auto unchanged = makeResponse(true, 1, 0);
    assert(IwxMccRefreshPolicy::parseResponse(unchanged.data(), unchanged.size(),
        true, channels, kKnownCount, 149, &parsed));
    assert(parsed.profileAction == 1 && !parsed.profile149Present);

    // Reject wrong header selection, short/trailing payload, missing known
    // channel prefix, impossible counts, and status that cannot apply a map.
    assert(!IwxMccRefreshPolicy::parseResponse(v4.data(), v4.size(), false,
        channels, kKnownCount, 149, &parsed));
    assert(!IwxMccRefreshPolicy::parseResponse(v4.data(), 19, true,
        channels, kKnownCount, 149, &parsed));
    std::vector<uint8_t> trailing = v4;
    trailing.push_back(0);
    assert(!IwxMccRefreshPolicy::parseResponse(trailing.data(), trailing.size(),
        true, channels, kKnownCount, 149, &parsed));
    const auto shortProfile = makeResponse(true, 0, 50);
    assert(!IwxMccRefreshPolicy::parseResponse(shortProfile.data(),
        shortProfile.size(), true, channels, kKnownCount, 149, &parsed));
    const auto oversized = makeResponse(true, 0, 111);
    assert(!IwxMccRefreshPolicy::parseResponse(oversized.data(), oversized.size(),
        true, channels, kKnownCount, 149, &parsed));
    const auto badStatus = makeResponse(true, 5, 51);
    assert(!IwxMccRefreshPolicy::parseResponse(badStatus.data(), badStatus.size(),
        true, channels, kKnownCount, 149, &parsed));
}

int main()
{
    testRequestPreconditions();
    testMccAndSourceValidation();
    testGenerationAndLifecycleFence();
    testStrictProfileShape();
    testDynamicChannel149Index();
    testCapabilitySelectsV3OrV4AndPayloadIsStrict();
    return 0;
}
