// SPDX-License-Identifier: GPL-2.0-only
#include "openwrt_echo_channel.hpp"
#include <assert.h>
#include <stdio.h>
#include <string.h>

using namespace Test110Channel;

static void set16(uint8_t *p, uint16_t value)
{
    p[0] = static_cast<uint8_t>(value);
    p[1] = static_cast<uint8_t>(value >> 8);
}

static void set32(uint8_t *p, uint32_t value)
{
    for (unsigned i = 0; i < 4; ++i)
        p[i] = static_cast<uint8_t>(value >> (i * 8));
}

static size_t beginReply(uint8_t *bytes, uint16_t type, uint32_t sequence,
                         uint32_t portId, uint8_t command)
{
    memset(bytes, 0, 512);
    set32(bytes, 20);
    set16(bytes + 4, type);
    set16(bytes + 6, 0);
    set32(bytes + 8, sequence);
    set32(bytes + 12, portId);
    bytes[16] = command;
    bytes[17] = 1;
    bytes[18] = bytes[19] = 0;
    return 20;
}

static size_t addAttribute(uint8_t *bytes, size_t offset, uint16_t type,
                           const void *value, size_t valueLength)
{
    const size_t length = 4 + valueLength;
    const size_t aligned = (length + 3) & ~size_t(3);
    set16(bytes + offset, static_cast<uint16_t>(length));
    set16(bytes + offset + 2, type);
    if (valueLength)
        memcpy(bytes + offset + 4, value, valueLength);
    if (aligned > length)
        memset(bytes + offset + length, 0, aligned - length);
    set32(bytes, static_cast<uint32_t>(offset + aligned));
    return offset + aligned;
}

static size_t familyReply(uint8_t *bytes, uint32_t sequence = 7,
                          uint32_t portId = 1234,
                          const char *familyName = "nl80211")
{
    size_t length = beginReply(bytes, kNlctrlFamilyId, sequence, portId,
                               kCtrlCmdNewFamily);
    const uint16_t familyId = 0x31;
    length = addAttribute(bytes, length, kCtrlAttrFamilyId, &familyId,
                          sizeof(familyId));
    length = addAttribute(bytes, length, kCtrlAttrFamilyName, familyName,
                          strlen(familyName) + 1);
    return length;
}

static size_t interfaceReply(uint8_t *bytes, uint32_t frequency = 2437,
                             uint32_t offsetKhz = 0,
                             uint32_t ifindex = 9,
                             const char *ifname = "mon0")
{
    size_t length = beginReply(bytes, 0x31, 8, 1234,
                               kNl80211CmdNewInterface);
    length = addAttribute(bytes, length, kNl80211AttrIfindex, &ifindex,
                          sizeof(ifindex));
    length = addAttribute(bytes, length, kNl80211AttrIfname, ifname,
                          strlen(ifname) + 1);
    length = addAttribute(bytes, length, kNl80211AttrWiphyFreq, &frequency,
                          sizeof(frequency));
    length = addAttribute(bytes, length, kNl80211AttrWiphyFreqOffset,
                          &offsetKhz, sizeof(offsetKhz));
    return length;
}

static void testFamilyIdentityAndBounds()
{
    uint8_t bytes[512]{};
    const SourceAddress kernel{0, 0};
    uint16_t familyId = 0;
    const size_t length = familyReply(bytes);
    assert(parseFamilyReply(bytes, length, kernel, 7, 1234,
                            "nl80211", &familyId) == Status::kOk);
    assert(familyId == 0x31);

    SourceAddress wrongSource{42, 0};
    assert(parseFamilyReply(bytes, length, wrongSource, 7, 1234,
                            "nl80211", &familyId) == Status::kWrongSource);
    wrongSource = SourceAddress{0, 1};
    assert(parseFamilyReply(bytes, length, wrongSource, 7, 1234,
                            "nl80211", &familyId) == Status::kWrongSource);
    assert(parseFamilyReply(bytes, length, kernel, 6, 1234,
                            "nl80211", &familyId) == Status::kWrongSequence);
    assert(parseFamilyReply(bytes, length, kernel, 7, 1235,
                            "nl80211", &familyId) == Status::kWrongPortId);
    assert(parseFamilyReply(bytes, length - 1, kernel, 7, 1234,
                            "nl80211", &familyId) == Status::kInvalidLength);

    set32(bytes + 12, 1235);
    assert(parseFamilyReply(bytes, length, kernel, 7, 1234,
                            "nl80211", &familyId) == Status::kWrongPortId);
    familyReply(bytes);
    set32(bytes, 19);
    assert(parseFamilyReply(bytes, length, kernel, 7, 1234,
                            "nl80211", &familyId) == Status::kInvalidLength);
    familyReply(bytes);
    bytes[16] = 0xff;
    assert(parseFamilyReply(bytes, length, kernel, 7, 1234,
                            "nl80211", &familyId) == Status::kWrongCommand);
}

static void testFamilyAttributesFailClosed()
{
    uint8_t bytes[512]{};
    const SourceAddress kernel{0, 0};
    uint16_t familyId = 0;
    size_t length = familyReply(bytes, 7, 1234, "other");
    assert(parseFamilyReply(bytes, length, kernel, 7, 1234,
                            "nl80211", &familyId) == Status::kFamilyNameMismatch);

    length = beginReply(bytes, kNlctrlFamilyId, 7, 1234, kCtrlCmdNewFamily);
    const uint16_t id = 0x31;
    length = addAttribute(bytes, length, kCtrlAttrFamilyId, &id, sizeof(id));
    length = addAttribute(bytes, length, kCtrlAttrFamilyId, &id, sizeof(id));
    const char name[] = "nl80211";
    length = addAttribute(bytes, length, kCtrlAttrFamilyName, name, sizeof(name));
    assert(parseFamilyReply(bytes, length, kernel, 7, 1234,
                            "nl80211", &familyId) == Status::kDuplicateAttribute);

    length = beginReply(bytes, kNlctrlFamilyId, 7, 1234, kCtrlCmdNewFamily);
    length = addAttribute(bytes, length, kCtrlAttrFamilyName, name, sizeof(name));
    assert(parseFamilyReply(bytes, length, kernel, 7, 1234,
                            "nl80211", &familyId) == Status::kMissingAttribute);

    length = familyReply(bytes);
    set16(bytes + 20, 3); // family ID attribute cannot be shorter than its header.
    assert(parseFamilyReply(bytes, length, kernel, 7, 1234,
                            "nl80211", &familyId) == Status::kMalformedAttribute);
}

static void testInterfaceChannelAndIdentity()
{
    uint8_t bytes[512]{};
    const SourceAddress kernel{0, 0};
    uint32_t frequency = 0, offset = 99;
    size_t length = interfaceReply(bytes);
    assert(parseInterfaceReply(bytes, length, kernel, 0x31, 8, 1234,
        9, "mon0", &frequency, &offset) == Status::kOk);
    assert(frequency == 2437 && offset == 0);

    length = interfaceReply(bytes, 2412);
    assert(parseInterfaceReply(bytes, length, kernel, 0x31, 8, 1234,
        9, "mon0", &frequency, &offset) == Status::kFrequencyMismatch);
    length = interfaceReply(bytes, 2437, 1000);
    assert(parseInterfaceReply(bytes, length, kernel, 0x31, 8, 1234,
        9, "mon0", &frequency, &offset) == Status::kFrequencyMismatch);
    length = interfaceReply(bytes, 2437, 0, 10);
    assert(parseInterfaceReply(bytes, length, kernel, 0x31, 8, 1234,
        9, "mon0", &frequency, &offset) == Status::kIfindexMismatch);
    length = interfaceReply(bytes, 2437, 0, 9, "mon1");
    assert(parseInterfaceReply(bytes, length, kernel, 0x31, 8, 1234,
        9, "mon0", &frequency, &offset) == Status::kIfnameMismatch);

    length = beginReply(bytes, 0x31, 8, 1234, kNl80211CmdNewInterface);
    const uint32_t index = 9, channel = 2437;
    const char name[] = "mon0";
    length = addAttribute(bytes, length, kNl80211AttrIfindex, &index, sizeof(index));
    length = addAttribute(bytes, length, kNl80211AttrIfname, name, sizeof(name));
    assert(parseInterfaceReply(bytes, length, kernel, 0x31, 8, 1234,
        9, "mon0", &frequency, &offset) == Status::kMissingAttribute);

    length = interfaceReply(bytes);
    set16(bytes + 20, 3); // invalid short IFINDEX nla length.
    assert(parseInterfaceReply(bytes, length, kernel, 0x31, 8, 1234,
        9, "mon0", &frequency, &offset) == Status::kMalformedAttribute);
    (void)channel;
}

static void testNoncePolicyMatchesReturnHelper()
{
    uint8_t nonce[8] = {1,2,3,4,5,6,7,8};
    assert(nonceUsable(nonce));
    memset(nonce, 0, sizeof(nonce));
    assert(!nonceUsable(nonce));
    const uint8_t oldMarker[8] = {'T','0','8','6','R','X','0','1'};
    assert(!nonceUsable(oldMarker));
    assert(!nonceUsable(nullptr));
}

int main()
{
    testFamilyIdentityAndBounds();
    testFamilyAttributesFailClosed();
    testInterfaceChannelAndIdentity();
    testNoncePolicyMatchesReturnHelper();
    puts("PASS: bounded nl80211 family/interface replies, exact channel, fresh nonce");
}
