// SPDX-License-Identifier: GPL-2.0-only
#include "awdl_qm_no_known_answer.hpp"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

namespace {

constexpr size_t kIpv6Length = 112;
constexpr size_t kQuestionOffset = 40 + 8 + 12;
constexpr size_t kQuestionSectionLength = 21 + 4;
constexpr size_t kAnswerOffset = 40 + 8 + 12 + kQuestionSectionLength;
constexpr size_t kStrippedLength = 85;

void putBe16(uint8_t *bytes, uint16_t value)
{
    bytes[0] = static_cast<uint8_t>(value >> 8);
    bytes[1] = static_cast<uint8_t>(value);
}

uint16_t readBe16(const uint8_t *bytes)
{
    return static_cast<uint16_t>((static_cast<uint16_t>(bytes[0]) << 8) |
                                 bytes[1]);
}

uint32_t addWords(uint32_t sum, const uint8_t *bytes, size_t length)
{
    size_t offset = 0;
    while (offset + 1 < length) {
        sum += readBe16(bytes + offset);
        offset += 2;
    }
    if (offset < length)
        sum += static_cast<uint32_t>(bytes[offset]) << 8;
    return sum;
}

uint16_t makeChecksum(const uint8_t *ipv6, uint8_t *udp, size_t udpLength)
{
    uint32_t sum = 0;
    sum = addWords(sum, ipv6 + 8, 32);
    sum += static_cast<uint16_t>((udpLength >> 16) & 0xffffu);
    sum += static_cast<uint16_t>(udpLength & 0xffffu);
    sum += 17u;
    sum = addWords(sum, udp, udpLength);
    while (sum >> 16)
        sum = (sum & 0xffffu) + (sum >> 16);
    const uint16_t result = static_cast<uint16_t>(~sum);
    return result == 0 ? 0xffffu : result;
}

size_t makePacket(uint8_t *ipv6)
{
    memset(ipv6, 0, 128);
    ipv6[0] = 0x60;
    putBe16(ipv6 + 4, 72);
    ipv6[6] = 17;
    ipv6[7] = 255;
    ipv6[8] = 0xfe;
    ipv6[9] = 0x80;
    ipv6[23] = 1;
    ipv6[24] = 0xff;
    ipv6[25] = 0x02;
    ipv6[39] = 0xfb;

    uint8_t *udp = ipv6 + 40;
    putBe16(udp, 5353);
    putBe16(udp + 2, 5353);
    putBe16(udp + 4, 72);
    uint8_t *dns = udp + 8;
    putBe16(dns, 0);       // mDNS ID
    putBe16(dns + 2, 0);   // flags
    putBe16(dns + 4, 1);   // QDCOUNT
    putBe16(dns + 6, 1);   // ANCOUNT
    putBe16(dns + 8, 0);   // NSCOUNT
    putBe16(dns + 10, 0);  // ARCOUNT

    static const uint8_t kAirdropName[] = {
        8, '_','a','i','r','d','r','o','p',
        4, '_','t','c','p',
        5, 'l','o','c','a','l', 0
    };
    memcpy(dns + 12, kAirdropName, sizeof(kAirdropName));
    size_t offset = 12 + sizeof(kAirdropName);
    putBe16(dns + offset, 12); // PTR
    putBe16(dns + offset + 2, 1); // IN, QM (no QU bit)
    offset += 4;

    dns[offset++] = 0xc0;
    dns[offset++] = 0x0c; // Answer owner compresses to the question name.
    putBe16(dns + offset, 12); // PTR
    putBe16(dns + offset + 2, 1); // IN, no cache-flush bit
    dns[offset + 4] = 0;
    dns[offset + 5] = 0;
    dns[offset + 6] = 0;
    dns[offset + 7] = 120; // Nonzero Known Answer TTL.
    putBe16(dns + offset + 8, 15);
    offset += 10;
    dns[offset++] = 12;
    memcpy(dns + offset, "abcdefghijkl", 12);
    offset += 12;
    dns[offset++] = 0xc0;
    dns[offset++] = 0x0c; // PTR target uses a legal backward pointer too.
    assert(offset == 64);

    udp[6] = 0;
    udp[7] = 0;
    const uint16_t checksum = makeChecksum(ipv6, udp, 72);
    putBe16(udp + 6, checksum);
    return kIpv6Length;
}

void expectRejectedWithoutMutation(uint8_t *packet, size_t length)
{
    uint8_t before[128];
    memcpy(before, packet, sizeof(before));
    size_t actualLength = length;
    assert(!NativeAwdlData::stripAirdropQmKnownAnswer(packet, &actualLength));
    assert(actualLength == length);
    assert(memcmp(before, packet, sizeof(before)) == 0);
}

void testSuccessfulStrip()
{
    uint8_t packet[128]{};
    uint8_t before[128]{};
    size_t length = makePacket(packet);
    memcpy(before, packet, sizeof(before));
    assert(length == kIpv6Length);
    assert(NativeAwdlData::txObservationChecksumValid(
        packet, packet + 40, 72));

    assert(NativeAwdlData::stripAirdropQmKnownAnswer(packet, &length));
    assert(length == kStrippedLength);
    assert(readBe16(packet + 4) == 45);
    assert(readBe16(packet + 40 + 4) == 45);
    assert(readBe16(packet + 40 + 8 + 4) == 1);
    assert(readBe16(packet + 40 + 8 + 6) == 0);
    assert(readBe16(packet + 40 + 8 + 8) == 0);
    assert(readBe16(packet + 40 + 8 + 10) == 0);
    assert(memcmp(packet + kQuestionOffset, before + kQuestionOffset,
                  kQuestionSectionLength) == 0);
    assert(NativeAwdlData::txObservationChecksumValid(
        packet, packet + 40, 45));
    for (size_t i = length; i < sizeof(packet); ++i)
        assert(packet[i] == 0);

    const auto observed = NativeAwdlData::observeMdnsSupportedServiceQuery(
        packet, packet + 40, 45, NativeAwdlData::UdpChecksumStatus::Valid);
    assert(observed.queryClass == NativeAwdlData::MdnsQueryClass::QmMulticast);
    assert(observed.questionCount == 1);
    assert(observed.targetPtrInQuestionCount == 1);
    assert(observed.quQuestionMask == 0);
}

void testStrictBoundariesAndNoMutation()
{
    uint8_t packet[128]{};
    size_t length = makePacket(packet);

    makePacket(packet);
    putBe16(packet + 40 + 8, 1); // mDNS identifier must be zero.
    expectRejectedWithoutMutation(packet, length);

    makePacket(packet);
    putBe16(packet + 40 + 8 + 6, 0); // ANCOUNT=0 is not a transform success.
    expectRejectedWithoutMutation(packet, length);

    makePacket(packet);
    putBe16(packet + 40 + 8 + 6, 2);
    expectRejectedWithoutMutation(packet, length);

    makePacket(packet);
    putBe16(packet + 40 + 8 + 8, 1); // No authority section accepted.
    expectRejectedWithoutMutation(packet, length);

    makePacket(packet);
    putBe16(packet + 40 + 8 + 10, 1); // No additional section accepted.
    expectRejectedWithoutMutation(packet, length);

    makePacket(packet);
    putBe16(packet + 40 + 8 + 2, 0x0100); // Flags must be exactly zero.
    expectRejectedWithoutMutation(packet, length);

    makePacket(packet);
    putBe16(packet + 40 + 8 + 12 + 21 + 2, 0x8001); // QU question.
    expectRejectedWithoutMutation(packet, length);

    makePacket(packet);
    packet[kAnswerOffset] = 0xc0;
    packet[kAnswerOffset + 1] = 0x00; // Wrong answer owner.
    expectRejectedWithoutMutation(packet, length);

    makePacket(packet);
    putBe16(packet + kAnswerOffset + 2, 1); // A RR, not PTR.
    expectRejectedWithoutMutation(packet, length);

    makePacket(packet);
    putBe16(packet + kAnswerOffset + 4, 0x8001); // Cache-flush class rejected.
    expectRejectedWithoutMutation(packet, length);

    makePacket(packet);
    memset(packet + kAnswerOffset + 6, 0, 4); // TTL zero is not a Known Answer.
    expectRejectedWithoutMutation(packet, length);

    makePacket(packet);
    packet[40 + 6] = 0; // Extension header / non-direct UDP.
    expectRejectedWithoutMutation(packet, length);

    makePacket(packet);
    packet[7] = 64; // mDNS over IPv6 requires hop limit 255.
    expectRejectedWithoutMutation(packet, length);

    makePacket(packet);
    packet[40 + 6] = packet[40 + 7] = 0; // IPv6 UDP checksum cannot be zero.
    expectRejectedWithoutMutation(packet, length);

    makePacket(packet);
    packet[40 + 8 + 63] ^= 1; // The original UDP checksum is now invalid.
    expectRejectedWithoutMutation(packet, length);

    makePacket(packet);
    putBe16(packet + 40 + 4, 71); // IPv6/UDP lengths disagree.
    expectRejectedWithoutMutation(packet, length);

    makePacket(packet);
    packet[kAnswerOffset + 25] = 0xc0;
    packet[kAnswerOffset + 26] = 0xff; // Forward/out-of-range PTR target.
    // Restore a valid checksum so rejection exercises DNS compression.
    packet[40 + 6] = packet[40 + 7] = 0;
    putBe16(packet + 40 + 6, makeChecksum(packet, packet + 40, 72));
    expectRejectedWithoutMutation(packet, length);

    makePacket(packet);
    putBe16(packet + kAnswerOffset + 10, 1);
    packet[kAnswerOffset + 12] = 0; // A root name is not a PTR target.
    putBe16(packet + 4, 58);
    putBe16(packet + 40 + 4, 58);
    memset(packet + 98, 0, sizeof(packet) - 98);
    packet[40 + 6] = packet[40 + 7] = 0;
    putBe16(packet + 40 + 6, makeChecksum(packet, packet + 40, 58));
    expectRejectedWithoutMutation(packet, 98);

    makePacket(packet);
    expectRejectedWithoutMutation(packet, length - 1); // Truncated input.
}

} // namespace

int main()
{
    testSuccessfulStrip();
    testStrictBoundariesAndNoMutation();
    puts("Test138 QM Known Answer strip: success transform and 18 fail-closed boundaries passed");
    return 0;
}
