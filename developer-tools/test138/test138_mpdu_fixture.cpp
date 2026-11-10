// SPDX-License-Identifier: GPL-2.0-only
// Offline fixture: production Known-Answer transform plus production MPDU encoder.
#include "awdl_data_frame.hpp"
#include "awdl_qm_no_known_answer.hpp"

#include <cassert>
#include <cstdint>
#include <cstring>
#include <iostream>

namespace {

void putBe16(uint8_t *bytes, uint16_t value)
{
    bytes[0] = static_cast<uint8_t>(value >> 8);
    bytes[1] = static_cast<uint8_t>(value);
}

void putBe32(uint8_t *bytes, uint32_t value)
{
    bytes[0] = static_cast<uint8_t>(value >> 24);
    bytes[1] = static_cast<uint8_t>(value >> 16);
    bytes[2] = static_cast<uint8_t>(value >> 8);
    bytes[3] = static_cast<uint8_t>(value);
}

uint32_t addWords(uint32_t sum, const uint8_t *bytes, size_t length)
{
    size_t offset = 0;
    while (offset + 1 < length) {
        sum += (static_cast<uint16_t>(bytes[offset]) << 8) | bytes[offset + 1];
        offset += 2;
    }
    if (offset < length)
        sum += static_cast<uint32_t>(bytes[offset]) << 8;
    return sum;
}

uint16_t udpChecksum(const uint8_t *ipv6, const uint8_t *udp, size_t length)
{
    uint32_t sum = addWords(0, ipv6 + 8, 32);
    sum += static_cast<uint16_t>(length >> 16);
    sum += static_cast<uint16_t>(length);
    sum += 17;
    sum = addWords(sum, udp, length);
    while (sum >> 16)
        sum = (sum & 0xffffu) + (sum >> 16);
    const uint16_t result = static_cast<uint16_t>(~sum);
    return result ? result : 0xffff;
}

size_t makeKnownAnswerPacket(uint8_t *ipv6)
{
    constexpr size_t length = 112;
    memset(ipv6, 0, length);
    ipv6[0] = 0x60;
    putBe16(ipv6 + 4, 72);
    ipv6[6] = 17;
    ipv6[7] = 255;
    ipv6[8] = 0xfe;
    ipv6[9] = 0x80;
    // 02:00:00:00:00:01 -> modified EUI-64 00:00:00:ff:fe:00:00:01.
    ipv6[16] = 0x00;
    ipv6[17] = 0x00;
    ipv6[18] = 0x00;
    ipv6[19] = 0xff;
    ipv6[20] = 0xfe;
    ipv6[21] = 0x00;
    ipv6[22] = 0x00;
    ipv6[23] = 0x01;
    ipv6[24] = 0xff;
    ipv6[25] = 0x02;
    ipv6[39] = 0xfb;

    uint8_t *udp = ipv6 + 40;
    putBe16(udp, 5353);
    putBe16(udp + 2, 5353);
    putBe16(udp + 4, 72);
    uint8_t *dns = udp + 8;
    putBe16(dns, 0);
    putBe16(dns + 2, 0);
    putBe16(dns + 4, 1);
    putBe16(dns + 6, 1);
    putBe16(dns + 8, 0);
    putBe16(dns + 10, 0);
    static const uint8_t question[] = {
        8, '_','a','i','r','d','r','o','p',
        4, '_','t','c','p', 5, 'l','o','c','a','l', 0,
        0,12, 0,1
    };
    memcpy(dns + 12, question, sizeof(question));
    size_t offset = 12 + sizeof(question);
    dns[offset++] = 0xc0;
    dns[offset++] = 0x0c;
    putBe16(dns + offset, 12);
    putBe16(dns + offset + 2, 1);
    putBe32(dns + offset + 4, 120);
    putBe16(dns + offset + 8, 15);
    offset += 10;
    dns[offset++] = 12;
    memcpy(dns + offset, "abcdefghijkl", 12);
    offset += 12;
    dns[offset++] = 0xc0;
    dns[offset++] = 0x0c;
    assert(offset == 64);
    putBe16(udp + 6, udpChecksum(ipv6, udp, 72));
    return length;
}

void emitHex(const char *name, const uint8_t *bytes, size_t length)
{
    static const char digits[] = "0123456789abcdef";
    std::cout << name << '=';
    for (size_t index = 0; index < length; ++index)
        std::cout << digits[bytes[index] >> 4] << digits[bytes[index] & 0x0f];
    std::cout << '\n';
}

} // namespace

int main()
{
    uint8_t ipv6[128]{};
    size_t ipv6Length = makeKnownAnswerPacket(ipv6);
    assert(ipv6Length == 112);
    assert(NativeAwdlData::txObservationChecksumValid(ipv6, ipv6 + 40, 72));
    assert(NativeAwdlData::txObservationReadBe16(ipv6 + 40 + 8 + 6) == 1);

    NativeAwdlData::EncodeInput input{};
    const uint8_t destination[6] = {0x33, 0x33, 0, 0, 0, 0xfb};
    const uint8_t source[6] = {0x02, 0, 0, 0, 0, 1};
    memcpy(input.destinationAddress, destination, sizeof(destination));
    memcpy(input.sourceAddress, source, sizeof(source));
    input.wifiSequenceNumber = 2;
    input.awdlSequenceNumber = 9;
    input.ipv6Packet = ipv6;
    input.ipv6Length = ipv6Length;
    uint8_t originalMpdu[256]{};
    size_t originalMpduLength = 0;
    assert(NativeAwdlData::encodeIpv6DataMpdu(
        &input, originalMpdu, sizeof(originalMpdu), &originalMpduLength) ==
        NativeAwdlData::Status::Ok);
    assert(originalMpduLength == 152);

    assert(NativeAwdlData::stripAirdropQmKnownAnswer(ipv6, &ipv6Length));
    assert(ipv6Length == 85);
    assert(NativeAwdlData::txObservationReadBe16(ipv6 + 40 + 8 + 6) == 0);
    assert(NativeAwdlData::txObservationChecksumValid(ipv6, ipv6 + 40, 45));

    input.ipv6Length = ipv6Length;
    uint8_t mpdu[256]{};
    size_t mpduLength = 0;
    assert(NativeAwdlData::encodeIpv6DataMpdu(
        &input, mpdu, sizeof(mpdu), &mpduLength) == NativeAwdlData::Status::Ok);
    assert(mpduLength == 125);
    NativeAwdlData::DecodedFrame decoded{};
    assert(NativeAwdlData::decodeIpv6DataMpdu(
        mpdu, mpduLength, &decoded) == NativeAwdlData::Status::Ok);
    assert(decoded.frameControl == 0x0008);
    assert(decoded.wifiSequenceNumber == 2);
    assert(decoded.packetCount == 1);
    assert(decoded.packets[0].awdlSequenceNumber == 9);

    std::cout << "original_ipv6_length=112\n"
              << "original_an_count=1\n"
              << "final_ipv6_length=" << ipv6Length << '\n'
              << "final_udp_length=45\n"
              << "final_dns_length=37\n"
              << "final_an_count=0\n"
              << "final_mpdu_length=" << mpduLength << '\n'
              << "awdl_sequence=9\n";
    emitHex("original_mpdu_hex", originalMpdu, originalMpduLength);
    emitHex("mpdu_hex", mpdu, mpduLength);
    return 0;
}
