// SPDX-License-Identifier: GPL-2.0-only
#include "../awdl_data_frame.hpp"
#include "../awdl_data_tx_observation.hpp"

#include <assert.h>
#include <stdint.h>
#include <string.h>

namespace {

uint16_t readBe16(const uint8_t *bytes)
{
    return static_cast<uint16_t>((uint16_t(bytes[0]) << 8) | bytes[1]);
}

void putBe16(uint8_t *bytes, uint16_t value)
{
    bytes[0] = static_cast<uint8_t>(value >> 8);
    bytes[1] = static_cast<uint8_t>(value);
}

uint32_t addWords(uint32_t sum, const uint8_t *bytes, size_t length)
{
    size_t offset = 0;
    while (offset + 1 < length) {
        sum += readBe16(bytes + offset);
        offset += 2;
    }
    if (offset < length)
        sum += uint32_t(bytes[offset]) << 8;
    return sum;
}

uint16_t makeUdpChecksum(const uint8_t *ipv6, const uint8_t *udp,
                         size_t udpLength)
{
    uint32_t sum = addWords(0, ipv6 + 8, 32);
    sum += static_cast<uint16_t>((udpLength >> 16) & 0xffffu);
    sum += static_cast<uint16_t>(udpLength & 0xffffu);
    sum += 17;
    sum = addWords(sum, udp, udpLength);
    while (sum >> 16)
        sum = (sum & 0xffffu) + (sum >> 16);
    return static_cast<uint16_t>(~sum);
}

constexpr uint8_t kOwnMac[6] = {0x02, 0x11, 0x22, 0x33, 0x44, 0x55};
constexpr size_t kEthernetLength = 14 + 40 + 11;

void makePacket(uint8_t *packet)
{
    memset(packet, 0, kEthernetLength);
    const uint8_t destinationMac[6] = {0x33, 0x33, 0x00, 0x00, 0x00, 0xfb};
    memcpy(packet, destinationMac, sizeof(destinationMac));
    memcpy(packet + 6, kOwnMac, sizeof(kOwnMac));
    packet[12] = 0x86;
    packet[13] = 0xdd;

    uint8_t *ipv6 = packet + 14;
    ipv6[0] = 0x60;
    putBe16(ipv6 + 4, 11);
    ipv6[6] = 17;
    ipv6[7] = 255;
    const uint8_t source[16] = {
        0xfe, 0x80, 0, 0, 0, 0, 0, 0,
        0x00, 0x11, 0x22, 0xff, 0xfe, 0x33, 0x44, 0x55
    };
    const uint8_t destination[16] = {
        0xff, 0x02, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0xfb
    };
    memcpy(ipv6 + 8, source, sizeof(source));
    memcpy(ipv6 + 24, destination, sizeof(destination));

    uint8_t *udp = ipv6 + 40;
    putBe16(udp, 49152);
    putBe16(udp + 2, 5353);
    putBe16(udp + 4, 11);
    udp[8] = 1;
    udp[9] = 2;
    udp[10] = 3;
    putBe16(udp + 6, makeUdpChecksum(ipv6, udp, 11));
}

void testCandidateClassification()
{
    uint8_t frame[64]{};
    frame[0] = 0x08; // ordinary data
    memcpy(frame + 16, NativeAwdlData::kAwdlBssid, 6);
    assert(NativeAwdlData::isAwdlDataCandidate(frame, 24));

    frame[1] = 0x40; // protected payload; visible header remains a candidate
    assert(NativeAwdlData::isAwdlDataCandidate(frame, 24));
    frame[0] = 0x88; // QoS data requires its two-byte QoS control header
    assert(!NativeAwdlData::isAwdlDataCandidate(frame, 24));
    assert(NativeAwdlData::isAwdlDataCandidate(frame, 26));
    frame[1] = 0x41; // To-DS is outside the AWDL no-DS candidate shape
    assert(!NativeAwdlData::isAwdlDataCandidate(frame, 26));
    frame[1] = 0;
    frame[16] ^= 1;
    assert(!NativeAwdlData::isAwdlDataCandidate(frame, 26));
    assert(!NativeAwdlData::isAwdlDataCandidate(frame, 23));
    assert(!NativeAwdlData::isAwdlDataCandidate(nullptr, 64));
}

void testPacketObservation()
{
    uint8_t packet[kEthernetLength]{};
    makePacket(packet);
    assert(readBe16(packet + 14 + 40 + 6) == 0xc2d4);
    auto result = NativeAwdlData::observeAwdlTxPacket(
        packet, sizeof(packet), kOwnMac);
    assert(result.ipv6PacketWellFormed == 1);
    assert(result.ethernetLength == sizeof(packet));
    assert(result.ipv6Length == 51);
    assert(result.udpLength == 11);
    assert(result.ipv6NextHeader == 17);
    assert(result.sourceIsLinkLocal == 1);
    assert(result.sourceEui64MatchesOwn == 1);
    assert(result.udpHasMdnsPort == 1);
    assert(result.ipv6DestinationIsMulticast == 1);
    assert(result.ethernetMulticastMappingMatches == 1);
    assert(result.udpChecksumStatus ==
           NativeAwdlData::UdpChecksumStatus::Valid);
    auto delta = NativeAwdlData::summarizeTxObservation(result);
    assert(delta.checksumStatusBit == (1u << 1));
    assert(delta.sourceEui64Mismatch == 0);
    assert(delta.multicastMappingMismatch == 0);
    assert(delta.malformed == 0);

    packet[14 + 40 + 6] ^= 1;
    result = NativeAwdlData::observeAwdlTxPacket(
        packet, sizeof(packet), kOwnMac);
    assert(result.udpChecksumStatus ==
           NativeAwdlData::UdpChecksumStatus::Invalid);
    delta = NativeAwdlData::summarizeTxObservation(result);
    assert(delta.checksumStatusBit == (1u << 2));

    makePacket(packet);
    packet[14 + 6] = 0; // IPv6 extension header: no checksum verdict.
    result = NativeAwdlData::observeAwdlTxPacket(
        packet, sizeof(packet), kOwnMac);
    assert(result.udpChecksumStatus ==
           NativeAwdlData::UdpChecksumStatus::NotDirectUdp);
    delta = NativeAwdlData::summarizeTxObservation(result);
    assert(delta.checksumStatusBit == (1u << 0));
    assert(delta.malformed == 0);

    makePacket(packet);
    packet[0] = 0x32; // Incorrect IPv6 multicast Ethernet mapping.
    result = NativeAwdlData::observeAwdlTxPacket(
        packet, sizeof(packet), kOwnMac);
    assert(result.ethernetMulticastMappingMatches == 0);
    delta = NativeAwdlData::summarizeTxObservation(result);
    assert(delta.multicastMappingMismatch == 1);

    makePacket(packet);
    packet[14 + 8 + 15] ^= 1; // Wrong IPv6 source EUI-64.
    result = NativeAwdlData::observeAwdlTxPacket(
        packet, sizeof(packet), kOwnMac);
    assert(result.sourceEui64MatchesOwn == 0);
    delta = NativeAwdlData::summarizeTxObservation(result);
    assert(delta.sourceEui64Mismatch == 1);

    makePacket(packet);
    packet[14 + 8] = 0x20; // Global source: EUI-64 mismatch is not applicable.
    result = NativeAwdlData::observeAwdlTxPacket(
        packet, sizeof(packet), kOwnMac);
    delta = NativeAwdlData::summarizeTxObservation(result);
    assert(result.sourceIsLinkLocal == 0);
    assert(delta.sourceEui64Mismatch == 0);

    makePacket(packet);
    putBe16(packet + 14 + 40 + 4, 10); // UDP length differs from IPv6 payload.
    result = NativeAwdlData::observeAwdlTxPacket(
        packet, sizeof(packet), kOwnMac);
    delta = NativeAwdlData::summarizeTxObservation(result);
    assert(result.udpChecksumStatus == NativeAwdlData::UdpChecksumStatus::Malformed);
    assert(delta.checksumStatusBit == (1u << 3));
    assert(delta.malformed == 1);

    makePacket(packet);
    packet[14 + 4] = 0;
    packet[14 + 5] = 10; // IPv6 payload length no longer matches packet bytes.
    result = NativeAwdlData::observeAwdlTxPacket(
        packet, sizeof(packet), kOwnMac);
    assert(result.ipv6PacketWellFormed == 0);
    delta = NativeAwdlData::summarizeTxObservation(result);
    assert(delta.malformed == 1);

    for (size_t length = 0; length < sizeof(packet); ++length)
        (void)NativeAwdlData::observeAwdlTxPacket(packet, length, kOwnMac);
}

} // namespace

int main()
{
    testCandidateClassification();
    testPacketObservation();
}
