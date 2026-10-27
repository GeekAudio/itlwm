// SPDX-License-Identifier: GPL-2.0-only
#ifndef NATIVE_AWDL_DATA_TX_OBSERVATION_HPP
#define NATIVE_AWDL_DATA_TX_OBSERVATION_HPP

#include <stddef.h>
#include <stdint.h>

namespace NativeAwdlData {

enum class UdpChecksumStatus : uint8_t {
    NotDirectUdp = 0,
    Valid = 1,
    Invalid = 2,
    Malformed = 3
};

// Numeric-only facts from the actual BSD Ethernet packet immediately before
// it is encoded as an AWDL MPDU. No address, payload, or checksum bytes escape.
struct TxObservation {
    uint32_t ethernetLength;
    uint32_t ipv6Length;
    uint32_t udpLength;
    uint8_t ipv6NextHeader;
    uint8_t sourceIsLinkLocal;
    uint8_t sourceEui64MatchesOwn;
    uint8_t udpHasMdnsPort;
    uint8_t ipv6DestinationIsMulticast;
    uint8_t ethernetMulticastMappingMatches;
    UdpChecksumStatus udpChecksumStatus;
    uint8_t ipv6PacketWellFormed;
};

struct TxObservationDelta {
    uint8_t checksumStatusBit;
    uint8_t sourceEui64Mismatch;
    uint8_t multicastMappingMismatch;
    uint8_t malformed;
};

inline TxObservationDelta summarizeTxObservation(const TxObservation &observation)
{
    TxObservationDelta delta{};
    const uint8_t status = static_cast<uint8_t>(observation.udpChecksumStatus);
    if (status < 8)
        delta.checksumStatusBit = static_cast<uint8_t>(1u << status);
    delta.sourceEui64Mismatch = observation.ipv6PacketWellFormed &&
        observation.sourceIsLinkLocal && !observation.sourceEui64MatchesOwn;
    delta.multicastMappingMismatch = observation.ipv6PacketWellFormed &&
        observation.ipv6DestinationIsMulticast &&
        !observation.ethernetMulticastMappingMatches;
    delta.malformed = !observation.ipv6PacketWellFormed ||
        observation.udpChecksumStatus == UdpChecksumStatus::Malformed;
    return delta;
}

inline uint16_t txObservationReadBe16(const uint8_t *bytes)
{
    return static_cast<uint16_t>(
        (static_cast<uint16_t>(bytes[0]) << 8) | bytes[1]);
}

inline uint32_t txObservationAddWords(uint32_t sum, const uint8_t *bytes,
                                     size_t length)
{
    size_t offset = 0;
    while (offset + 1 < length) {
        sum += txObservationReadBe16(bytes + offset);
        offset += 2;
    }
    if (offset < length)
        sum += static_cast<uint32_t>(bytes[offset]) << 8;
    return sum;
}

inline bool txObservationChecksumValid(const uint8_t *ipv6,
                                       const uint8_t *udp,
                                       size_t udpLength)
{
    uint32_t sum = 0;
    sum = txObservationAddWords(sum, ipv6 + 8, 32); // IPv6 source + destination
    sum += static_cast<uint16_t>((udpLength >> 16) & 0xffffu);
    sum += static_cast<uint16_t>(udpLength & 0xffffu);
    sum += 17u; // zero/zero/zero/next-header=UDP
    sum = txObservationAddWords(sum, udp, udpLength);
    while (sum >> 16)
        sum = (sum & 0xffffu) + (sum >> 16);
    return (sum & 0xffffu) == 0xffffu;
}

inline TxObservation observeAwdlTxPacket(const uint8_t *ethernet,
                                         size_t ethernetLength,
                                         const uint8_t ownMac[6])
{
    TxObservation result{};
    result.ethernetLength = ethernetLength > UINT32_MAX
        ? UINT32_MAX : static_cast<uint32_t>(ethernetLength);
    result.udpChecksumStatus = UdpChecksumStatus::NotDirectUdp;

    constexpr size_t kEthernetHeaderLength = 14;
    constexpr size_t kIpv6HeaderLength = 40;
    if (!ethernet || !ownMac || ethernetLength <
            kEthernetHeaderLength + kIpv6HeaderLength ||
        ethernet[12] != 0x86 || ethernet[13] != 0xdd)
        return result;

    const uint8_t *ipv6 = ethernet + kEthernetHeaderLength;
    if ((ipv6[0] >> 4) != 6)
        return result;

    const size_t ipv6PayloadLength = txObservationReadBe16(ipv6 + 4);
    const size_t expectedIpv6Length = kIpv6HeaderLength + ipv6PayloadLength;
    if (expectedIpv6Length != ethernetLength - kEthernetHeaderLength)
        return result;

    result.ipv6Length = static_cast<uint32_t>(expectedIpv6Length);
    result.ipv6PacketWellFormed = 1;
    const uint8_t *source = ipv6 + 8;
    const uint8_t *destination = ipv6 + 24;
    const uint8_t *sourceEui64 = source + 8;
    const uint8_t expectedEui64[8] = {
        static_cast<uint8_t>(ownMac[0] ^ 0x02), ownMac[1], ownMac[2],
        0xff, 0xfe, ownMac[3], ownMac[4], ownMac[5]
    };
    const bool linkLocal = source[0] == 0xfe && (source[1] & 0xc0) == 0x80;
    result.sourceIsLinkLocal = linkLocal;
    uint8_t eui64Difference = 0;
    for (size_t i = 0; i < sizeof(expectedEui64); ++i)
        eui64Difference |= sourceEui64[i] ^ expectedEui64[i];
    result.sourceEui64MatchesOwn = linkLocal && eui64Difference == 0;

    result.ipv6NextHeader = ipv6[6];
    result.ipv6DestinationIsMulticast = destination[0] == 0xff;
    if (result.ipv6DestinationIsMulticast) {
        const uint8_t expectedMulticastMac[6] = {
            0x33, 0x33, destination[12], destination[13],
            destination[14], destination[15]
        };
        uint8_t difference = 0;
        for (size_t i = 0; i < sizeof(expectedMulticastMac); ++i)
            difference |= ethernet[i] ^ expectedMulticastMac[i];
        result.ethernetMulticastMappingMatches = difference == 0;
    }

    // Extension headers are intentionally not walked here. Their presence is
    // unsupported observation, not evidence of a bad UDP checksum.
    if (ipv6[6] != 17)
        return result;

    if (ipv6PayloadLength < 8) {
        result.udpChecksumStatus = UdpChecksumStatus::Malformed;
        return result;
    }
    const uint8_t *udp = ipv6 + kIpv6HeaderLength;
    const size_t udpLength = txObservationReadBe16(udp + 4);
    result.udpLength = static_cast<uint32_t>(udpLength);
    if (udpLength < 8 || udpLength != ipv6PayloadLength) {
        result.udpChecksumStatus = UdpChecksumStatus::Malformed;
        return result;
    }

    const uint16_t sourcePort = txObservationReadBe16(udp);
    const uint16_t destinationPort = txObservationReadBe16(udp + 2);
    // The packet body is opaque here; this only records a port-5353 signal.
    result.udpHasMdnsPort = sourcePort == 5353 || destinationPort == 5353;
    const uint16_t checksum = txObservationReadBe16(udp + 6);
    result.udpChecksumStatus = checksum != 0 &&
            txObservationChecksumValid(ipv6, udp, udpLength)
        ? UdpChecksumStatus::Valid : UdpChecksumStatus::Invalid;
    return result;
}

} // namespace NativeAwdlData

#endif // NATIVE_AWDL_DATA_TX_OBSERVATION_HPP
