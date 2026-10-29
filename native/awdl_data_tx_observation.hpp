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

// Only identifies the on-wire DNS-SD query class. It does not claim a reply,
// peer identity, or AirDrop service discovery.
enum class MdnsQueryClass : uint8_t {
    Unknown = 0, // Unsupported/truncated DNS/IPv6 or invalid mDNS-port UDP.
    LegacyUnicastReply = 1,
    QuUnicastPreferred = 2,
    QmMulticast = 3,
    Other = 4 // Non-mDNS UDP or DNS outside the supported target query classes.
};

struct MdnsQueryObservation {
    MdnsQueryClass queryClass;
    uint8_t sourcePortIs5353;
    uint8_t destinationPortIs5353;
    uint8_t destinationIsFf02Fb;
    uint8_t headerParsed;
    uint8_t qr;
    uint8_t tc;
    uint16_t questionCount;
    uint16_t targetPtrInQuestionCount;
    uint8_t quQuestionMask;
};

inline uint16_t txObservationReadBe16(const uint8_t *bytes);

inline uint8_t mdnsAsciiLower(uint8_t value)
{
    return value >= 'A' && value <= 'Z'
        ? static_cast<uint8_t>(value + ('a' - 'A')) : value;
}

// Decode one possibly-compressed DNS name. All reads are length checked,
// labels are limited to 63 bytes, the expanded wire name to 255 bytes, pointer
// chains to 16, and total steps to 128. RFC compression pointers must point
// backwards, which also prevents loops without dynamic allocation.
inline bool parseMdnsQuestionName(const uint8_t *dns, size_t dnsLength,
                                  size_t *position, uint8_t *name,
                                  size_t nameCapacity, size_t *nameLength)
{
    if (!dns || !position || !name || !nameLength || *position >= dnsLength)
        return false;
    size_t cursor = *position;
    size_t consumed = 0;
    size_t output = 0;
    uint16_t pointerOffsets[16]{};
    size_t pointerCount = 0;
    unsigned steps = 0;
    bool jumped = false;
    while (steps++ < 128) {
        if (cursor >= dnsLength)
            return false;
        const uint8_t label = dns[cursor];
        if ((label & 0xc0u) == 0xc0u) {
            if (cursor + 2 > dnsLength)
                return false;
            const size_t target = (static_cast<size_t>(label & 0x3fu) << 8) |
                dns[cursor + 1];
            if (target >= cursor || target >= dnsLength || pointerCount >= 16)
                return false;
            for (size_t i = 0; i < pointerCount; ++i)
                if (pointerOffsets[i] == target)
                    return false;
            pointerOffsets[pointerCount++] = static_cast<uint16_t>(target);
            if (!jumped)
                consumed += 2;
            cursor = target;
            jumped = true;
            continue;
        }
        if ((label & 0xc0u) != 0 || label > 63 ||
            cursor + 1u + label > dnsLength || output + 1u + label > nameCapacity ||
            output + 1u + label > 255)
            return false;
        name[output++] = label;
        if (!jumped)
            consumed += 1u + label;
        ++cursor;
        if (label == 0) {
            *position += consumed;
            *nameLength = output;
            return true;
        }
        for (size_t i = 0; i < label; ++i)
            name[output++] = mdnsAsciiLower(dns[cursor + i]);
        cursor += label;
    }
    return false;
}

inline bool isAirdropPtrInName(const uint8_t *name, size_t length)
{
    static const uint8_t expected[] = {
        8, '_','a','i','r','d','r','o','p',
        4, '_','t','c','p',
        5, 'l','o','c','a','l', 0
    };
    if (length != sizeof(expected))
        return false;
    uint8_t difference = 0;
    for (size_t i = 0; i < sizeof(expected); ++i)
        difference |= name[i] ^ expected[i];
    return difference == 0;
}

inline MdnsQueryObservation observeMdnsAirdropQuery(
    const uint8_t *ipv6, const uint8_t *udp, size_t udpLength,
    UdpChecksumStatus checksumStatus)
{
    MdnsQueryObservation result{};
    result.queryClass = MdnsQueryClass::Unknown;
    if (!ipv6 || !udp || udpLength < 8 || udpLength > 65535)
        return result;

    const uint16_t sourcePort = txObservationReadBe16(udp);
    const uint16_t destinationPort = txObservationReadBe16(udp + 2);
    result.sourcePortIs5353 = sourcePort == 5353;
    result.destinationPortIs5353 = destinationPort == 5353;
    const uint8_t *destination = ipv6 + 24;
    bool group = destination[0] == 0xff && destination[1] == 0x02 &&
        destination[15] == 0xfb;
    for (size_t i = 2; i < 15; ++i)
        group = group && destination[i] == 0;
    result.destinationIsFf02Fb = group;
    if (!result.sourcePortIs5353 && !result.destinationPortIs5353) {
        result.queryClass = MdnsQueryClass::Other;
        return result;
    }

    const uint8_t *dns = udp + 8;
    const size_t dnsLength = udpLength - 8;
    if (dnsLength < 12)
        return result;
    const uint16_t flags = txObservationReadBe16(dns + 2);
    result.qr = static_cast<uint8_t>((flags >> 15) & 1u);
    result.tc = static_cast<uint8_t>((flags >> 9) & 1u);
    result.questionCount = txObservationReadBe16(dns + 4);
    result.headerParsed = 1;
    if (result.qr || ((flags >> 11) & 0x0fu) != 0 ||
        result.questionCount == 0) {
        result.queryClass = checksumStatus == UdpChecksumStatus::Valid
            ? MdnsQueryClass::Other : MdnsQueryClass::Unknown;
        return result;
    }
    if (result.questionCount > 8)
        return result; // Valid header, query analysis is outside the fixed bound.

    size_t offset = 12;
    bool allQuestionsTarget = true;
    bool quValue = false;
    bool haveQuValue = false;
    bool mixedQu = false;
    for (uint16_t i = 0; i < result.questionCount; ++i) {
        uint8_t name[255]{};
        size_t nameLength = 0;
        if (!parseMdnsQuestionName(dns, dnsLength, &offset, name,
                                   sizeof(name), &nameLength) ||
            offset + 4 > dnsLength)
            return result;
        const uint16_t type = txObservationReadBe16(dns + offset);
        const uint16_t qclass = txObservationReadBe16(dns + offset + 2);
        offset += 4;
        const bool qu = (qclass & 0x8000u) != 0;
        if (qu)
            result.quQuestionMask |= static_cast<uint8_t>(1u << i);
        if (!haveQuValue) {
            quValue = qu;
            haveQuValue = true;
        } else if (qu != quValue) {
            mixedQu = true;
        }
        const bool target = type == 12 && (qclass & 0x7fffu) == 1 &&
            isAirdropPtrInName(name, nameLength);
        if (target)
            ++result.targetPtrInQuestionCount;
        else
            allQuestionsTarget = false;
    }
    // Keep parsed ports, DNS header, questions, and QU mask for diagnosis,
    // but never present an invalid mDNS-port transport packet as Legacy/QU/QM.
    if (checksumStatus != UdpChecksumStatus::Valid)
        return result;
    // RFC 6762 section 18.11 requires the mDNS response-code field to be zero.
    if ((flags & 0x000fu) != 0) {
        result.queryClass = MdnsQueryClass::Other;
    } else if (!group || !allQuestionsTarget || mixedQu) {
        result.queryClass = MdnsQueryClass::Other;
    } else if (!result.sourcePortIs5353 && result.destinationPortIs5353) {
        result.queryClass = MdnsQueryClass::LegacyUnicastReply;
    } else if (result.sourcePortIs5353 && result.destinationPortIs5353) {
        result.queryClass = quValue ? MdnsQueryClass::QuUnicastPreferred
                                    : MdnsQueryClass::QmMulticast;
    } else {
        result.queryClass = MdnsQueryClass::Other;
    }
    return result;
}

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
    uint8_t ipv6DestinationIsAirdropMdnsGroup;
    MdnsQueryObservation mdnsQuery;
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
    result.mdnsQuery = observeMdnsAirdropQuery(
        ipv6, udp, udpLength, result.udpChecksumStatus);
    result.ipv6DestinationIsAirdropMdnsGroup =
        result.mdnsQuery.destinationIsFf02Fb;
    return result;
}

} // namespace NativeAwdlData

#endif // NATIVE_AWDL_DATA_TX_OBSERVATION_HPP
