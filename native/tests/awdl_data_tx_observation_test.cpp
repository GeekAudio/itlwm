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

constexpr uint8_t kAirdropName[] = {
    8, '_','a','i','r','d','r','o','p', 4, '_','t','c','p',
    5, 'l','o','c','a','l', 0
};
constexpr uint8_t kCompanionLinkName[] = {
    15, '_','c','o','m','p','a','n','i','o','n','-','l','i','n','k',
    4, '_','t','c','p', 5, 'l','o','c','a','l', 0
};
constexpr uint8_t kAsquicName[] = {
    7, '_','a','s','q','u','i','c', 4, '_','u','d','p',
    5, 'l','o','c','a','l', 0
};
constexpr uint8_t kUnknownNearMatchName[] = {
    17, '_','c','o','m','p','a','n','i','o','n','-','l','i','n','k','e','r',
    4, '_','t','c','p', 5, 'l','o','c','a','l', 0
};
constexpr uint8_t kCompanionWrongTransportName[] = {
    15, '_','c','o','m','p','a','n','i','o','n','-','l','i','n','k',
    4, '_','u','d','p', 5, 'l','o','c','a','l', 0
};
constexpr uint8_t kAsquicWrongTransportName[] = {
    7, '_','a','s','q','u','i','c', 4, '_','t','c','p',
    5, 'l','o','c','a','l', 0
};
constexpr uint8_t kAsquicTrailingLabelName[] = {
    7, '_','a','s','q','u','i','c', 4, '_','u','d','p',
    5, 'l','o','c','a','l', 4, 'e','v','i','l', 0
};

size_t appendQuestionRecord(uint8_t *dns, size_t offset, const uint8_t *name,
                            size_t nameLength, uint16_t type,
                            uint16_t qclass)
{
    memcpy(dns + offset, name, nameLength);
    offset += nameLength;
    putBe16(dns + offset, type);
    putBe16(dns + offset + 2, qclass);
    return offset + 4;
}

size_t appendQuestion(uint8_t *dns, size_t offset, const uint8_t *name,
                      size_t nameLength, uint16_t qclass)
{
    return appendQuestionRecord(dns, offset, name, nameLength, 12, qclass);
}

size_t makeDnsPacket(uint8_t *packet, const uint8_t *questions,
                     size_t questionBytes, uint16_t questionCount,
                     uint16_t dnsFlags, uint16_t sourcePort,
                     uint16_t destinationPort)
{
    const size_t dnsLength = 12 + questionBytes;
    const size_t udpLength = 8 + dnsLength;
    const size_t ethernetLength = 14 + 40 + udpLength;
    memset(packet, 0, ethernetLength);
    const uint8_t destinationMac[6] = {0x33, 0x33, 0, 0, 0, 0xfb};
    memcpy(packet, destinationMac, sizeof(destinationMac));
    memcpy(packet + 6, kOwnMac, sizeof(kOwnMac));
    putBe16(packet + 12, 0x86dd);
    uint8_t *ipv6 = packet + 14;
    ipv6[0] = 0x60;
    putBe16(ipv6 + 4, static_cast<uint16_t>(udpLength));
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
    putBe16(udp, sourcePort);
    putBe16(udp + 2, destinationPort);
    putBe16(udp + 4, static_cast<uint16_t>(udpLength));
    uint8_t *dns = udp + 8;
    putBe16(dns + 2, dnsFlags);
    putBe16(dns + 4, questionCount);
    if (questionBytes)
        memcpy(dns + 12, questions, questionBytes);
    putBe16(udp + 6, makeUdpChecksum(ipv6, udp, udpLength));
    return ethernetLength;
}

NativeAwdlData::TxObservation observeDnsName(
    uint8_t *packet, size_t packetCapacity, const uint8_t *name,
    size_t nameLength, uint16_t type, uint16_t sourcePort,
    uint16_t destinationPort, uint16_t questionClass = 1,
    uint16_t dnsFlags = 0)
{
    uint8_t question[64]{};
    const size_t bytes = appendQuestionRecord(question, 0, name,
        nameLength, type, questionClass);
    const size_t lengthOut = makeDnsPacket(packet, question, bytes, 1,
        dnsFlags, sourcePort, destinationPort);
    assert(packetCapacity >= lengthOut);
    return NativeAwdlData::observeAwdlTxPacket(packet, lengthOut, kOwnMac);
}

NativeAwdlData::TxObservation observeDns(
    uint8_t *packet, size_t packetCapacity, uint16_t sourcePort,
    uint16_t destinationPort, uint16_t questionClass = 1,
    uint16_t dnsFlags = 0)
{
    return observeDnsName(packet, packetCapacity, kAirdropName,
        sizeof(kAirdropName), 12, sourcePort, destinationPort,
        questionClass, dnsFlags);
}

void testMdnsAirdropQueryClassification()
{
    uint8_t packet[256]{};
    auto result = observeDns(packet, sizeof(packet), 49152, 5353);
    assert(result.mdnsQuery.queryClass ==
           NativeAwdlData::MdnsQueryClass::LegacyUnicastReply);
    assert(!result.mdnsQuery.sourcePortIs5353);
    assert(result.mdnsQuery.destinationPortIs5353);
    assert(result.mdnsQuery.destinationIsFf02Fb);
    assert(result.mdnsQuery.headerParsed && result.mdnsQuery.qr == 0);
    assert(result.mdnsQuery.questionCount == 1);
    assert(result.mdnsQuery.targetPtrInQuestionCount == 1);
    assert(result.mdnsQuery.quQuestionMask == 0);

    result = observeDns(packet, sizeof(packet), 5353, 5353, 0x8001);
    assert(result.mdnsQuery.queryClass ==
           NativeAwdlData::MdnsQueryClass::QuUnicastPreferred);
    assert(result.mdnsQuery.sourcePortIs5353 &&
           result.mdnsQuery.destinationPortIs5353);
    assert(result.mdnsQuery.quQuestionMask == 1);

    result = observeDns(packet, sizeof(packet), 5353, 5353, 1, 1u << 9);
    assert(result.mdnsQuery.queryClass ==
           NativeAwdlData::MdnsQueryClass::QmMulticast);
    assert(result.mdnsQuery.tc == 1);
    assert(result.mdnsQuery.quQuestionMask == 0);

    // A second question uses a legal backward compression pointer to the
    // first question name; both IN/PTR questions are classified as QM.
    uint8_t multi[2 * (sizeof(kAirdropName) + 4)]{};
    size_t multiLength = appendQuestion(multi, 0, kAirdropName,
        sizeof(kAirdropName), 1);
    const size_t firstNameOffset = 12;
    multi[multiLength++] = static_cast<uint8_t>(0xc0 | (firstNameOffset >> 8));
    multi[multiLength++] = static_cast<uint8_t>(firstNameOffset);
    putBe16(multi + multiLength, 12);
    putBe16(multi + multiLength + 2, 1);
    multiLength += 4;
    const size_t multiPacketLength = makeDnsPacket(packet, multi,
        multiLength, 2, 0, 5353, 5353);
    result = NativeAwdlData::observeAwdlTxPacket(
        packet, multiPacketLength, kOwnMac);
    assert(result.mdnsQuery.queryClass ==
           NativeAwdlData::MdnsQueryClass::QmMulticast);
    assert(result.mdnsQuery.questionCount == 2);
    assert(result.mdnsQuery.targetPtrInQuestionCount == 2);

    // A mixed QM/QU multi-question packet is valid DNS but not a clean
    // single-class sample, so it remains Other.
    multi[multiLength - 2] = 0x80;
    multi[multiLength - 1] = 0x01;
    const size_t mixedLength = makeDnsPacket(packet, multi,
        multiLength, 2, 0, 5353, 5353);
    result = NativeAwdlData::observeAwdlTxPacket(packet, mixedLength, kOwnMac);
    assert(result.mdnsQuery.queryClass == NativeAwdlData::MdnsQueryClass::Other);
    assert(result.mdnsQuery.quQuestionMask == 2);

    result = observeDns(packet, sizeof(packet), 5353, 5353, 1, 0x8000);
    assert(result.mdnsQuery.queryClass == NativeAwdlData::MdnsQueryClass::Other);
    assert(result.mdnsQuery.qr == 1);

    // A self-referential compression pointer is malformed and must stay
    // Unknown rather than being mistaken for an unrelated, valid query.
    uint8_t cycleQuestion[6] = {0xc0, 0x0c, 0, 12, 0, 1};
    const size_t cycleLength = makeDnsPacket(packet, cycleQuestion,
        sizeof(cycleQuestion), 1, 0, 5353, 5353);
    result = NativeAwdlData::observeAwdlTxPacket(packet, cycleLength, kOwnMac);
    assert(result.mdnsQuery.queryClass == NativeAwdlData::MdnsQueryClass::Unknown);

    // Header count exceeds the bounded multi-question parser budget.
    const size_t tooManyLength = makeDnsPacket(packet, nullptr, 0, 9, 0, 5353, 5353);
    result = NativeAwdlData::observeAwdlTxPacket(packet, tooManyLength, kOwnMac);
    assert(result.mdnsQuery.headerParsed == 1);
    assert(result.mdnsQuery.questionCount == 9);
    assert(result.mdnsQuery.queryClass == NativeAwdlData::MdnsQueryClass::Unknown);

    // Truncated label data cannot be safely called a valid unrelated mDNS
    // question; the parser must preserve the Unknown result.
    const uint8_t truncatedQuestion[] = {8, '_'};
    const size_t truncatedLength = makeDnsPacket(packet, truncatedQuestion,
        sizeof(truncatedQuestion), 1, 0, 5353, 5353);
    result = NativeAwdlData::observeAwdlTxPacket(packet,
        truncatedLength, kOwnMac);
    assert(result.mdnsQuery.headerParsed == 1);
    assert(result.mdnsQuery.queryClass == NativeAwdlData::MdnsQueryClass::Unknown);

    // A valid mDNS packet on an unrelated IPv6 multicast group is not a QM
    // sample for ff02::fb.
    result = observeDns(packet, sizeof(packet), 5353, 5353, 1);
    packet[14 + 24 + 15] = 0xfc;
    uint8_t *ipv6 = packet + 14;
    uint8_t *udp = ipv6 + 40;
    const size_t udpLength = 8 + 12 + sizeof(kAirdropName) + 4;
    putBe16(udp + 6, 0);
    putBe16(udp + 6, makeUdpChecksum(ipv6, udp, udpLength));
    result = NativeAwdlData::observeAwdlTxPacket(packet,
        14 + 40 + 8 + 12 + sizeof(kAirdropName) + 4, kOwnMac);
    assert(result.mdnsQuery.queryClass == NativeAwdlData::MdnsQueryClass::Other);
    assert(result.mdnsQuery.destinationIsFf02Fb == 0);
}

void testSupportedDnsSdServiceQueries()
{
    uint8_t packet[256]{};
    auto result = observeDnsName(packet, sizeof(packet), kCompanionLinkName,
        sizeof(kCompanionLinkName), 12, 5353, 5353, 1);
    assert(result.udpChecksumStatus ==
           NativeAwdlData::UdpChecksumStatus::Valid);
    assert(result.mdnsQuery.queryClass ==
           NativeAwdlData::MdnsQueryClass::QmMulticast);
    assert(result.mdnsQuery.questionCount == 1);
    assert(result.mdnsQuery.targetPtrInQuestionCount == 1);

    result = observeDnsName(packet, sizeof(packet), kCompanionLinkName,
        sizeof(kCompanionLinkName), 12, 5353, 5353, 0x8001);
    assert(result.mdnsQuery.queryClass ==
           NativeAwdlData::MdnsQueryClass::QuUnicastPreferred);
    assert(result.mdnsQuery.quQuestionMask == 1);
    assert(result.mdnsQuery.targetPtrInQuestionCount == 1);

    // The _udp service is deliberately supported as an exact peer-discovery
    // target and follows the same multicast question-class rules.
    result = observeDnsName(packet, sizeof(packet), kAsquicName,
        sizeof(kAsquicName), 12, 5353, 5353, 1);
    assert(result.mdnsQuery.queryClass ==
           NativeAwdlData::MdnsQueryClass::QmMulticast);
    assert(result.mdnsQuery.targetPtrInQuestionCount == 1);

    // A multi-question packet may mix the supported service names when every
    // question remains PTR/IN and uses the same QM/QU class.
    uint8_t multi[sizeof(kCompanionLinkName) + sizeof(kAsquicName) + 8]{};
    size_t multiLength = appendQuestion(multi, 0, kCompanionLinkName,
        sizeof(kCompanionLinkName), 1);
    multiLength = appendQuestion(multi, multiLength, kAsquicName,
        sizeof(kAsquicName), 1);
    const size_t multiPacketLength = makeDnsPacket(packet, multi,
        multiLength, 2, 0, 5353, 5353);
    result = NativeAwdlData::observeAwdlTxPacket(
        packet, multiPacketLength, kOwnMac);
    assert(result.mdnsQuery.queryClass ==
           NativeAwdlData::MdnsQueryClass::QmMulticast);
    assert(result.mdnsQuery.questionCount == 2);
    assert(result.mdnsQuery.targetPtrInQuestionCount == 2);
    assert(result.mdnsQuery.quQuestionMask == 0);

    // Existing QM/QU separation still applies to mixed supported names.
    multi[multiLength - 2] = 0x80;
    multi[multiLength - 1] = 0x01;
    const size_t mixedClassLength = makeDnsPacket(packet, multi,
        multiLength, 2, 0, 5353, 5353);
    result = NativeAwdlData::observeAwdlTxPacket(
        packet, mixedClassLength, kOwnMac);
    assert(result.mdnsQuery.queryClass == NativeAwdlData::MdnsQueryClass::Other);
    assert(result.mdnsQuery.targetPtrInQuestionCount == 2);
    assert(result.mdnsQuery.quQuestionMask == 2);

    // One unsupported question prevents a mixed packet from becoming a
    // supported-service sample, while the supported question count remains
    // available in the existing generic target counter.
    uint8_t mixedNames[sizeof(kCompanionLinkName) + sizeof(kUnknownNearMatchName) + 8]{};
    size_t mixedNamesLength = appendQuestion(mixedNames, 0,
        kCompanionLinkName, sizeof(kCompanionLinkName), 1);
    mixedNamesLength = appendQuestion(mixedNames, mixedNamesLength,
        kUnknownNearMatchName, sizeof(kUnknownNearMatchName), 1);
    const size_t mixedNamesPacketLength = makeDnsPacket(packet, mixedNames,
        mixedNamesLength, 2, 0, 5353, 5353);
    result = NativeAwdlData::observeAwdlTxPacket(
        packet, mixedNamesPacketLength, kOwnMac);
    assert(result.mdnsQuery.queryClass == NativeAwdlData::MdnsQueryClass::Other);
    assert(result.mdnsQuery.targetPtrInQuestionCount == 1);

    // The allowlist is exact: wrong service labels, wrong transport labels,
    // and suffix extension lookalikes remain unrelated valid mDNS queries.
    const struct {
        const uint8_t *name;
        size_t length;
    } nearMatches[] = {
        {kUnknownNearMatchName, sizeof(kUnknownNearMatchName)},
        {kCompanionWrongTransportName, sizeof(kCompanionWrongTransportName)},
        {kAsquicWrongTransportName, sizeof(kAsquicWrongTransportName)},
        {kAsquicTrailingLabelName, sizeof(kAsquicTrailingLabelName)},
    };
    for (const auto &nearMatch : nearMatches) {
        result = observeDnsName(packet, sizeof(packet), nearMatch.name,
            nearMatch.length, 12, 5353, 5353, 1);
        assert(result.udpChecksumStatus ==
               NativeAwdlData::UdpChecksumStatus::Valid);
        assert(result.mdnsQuery.queryClass == NativeAwdlData::MdnsQueryClass::Other);
        assert(result.mdnsQuery.targetPtrInQuestionCount == 0);
    }

    // Type and class stay strict even when a supported owner name is used.
    result = observeDnsName(packet, sizeof(packet), kCompanionLinkName,
        sizeof(kCompanionLinkName), 1, 5353, 5353, 1);
    assert(result.mdnsQuery.queryClass == NativeAwdlData::MdnsQueryClass::Other);
    assert(result.mdnsQuery.targetPtrInQuestionCount == 0);
    result = observeDnsName(packet, sizeof(packet), kAsquicName,
        sizeof(kAsquicName), 12, 5353, 5353, 3);
    assert(result.mdnsQuery.queryClass == NativeAwdlData::MdnsQueryClass::Other);
    assert(result.mdnsQuery.targetPtrInQuestionCount == 0);

    // No port broadening: an mDNS-port packet sent to a unicast UDP port
    // cannot enter the QM/QU classes.
    result = observeDnsName(packet, sizeof(packet), kAsquicName,
        sizeof(kAsquicName), 12, 5353, 5352, 1);
    assert(result.mdnsQuery.queryClass == NativeAwdlData::MdnsQueryClass::Other);

    // Checksum validation remains before classification for newly supported
    // targets; parsing facts may remain, but a bad packet is never QM/QU.
    result = observeDnsName(packet, sizeof(packet), kAsquicName,
        sizeof(kAsquicName), 12, 5353, 5353, 1);
    const size_t packetLength = 14 + 40 + 8 + 12 + sizeof(kAsquicName) + 4;
    packet[14 + 40 + 6] ^= 1;
    result = NativeAwdlData::observeAwdlTxPacket(packet, packetLength, kOwnMac);
    assert(result.udpChecksumStatus ==
           NativeAwdlData::UdpChecksumStatus::Invalid);
    assert(result.mdnsQuery.queryClass == NativeAwdlData::MdnsQueryClass::Unknown);
    assert(result.mdnsQuery.targetPtrInQuestionCount == 1);
}

void testMdnsInvalidTransportAndRcodeClassification()
{
    uint8_t packet[14 + 40 + 8 + 12 + sizeof(kAirdropName) + 4]{};
    const size_t length = 14 + 40 + 8 + 12 + sizeof(kAirdropName) + 4;

    // A structurally valid packet with a non-zero mDNS RCODE is not a valid
    // QM query, but its parsed question facts remain available for diagnosis.
    auto result = observeDns(packet, sizeof(packet), 5353, 5353, 1, 0x0001);
    assert(result.udpChecksumStatus == NativeAwdlData::UdpChecksumStatus::Valid);
    assert(result.mdnsQuery.queryClass == NativeAwdlData::MdnsQueryClass::Other);
    assert(result.mdnsQuery.headerParsed == 1);
    assert(result.mdnsQuery.questionCount == 1);
    assert(result.mdnsQuery.targetPtrInQuestionCount == 1);

    // Keep transport and DNS observations, but never classify a target-shaped
    // packet with an invalid UDP checksum as Legacy/QU/QM.
    result = observeDns(packet, sizeof(packet), 5353, 5353);
    packet[14 + 40 + 6] ^= 0x01;
    result = NativeAwdlData::observeAwdlTxPacket(packet, length, kOwnMac);
    assert(result.udpChecksumStatus == NativeAwdlData::UdpChecksumStatus::Invalid);
    assert(result.mdnsQuery.queryClass == NativeAwdlData::MdnsQueryClass::Unknown);
    assert(result.mdnsQuery.sourcePortIs5353 == 1);
    assert(result.mdnsQuery.destinationPortIs5353 == 1);
    assert(result.mdnsQuery.destinationIsFf02Fb == 1);
    assert(result.mdnsQuery.headerParsed == 1);
    assert(result.mdnsQuery.questionCount == 1);
    assert(result.mdnsQuery.targetPtrInQuestionCount == 1);

    // A malformed UDP length stays Unknown and retains the transport verdict.
    result = observeDns(packet, sizeof(packet), 5353, 5353);
    putBe16(packet + 14 + 40 + 4,
            static_cast<uint16_t>(length - (14 + 40) - 1));
    result = NativeAwdlData::observeAwdlTxPacket(packet, length, kOwnMac);
    assert(result.udpChecksumStatus == NativeAwdlData::UdpChecksumStatus::Malformed);
    assert(result.mdnsQuery.queryClass == NativeAwdlData::MdnsQueryClass::Unknown);
}

} // namespace

int main()
{
    testCandidateClassification();
    testPacketObservation();
    testMdnsAirdropQueryClassification();
    testSupportedDnsSdServiceQueries();
    testMdnsInvalidTransportAndRcodeClassification();
}
