// SPDX-License-Identifier: GPL-2.0-only
#ifndef NATIVE_AWDL_QM_NO_KNOWN_ANSWER_HPP
#define NATIVE_AWDL_QM_NO_KNOWN_ANSWER_HPP

#include "awdl_data_tx_observation.hpp"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

namespace NativeAwdlData {

namespace qmNoKnownAnswerDetail {

inline bool isAirdropMdnsDestination(const uint8_t *address)
{
    if (!address || address[0] != 0xff || address[1] != 0x02 ||
        address[15] != 0xfb)
        return false;
    for (size_t i = 2; i < 15; ++i)
        if (address[i] != 0)
            return false;
    return true;
}

inline uint16_t computeUdpChecksum(const uint8_t *ipv6, const uint8_t *udp,
                                   size_t udpLength)
{
    uint32_t sum = 0;
    sum = txObservationAddWords(sum, ipv6 + 8, 32);
    sum += static_cast<uint16_t>((udpLength >> 16) & 0xffffu);
    sum += static_cast<uint16_t>(udpLength & 0xffffu);
    sum += 17u;
    sum = txObservationAddWords(sum, udp, udpLength);
    while (sum >> 16)
        sum = (sum & 0xffffu) + (sum >> 16);
    const uint16_t checksum = static_cast<uint16_t>(~sum);
    // A zero UDP checksum is not valid for IPv6. RFC 768/8200 encode a
    // computed zero as all ones on the wire.
    return checksum == 0 ? 0xffffu : checksum;
}

} // namespace qmNoKnownAnswerDetail

// Remove the one Known Answer carried by an exact, direct-UDP AirDrop QM
// query. This is a bounded in-place transform for the opt-in discovery path;
// it does not synthesize DNS, alter the question, or touch the queued mbuf.
//
// Preconditions: ipv6 points to a writable, complete IPv6 packet and
// ipv6Length points to its writable length; those two memory ranges do not
// overlap. The packet must be direct IPv6/UDP (no extension headers), use
// link-local source and ff02::fb destination, hop limit 255, have a valid,
// nonzero UDP checksum and both ports set to 5353, DNS ID/flags zero, exactly
// one AirDrop PTR/IN QM
// question, exactly one same-owner PTR/IN answer with a nonzero TTL, and no
// authority or additional records. The answer's PTR RDATA must be a complete
// bounded DNS name. Only ANCOUNT=1 is accepted; ANCOUNT=0 is intentionally
// rejected so success always proves that one record was removed.
//
// Returns true after removing only the answer and updating IPv6/UDP lengths,
// ANCOUNT, and the UDP checksum. On any rejection, both packet bytes and
// *ipv6Length are unchanged. The caller remains responsible for the separate
// Ethernet source/EUI-64 and owner/lease authorization gates.
inline bool stripAirdropQmKnownAnswer(uint8_t *ipv6, size_t *ipv6Length)
{
    if (!ipv6 || !ipv6Length)
        return false;
    const size_t originalLength = *ipv6Length;
    constexpr size_t kIpv6HeaderLength = 40;
    constexpr size_t kUdpHeaderLength = 8;
    constexpr size_t kDnsHeaderLength = 12;
    if (originalLength < kIpv6HeaderLength + kUdpHeaderLength +
                         kDnsHeaderLength ||
        (ipv6[0] >> 4) != 6 || ipv6[6] != 17 || ipv6[7] != 255)
        return false;

    const size_t ipv6PayloadLength = txObservationReadBe16(ipv6 + 4);
    if (ipv6PayloadLength != originalLength - kIpv6HeaderLength)
        return false;
    const uint8_t *source = ipv6 + 8;
    if (source[0] != 0xfe || (source[1] & 0xc0u) != 0x80u ||
        !qmNoKnownAnswerDetail::isAirdropMdnsDestination(ipv6 + 24))
        return false;

    uint8_t *udp = ipv6 + kIpv6HeaderLength;
    const size_t udpLength = txObservationReadBe16(udp + 4);
    if (udpLength != ipv6PayloadLength ||
        udpLength < kUdpHeaderLength + kDnsHeaderLength ||
        txObservationReadBe16(udp) != 5353 ||
        txObservationReadBe16(udp + 2) != 5353 ||
        txObservationReadBe16(udp + 6) == 0 ||
        !txObservationChecksumValid(ipv6, udp, udpLength))
        return false;

    const uint8_t *dns = udp + kUdpHeaderLength;
    const size_t dnsLength = udpLength - kUdpHeaderLength;
    if (txObservationReadBe16(dns) != 0 ||
        txObservationReadBe16(dns + 2) != 0 ||
        txObservationReadBe16(dns + 4) != 1 ||
        txObservationReadBe16(dns + 6) != 1 ||
        txObservationReadBe16(dns + 8) != 0 ||
        txObservationReadBe16(dns + 10) != 0)
        return false;

    // The production caller already has the full strict QM observation. Keep
    // this transform's own wire preconditions exact without reparsing the
    // same packet through the larger observation path.
    uint8_t questionName[21]{};
    size_t questionNameLength = 0;
    size_t questionOffset = kDnsHeaderLength;
    if (!parseMdnsQuestionName(dns, dnsLength, &questionOffset,
                               questionName, sizeof(questionName),
                               &questionNameLength) ||
        dnsLength - questionOffset < 4 ||
        txObservationReadBe16(dns + questionOffset) != 12 ||
        txObservationReadBe16(dns + questionOffset + 2) != 1 ||
        !isAirdropPtrInName(questionName, questionNameLength))
        return false;
    const size_t answerStart = questionOffset + 4;

    uint8_t answerOwner[21]{};
    size_t answerOwnerLength = 0;
    size_t answerOffset = answerStart;
    if (!parseMdnsQuestionName(dns, dnsLength, &answerOffset,
                               answerOwner, sizeof(answerOwner),
                               &answerOwnerLength) ||
        !isAirdropPtrInName(answerOwner, answerOwnerLength) ||
        dnsLength - answerOffset < 10)
        return false;

    const uint16_t answerType = txObservationReadBe16(dns + answerOffset);
    const uint16_t answerClass = txObservationReadBe16(dns + answerOffset + 2);
    const uint32_t answerTtl =
        (static_cast<uint32_t>(dns[answerOffset + 4]) << 24) |
        (static_cast<uint32_t>(dns[answerOffset + 5]) << 16) |
        (static_cast<uint32_t>(dns[answerOffset + 6]) << 8) |
        static_cast<uint32_t>(dns[answerOffset + 7]);
    const size_t rdataLength = txObservationReadBe16(dns + answerOffset + 8);
    const size_t rdataStart = answerOffset + 10;
    if (answerType != 12 || answerClass != 1 || answerTtl == 0 ||
        rdataLength != dnsLength - rdataStart)
        return false;

    uint8_t ptrTargetName[255]{};
    size_t ptrTargetNameLength = 0;
    size_t rdataOffset = rdataStart;
    if (!parseMdnsQuestionName(dns, dnsLength, &rdataOffset,
                               ptrTargetName, sizeof(ptrTargetName),
                               &ptrTargetNameLength) ||
        ptrTargetNameLength <= 1 || rdataOffset != dnsLength)
        return false;

    const size_t newDnsLength = answerStart;
    const size_t newUdpLength = kUdpHeaderLength + newDnsLength;
    const size_t newIpv6PayloadLength = newUdpLength;
    const size_t newIpv6Length = kIpv6HeaderLength + newIpv6PayloadLength;
    if (newUdpLength > UINT16_MAX || newIpv6PayloadLength > UINT16_MAX ||
        newIpv6Length >= originalLength)
        return false;

    // All validation is complete. From here the transform cannot fail.
    uint8_t *mutableDns = udp + kUdpHeaderLength;
    mutableDns[6] = 0;
    mutableDns[7] = 0;
    ipv6[4] = static_cast<uint8_t>(newIpv6PayloadLength >> 8);
    ipv6[5] = static_cast<uint8_t>(newIpv6PayloadLength);
    udp[4] = static_cast<uint8_t>(newUdpLength >> 8);
    udp[5] = static_cast<uint8_t>(newUdpLength);
    udp[6] = 0;
    udp[7] = 0;
    memset(ipv6 + newIpv6Length, 0, originalLength - newIpv6Length);
    const uint16_t checksum = qmNoKnownAnswerDetail::computeUdpChecksum(
        ipv6, udp, newUdpLength);
    udp[6] = static_cast<uint8_t>(checksum >> 8);
    udp[7] = static_cast<uint8_t>(checksum);
    *ipv6Length = newIpv6Length;
    return true;
}

} // namespace NativeAwdlData

#endif // NATIVE_AWDL_QM_NO_KNOWN_ANSWER_HPP
