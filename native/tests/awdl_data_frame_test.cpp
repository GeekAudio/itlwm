// SPDX-License-Identifier: GPL-2.0-only
#include "../awdl_data_frame.hpp"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <vector>

using NativeAwdlData::DecodedFrame;
using NativeAwdlData::EncodeInput;
using NativeAwdlData::Status;

namespace {

const uint8_t kDestination[6] = {0x02, 0x10, 0x20, 0x30, 0x40, 0x50};
const uint8_t kSource[6] = {0x06, 0x11, 0x22, 0x33, 0x44, 0x55};
const uint8_t kAmsduDestination[6] = {0x04, 0xaa, 0xbb, 0xcc, 0xdd, 0xee};
const uint8_t kAmsduSource[6] = {0x0a, 0xab, 0xbc, 0xcd, 0xde, 0xef};

void putLe16(uint8_t *bytes, uint16_t value)
{
    bytes[0] = static_cast<uint8_t>(value);
    bytes[1] = static_cast<uint8_t>(value >> 8);
}

void putBe16(uint8_t *bytes, uint16_t value)
{
    bytes[0] = static_cast<uint8_t>(value >> 8);
    bytes[1] = static_cast<uint8_t>(value);
}

std::vector<uint8_t> makeIpv6(size_t payloadLength)
{
    assert(payloadLength <= 0xffff);
    std::vector<uint8_t> packet(40 + payloadLength, 0);
    packet[0] = 0x60;
    putBe16(packet.data() + 4, static_cast<uint16_t>(payloadLength));
    packet[6] = 59; // No Next Header
    packet[7] = 64;
    for (size_t i = 40; i < packet.size(); ++i)
        packet[i] = static_cast<uint8_t>(i * 7 + 3);
    return packet;
}

std::vector<uint8_t> makeUnaggregatedFrame(const std::vector<uint8_t> &ipv6,
                                          bool qos = false,
                                          uint16_t qosControl = 0)
{
    const size_t headerLength = 24 + (qos ? 2 : 0);
    std::vector<uint8_t> frame(headerLength + 16 + ipv6.size(), 0);
    putLe16(frame.data(), qos ? 0x0088 : 0x0008);
    memcpy(frame.data() + 4, kDestination, sizeof(kDestination));
    memcpy(frame.data() + 10, kSource, sizeof(kSource));
    memcpy(frame.data() + 16, NativeAwdlData::kAwdlBssid, 6);
    putLe16(frame.data() + 22, 0x0123 << 4);
    size_t offset = 24;
    if (qos) {
        putLe16(frame.data() + offset, qosControl);
        offset += 2;
    }
    const uint8_t snap[] = {0xaa, 0xaa, 0x03, 0x00, 0x17, 0xf2, 0x08, 0x00};
    memcpy(frame.data() + offset, snap, sizeof(snap));
    offset += sizeof(snap);
    const uint8_t awdl[] = {0x03, 0x04, 0x34, 0x12,
                            0x00, 0x00, 0x86, 0xdd};
    memcpy(frame.data() + offset, awdl, sizeof(awdl));
    offset += sizeof(awdl);
    memcpy(frame.data() + offset, ipv6.data(), ipv6.size());
    return frame;
}

void appendAmsduSubframe(std::vector<uint8_t> *body,
                         const std::vector<uint8_t> &ipv6,
                         bool padForNext)
{
    const size_t payloadLength = 16 + ipv6.size();
    assert(payloadLength <= 0xffff);
    const size_t start = body->size();
    body->insert(body->end(), kAmsduDestination,
                 kAmsduDestination + sizeof(kAmsduDestination));
    body->insert(body->end(), kAmsduSource,
                 kAmsduSource + sizeof(kAmsduSource));
    const size_t lengthOffset = body->size();
    body->resize(body->size() + 2);
    putBe16(body->data() + lengthOffset,
            static_cast<uint16_t>(payloadLength));
    const uint8_t snap[] = {0xaa, 0xaa, 0x03, 0x00, 0x17, 0xf2, 0x08, 0x00};
    body->insert(body->end(), snap, snap + sizeof(snap));
    const uint8_t awdl[] = {0x03, 0x04, 0x78, 0x56,
                            0x00, 0x00, 0x86, 0xdd};
    body->insert(body->end(), awdl, awdl + sizeof(awdl));
    body->insert(body->end(), ipv6.begin(), ipv6.end());

    const size_t subframeLength = body->size() - start;
    if (padForNext) {
        const size_t padding = (4 - (subframeLength & 3)) & 3;
        body->insert(body->end(), padding, 0);
    }
}

std::vector<uint8_t> makeAmsduFrame(size_t subframeCount,
                                    const std::vector<uint8_t> &ipv6)
{
    std::vector<uint8_t> body;
    for (size_t i = 0; i < subframeCount; ++i)
        appendAmsduSubframe(&body, ipv6, i + 1 < subframeCount);

    std::vector<uint8_t> frame(26 + body.size(), 0);
    putLe16(frame.data(), 0x0088);
    memcpy(frame.data() + 4, kDestination, sizeof(kDestination));
    memcpy(frame.data() + 10, kSource, sizeof(kSource));
    memcpy(frame.data() + 16, NativeAwdlData::kAwdlBssid, 6);
    putLe16(frame.data() + 22, 0x321 << 4);
    putLe16(frame.data() + 24, 0x0080);
    memcpy(frame.data() + 26, body.data(), body.size());
    return frame;
}

void expectDecodeFailure(const std::vector<uint8_t> &frame, Status expected)
{
    DecodedFrame output;
    memset(&output, 0xa5, sizeof(output));
    uint8_t before[sizeof(output)];
    memcpy(before, &output, sizeof(output));
    const Status actual = NativeAwdlData::decodeIpv6DataMpdu(
        frame.empty() ? nullptr : frame.data(), frame.size(), &output);
    if (actual != expected)
        fprintf(stderr, "decode status expected=%u actual=%u length=%zu\n",
                static_cast<unsigned>(expected),
                static_cast<unsigned>(actual), frame.size());
    assert(actual == expected);
    assert(memcmp(&output, before, sizeof(output)) == 0);
}

void expectEncodeFailure(const EncodeInput &input, Status expected,
                         size_t capacity = 128)
{
    uint8_t output[128];
    memset(output, 0xa5, sizeof(output));
    uint8_t before[sizeof(output)];
    memcpy(before, output, sizeof(output));
    size_t written = 0x1234;
    const Status actual = NativeAwdlData::encodeIpv6DataMpdu(
        &input, output, capacity, &written);
    if (actual != expected)
        fprintf(stderr, "encode status expected=%u actual=%u\n",
                static_cast<unsigned>(expected),
                static_cast<unsigned>(actual));
    assert(actual == expected);
    assert(written == 0x1234);
    assert(memcmp(output, before, sizeof(output)) == 0);
}

EncodeInput validEncodeInput(const std::vector<uint8_t> &ipv6)
{
    EncodeInput input = {};
    memcpy(input.destinationAddress, kDestination, sizeof(kDestination));
    memcpy(input.sourceAddress, kSource, sizeof(kSource));
    input.wifiSequenceNumber = 0xabc;
    input.awdlSequenceNumber = 0xcafe;
    input.ipv6Packet = ipv6.data();
    input.ipv6Length = ipv6.size();
    return input;
}

void testEncodeGoldenAndRoundTrip()
{
    const std::vector<uint8_t> ipv6 = makeIpv6(3);
    const EncodeInput input = validEncodeInput(ipv6);
    uint8_t frame[128];
    memset(frame, 0, sizeof(frame));
    size_t written = 0;
    assert(NativeAwdlData::encodeIpv6DataMpdu(
               &input, frame, sizeof(frame), &written) == Status::Ok);
    assert(written == 40 + ipv6.size());
    assert(frame[0] == 0x08 && frame[1] == 0x00);
    assert(memcmp(frame + 4, kDestination, 6) == 0);
    assert(memcmp(frame + 10, kSource, 6) == 0);
    assert(memcmp(frame + 16, NativeAwdlData::kAwdlBssid, 6) == 0);
    assert(frame[22] == 0xc0 && frame[23] == 0xab);
    const uint8_t expectedPrefix[] = {
        0xaa, 0xaa, 0x03, 0x00, 0x17, 0xf2, 0x08, 0x00,
        0x03, 0x04, 0xfe, 0xca, 0x00, 0x00, 0x86, 0xdd};
    assert(memcmp(frame + 24, expectedPrefix, sizeof(expectedPrefix)) == 0);
    assert(memcmp(frame + 40, ipv6.data(), ipv6.size()) == 0);

    DecodedFrame decoded = {};
    assert(NativeAwdlData::decodeIpv6DataMpdu(
               frame, written, &decoded) == Status::Ok);
    assert(decoded.packetCount == 1);
    assert(decoded.qosData == 0 && decoded.amsdu == 0);
    assert(decoded.wifiSequenceNumber == input.wifiSequenceNumber);
    assert(decoded.packets[0].awdlSequenceNumber ==
           input.awdlSequenceNumber);
    assert(memcmp(decoded.destinationAddress, kDestination, 6) == 0);
    assert(memcmp(decoded.sourceAddress, kSource, 6) == 0);
    assert(memcmp(decoded.packets[0].ipv6Packet, ipv6.data(), ipv6.size()) ==
           0);
}

void testEncodeFailureAtomicity()
{
    const std::vector<uint8_t> ipv6 = makeIpv6(3);
    EncodeInput input = validEncodeInput(ipv6);
    expectEncodeFailure(input, Status::BufferTooSmall, 40 + ipv6.size() - 1);

    input.wifiSequenceNumber = 0x1000;
    expectEncodeFailure(input, Status::InvalidSequence);
    input = validEncodeInput(ipv6);
    input.sourceAddress[0] = 0x03;
    expectEncodeFailure(input, Status::InvalidAddress);
    input = validEncodeInput(ipv6);
    memset(input.destinationAddress, 0, sizeof(input.destinationAddress));
    expectEncodeFailure(input, Status::InvalidAddress);
    input = validEncodeInput(ipv6);
    input.ipv6Length--;
    expectEncodeFailure(input, Status::InvalidIpv6Packet);
    input = validEncodeInput(ipv6);
    std::vector<uint8_t> invalidIpv6 = ipv6;
    invalidIpv6[0] = 0x50;
    input.ipv6Packet = invalidIpv6.data();
    expectEncodeFailure(input, Status::InvalidIpv6Packet);
    assert(NativeAwdlData::encodeIpv6DataMpdu(
               nullptr, nullptr, 0, nullptr) == Status::InvalidArgument);
}

void testUnaggregatedDecodeBoundaries()
{
    const std::vector<uint8_t> ipv6 = makeIpv6(5);
    const std::vector<uint8_t> valid = makeUnaggregatedFrame(ipv6);
    for (size_t length = 0; length < valid.size(); ++length) {
        DecodedFrame output;
        memset(&output, 0x5a, sizeof(output));
        uint8_t before[sizeof(output)];
        memcpy(before, &output, sizeof(output));
        assert(NativeAwdlData::decodeIpv6DataMpdu(
                   valid.data(), length, &output) != Status::Ok);
        assert(memcmp(&output, before, sizeof(output)) == 0);
    }

    std::vector<uint8_t> bad = valid;
    bad[16] ^= 1;
    expectDecodeFailure(bad, Status::WrongBssid);

    bad = valid;
    bad[1] |= 0x01; // ToDS
    expectDecodeFailure(bad, Status::UnsupportedFrame);
    bad = valid;
    bad[1] |= 0x02; // FromDS
    expectDecodeFailure(bad, Status::UnsupportedFrame);
    bad = valid;
    bad[1] |= 0x04; // More Fragments
    expectDecodeFailure(bad, Status::FragmentedFrame);
    bad = valid;
    bad[1] |= 0x40; // Protected
    expectDecodeFailure(bad, Status::ProtectedFrame);
    bad = valid;
    bad[1] |= 0x80; // Order / HT control
    expectDecodeFailure(bad, Status::UnsupportedFrame);
    bad = valid;
    bad[22] |= 0x01; // nonzero fragment number in Sequence Control
    expectDecodeFailure(bad, Status::FragmentedFrame);
    bad = valid;
    bad[0] = 0x00; // management frame
    expectDecodeFailure(bad, Status::UnsupportedFrame);
    bad = valid;
    memset(bad.data() + 10, 0, 6);
    expectDecodeFailure(bad, Status::InvalidAddress);

    bad = valid;
    bad[29] ^= 1; // SNAP OUI
    expectDecodeFailure(bad, Status::InvalidSnapHeader);
    bad = valid;
    bad[32] ^= 1; // AWDL head
    expectDecodeFailure(bad, Status::InvalidAwdlHeader);
    bad = valid;
    bad[36] = 1; // AWDL reserved pad
    expectDecodeFailure(bad, Status::InvalidAwdlHeader);
    bad = valid;
    bad[38] = 0x08; // IPv4 ethertype
    bad[39] = 0x00;
    expectDecodeFailure(bad, Status::UnsupportedEthertype);
    bad = valid;
    bad[40] = 0x50; // not IPv6
    expectDecodeFailure(bad, Status::InvalidIpv6Packet);
    bad = valid;
    bad[44] = 0;
    bad[45] = 6; // claims one byte more than the MPDU carries
    expectDecodeFailure(bad, Status::InvalidIpv6Packet);
    bad = valid;
    bad.push_back(0); // extra bytes after the declared IPv6 packet
    expectDecodeFailure(bad, Status::InvalidIpv6Packet);
}

void testQosAndAmsdu()
{
    const std::vector<uint8_t> ipv6 = makeIpv6(3);
    const std::vector<uint8_t> qos = makeUnaggregatedFrame(ipv6, true, 0x0005);
    DecodedFrame decoded = {};
    assert(NativeAwdlData::decodeIpv6DataMpdu(
               qos.data(), qos.size(), &decoded) == Status::Ok);
    assert(decoded.qosData == 1 && decoded.amsdu == 0);
    assert(decoded.qosControl == 0x0005 && decoded.packetCount == 1);

    std::vector<uint8_t> bad = qos;
    putLe16(bad.data() + 24, 0x0100); // unsupported mesh-control extension
    expectDecodeFailure(bad, Status::UnsupportedFrame);

    const std::vector<uint8_t> two = makeAmsduFrame(2, ipv6);
    decoded = {};
    assert(NativeAwdlData::decodeIpv6DataMpdu(
               two.data(), two.size(), &decoded) == Status::Ok);
    assert(decoded.qosData == 1 && decoded.amsdu == 1);
    assert(decoded.packetCount == 2);
    for (size_t i = 0; i < decoded.packetCount; ++i) {
        assert(decoded.packets[i].awdlSequenceNumber == 0x5678);
        assert(decoded.packets[i].ipv6Length == ipv6.size());
        assert(memcmp(decoded.packets[i].ipv6Packet, ipv6.data(), ipv6.size()) ==
               0);
        assert(memcmp(decoded.packets[i].destinationAddress,
                      kAmsduDestination, 6) == 0);
        assert(memcmp(decoded.packets[i].sourceAddress, kAmsduSource, 6) == 0);
    }

    const std::vector<uint8_t> maximum =
        makeAmsduFrame(NativeAwdlData::kMaximumAmsduSubframes, ipv6);
    decoded = {};
    assert(NativeAwdlData::decodeIpv6DataMpdu(
               maximum.data(), maximum.size(), &decoded) == Status::Ok);
    assert(decoded.packetCount == NativeAwdlData::kMaximumAmsduSubframes);

    const std::vector<uint8_t> overMaximum =
        makeAmsduFrame(NativeAwdlData::kMaximumAmsduSubframes + 1, ipv6);
    expectDecodeFailure(overMaximum, Status::TooManySubframes);

    for (size_t length = 0; length < two.size(); ++length) {
        // A prefix ending exactly after the first subframe is itself a valid
        // one-subframe A-MSDU, so it cannot be classified as truncated.
        const size_t validSingleSubframePrefix = 26 + 14 + 16 + ipv6.size();
        if (length == validSingleSubframePrefix) {
            DecodedFrame one = {};
            assert(NativeAwdlData::decodeIpv6DataMpdu(
                       two.data(), length, &one) == Status::Ok);
            assert(one.packetCount == 1);
            continue;
        }
        DecodedFrame output;
        memset(&output, 0x3c, sizeof(output));
        uint8_t before[sizeof(output)];
        memcpy(before, &output, sizeof(output));
        assert(NativeAwdlData::decodeIpv6DataMpdu(
                   two.data(), length, &output) != Status::Ok);
        assert(memcmp(&output, before, sizeof(output)) == 0);
    }

    bad = two;
    putBe16(bad.data() + 26 + 12, 0xffff);
    expectDecodeFailure(bad, Status::InvalidAmsdu);
    bad = two;
    bad.pop_back();
    expectDecodeFailure(bad, Status::InvalidAmsdu);

    std::vector<uint8_t> shortSubframe(26 + 13, 0);
    putLe16(shortSubframe.data(), 0x0088);
    memcpy(shortSubframe.data() + 4, kDestination, 6);
    memcpy(shortSubframe.data() + 10, kSource, 6);
    memcpy(shortSubframe.data() + 16, NativeAwdlData::kAwdlBssid, 6);
    putLe16(shortSubframe.data() + 24, 0x0080);
    expectDecodeFailure(shortSubframe, Status::InvalidAmsdu);

    std::vector<uint8_t> trailingPadding = makeAmsduFrame(1, ipv6);
    // A one-subframe aggregate has no required final padding. Add the three
    // bytes that would only be valid before another subframe.
    trailingPadding.insert(trailingPadding.end(), 3, 0);
    expectDecodeFailure(trailingPadding, Status::InvalidAmsdu);

    bad = two;
    bad[26 + 14 + 8 + 8] ^= 0x10; // corrupt first IPv6 version nibble
    expectDecodeFailure(bad, Status::InvalidIpv6Packet);
}

} // namespace

int main()
{
    testEncodeGoldenAndRoundTrip();
    testEncodeFailureAtomicity();
    testUnaggregatedDecodeBoundaries();
    testQosAndAmsdu();
    return 0;
}
