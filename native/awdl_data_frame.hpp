// SPDX-License-Identifier: GPL-2.0-only
#ifndef NATIVE_AWDL_DATA_FRAME_HPP
#define NATIVE_AWDL_DATA_FRAME_HPP

#include <stddef.h>
#include <stdint.h>

namespace NativeAwdlData {

constexpr size_t kMaximumAmsduSubframes = 16;
constexpr size_t kIpv6HeaderLength = 40;
constexpr size_t kMaximumIpv6PacketLength = kIpv6HeaderLength + 0xffff;
constexpr uint8_t kAwdlBssid[6] = {0x00, 0x25, 0x00, 0xff, 0x94, 0x73};

enum class Status : uint8_t {
    Ok,
    InvalidArgument,
    InvalidAddress,
    InvalidSequence,
    InvalidIpv6Packet,
    BufferTooSmall,
    TruncatedFrame,
    UnsupportedFrame,
    FragmentedFrame,
    ProtectedFrame,
    WrongBssid,
    InvalidLength,
    InvalidSnapHeader,
    InvalidAwdlHeader,
    UnsupportedEthertype,
    InvalidAmsdu,
    TooManySubframes
};

struct EncodeInput {
    uint8_t destinationAddress[6];
    uint8_t sourceAddress[6];
    uint16_t wifiSequenceNumber; // 12-bit 802.11 sequence number
    uint16_t awdlSequenceNumber; // independent 16-bit AWDL data sequence
    const uint8_t *ipv6Packet;
    size_t ipv6Length;
};

struct PacketView {
    uint8_t destinationAddress[6];
    uint8_t sourceAddress[6];
    uint16_t awdlSequenceNumber;
    const uint8_t *ipv6Packet; // points into the input MPDU
    size_t ipv6Length;
};

struct DecodedFrame {
    uint16_t frameControl;
    uint16_t wifiSequenceNumber;
    uint16_t qosControl;
    uint8_t destinationAddress[6];
    uint8_t sourceAddress[6];
    uint8_t qosData;
    uint8_t amsdu;
    size_t packetCount;
    PacketView packets[kMaximumAmsduSubframes];
};

// Encode one unaggregated, no-DS, ordinary 802.11 Data MPDU carrying one
// IPv6 packet. The caller supplies both sequence spaces. The input IPv6 packet,
// output buffer and written pointer must be valid and non-overlapping. On any
// failure, output bytes and *written are left unchanged.
Status encodeIpv6DataMpdu(const EncodeInput *input, uint8_t *output,
                          size_t capacity, size_t *written);

// Decode one complete 802.11 data MPDU (without radiotap, FCS, or crypto
// overhead). Supports unaggregated Data and QoS Data with or without A-MSDU.
// Packet IPv6 pointers refer to the input buffer, which must remain alive while
// the views are used. On any failure, *output is left unchanged.
Status decodeIpv6DataMpdu(const uint8_t *frame, size_t frameLength,
                          DecodedFrame *output);

// Header-only classification for bounded driver telemetry. This confirms
// only an unencrypted-header-visible, no-DS data/QoS-data candidate addressed
// to the fixed AWDL BSSID; it does not decode or validate the body.
bool isAwdlDataCandidate(const uint8_t *frame, size_t frameLength);

} // namespace NativeAwdlData

#endif
