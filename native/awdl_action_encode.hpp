// SPDX-License-Identifier: GPL-2.0-only
#ifndef NATIVE_AWDL_ACTION_ENCODE_HPP
#define NATIVE_AWDL_ACTION_ENCODE_HPP

#include <stddef.h>
#include <stdint.h>

namespace NativeAwdl {

enum class EncodeStatus : uint8_t {
    Ok,
    InvalidArgument,
    InvalidSourceAddress,
    InvalidElectionAddress,
    InvalidChannelSequence,
    InvalidSyncFields,
    InvalidElectionFields,
    InvalidHtCapabilities,
    InvalidVersion,
    BufferTooSmall
};

// All values that depend on a live AWDL clock, election, channel scheduler,
// or radio capability are mandatory inputs. The encoder does not infer them.
// `phyTxTimestampUs` and `targetTxTimestampUs` are the two AWDL action-header
// timestamps; their clock epoch/mapping is outside this serializer's contract.
struct PsfInput {
    uint8_t sourceAddress[6];
    uint16_t sequenceNumber; // 12-bit 802.11 sequence number, before << 4.
    uint32_t phyTxTimestampUs;
    uint32_t targetTxTimestampUs;

    // The 16 truthful scheduler slots, each 0 (not served), 6, 44, or 149.
    uint8_t channelSlots[16];
    uint8_t nextAwChannel;
    uint16_t txDownCounterTu;
    uint8_t masterChannel;
    uint16_t remainingAwLengthTu;
    uint16_t nextAwSequenceNumber;
    uint16_t apAlignment;

    // Election state from the live election worker. The 8-bit v1 distance
    // must be representable in addition to the v2 32-bit value.
    uint8_t masterAddress[6];
    uint8_t syncAddress[6];
    uint32_t masterCounter;
    uint32_t distanceToMaster;
    uint32_t masterMetric;
    uint32_t ownMetric;
    uint32_t ownCounter;

    // Actual local HT capability data. The MCS mask contains MCS 0..31 only.
    uint16_t htCapabilityInfo;
    uint8_t ampduParameters;
    uint8_t rxMcsMask[4];
    uint8_t rxMcsLength; // 1..4 bytes.

    // Version TLV fields; the current target is macOS (device class 1).
    uint8_t awdlVersion;
    uint8_t deviceClass;

    // Optional AWDL address form for Data Path State. When true, serializes
    // flags=0x0004 and reuses sourceAddress as the six-byte advertised address.
    // Aggregate-zero callers retain the legacy flags=0, two-byte value.
    bool advertiseAwdlAddress;
};

// MCS 0..31 occupies up to four bytes: 231 legacy bytes plus the optional
// six-byte AWDL address value.
constexpr size_t kMaximumEncodedPsfLength = 237;

// Encode one complete 802.11 Action MPDU containing a PSF. The destination is
// broadcast and the BSSID is the AWDL BSSID from AWDL-1. No FCS/radiotap is
// included. On every failure, *written is zero and the output buffer is left
// untouched.
EncodeStatus encodePsf(const PsfInput *input, uint8_t *output,
                       size_t capacity, size_t *written);

} // namespace NativeAwdl

#endif
