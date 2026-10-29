// SPDX-License-Identifier: GPL-2.0-only
#ifndef NATIVE_AWDL_ADVERTISEMENT_IDENTITY_HPP
#define NATIVE_AWDL_ADVERTISEMENT_IDENTITY_HPP

#include "awdl_action_frame.hpp"
#include "awdl_mif_encode.hpp"

#include <string.h>

namespace NativeAwdl {

// Confirm that a bounded PSF or MIF actually advertises the same address in
// 802.11 Addr2 and Data Path State. Parsing validates the action envelope,
// timestamps, TLV lengths, and terminal padding before this walk inspects the
// type-12 value. This does not prove that a peer received the frame.
inline bool actionFrameAdvertisesAddress(const uint8_t *frame, size_t length,
                                         const uint8_t address[6])
{
    if (!frame || !address ||
        length > kMaximumEncodedMifLength ||
        length < kActionMacHeaderLength ||
        memcmp(frame + 10, address, 6) != 0)
        return false;

    ActionFrameInfo info{};
    ParseDiagnostics diagnostics{};
    if (parseActionFrame(frame, length, &info, &diagnostics) != ParseStatus::Ok ||
        (info.subtype != 0 && info.subtype != 3) ||
        !diagnostics.dataPathFlagsPresent ||
        diagnostics.dataPathFlags != 0x0004)
        return false;

    const uint16_t frameControl = static_cast<uint16_t>(frame[0]) |
        (static_cast<uint16_t>(frame[1]) << 8);
    size_t offset = kActionMacHeaderLength +
        ((frameControl & 0x8000) ? kActionHtControlLength : 0) +
        kAwdlActionHeaderLength;
    bool foundAddress = false;
    while (offset < length) {
        if (length - offset < 3) {
            // The parser permits up to two terminal zero pad bytes.
            for (size_t i = offset; i < length; ++i)
                if (frame[i] != 0)
                    return false;
            break;
        }
        const uint8_t type = frame[offset];
        const size_t valueLength = static_cast<uint16_t>(frame[offset + 1]) |
            (static_cast<uint16_t>(frame[offset + 2]) << 8);
        const size_t valueOffset = offset + 3;
        if (valueLength > length - valueOffset)
            return false;
        if (type == 12) {
            if (foundAddress || valueLength != 8 ||
                (static_cast<uint16_t>(frame[valueOffset]) |
                 (static_cast<uint16_t>(frame[valueOffset + 1]) << 8)) !=
                    0x0004 ||
                memcmp(frame + valueOffset + 2, address, 6) != 0)
                return false;
            foundAddress = true;
        }
        offset = valueOffset + valueLength;
    }
    return foundAddress;
}

} // namespace NativeAwdl

#endif
