// SPDX-License-Identifier: GPL-2.0-only
#ifndef GEEK_IWX_STA_KEY_RX_PN_HPP
#define GEEK_IWX_STA_KEY_RX_PN_HPP

#include <stddef.h>
#include <stdint.h>

// ADD_STA_KEY RX replay-floor encoding for the CCMP key layout used by fw API
// versions 2 and 3. Firmware API v2 reserves bytes 2 and 3; v3 is contiguous.
// The helper intentionally rejects all other/unknown versions so the caller
// can preserve its existing command unchanged instead of guessing a layout.
namespace IwxStaKeyRxPn {

constexpr size_t kTidCount = 16;
constexpr size_t kSequenceBytes = 16;
constexpr uint64_t kCcmpPnMask = (uint64_t(1) << 48) - 1;

enum class Status : uint8_t {
    kReady = 0,
    kUnsupportedApi = 1,
    kInvalidArgument = 2,
    kPnOutOfRange = 3
};

struct Encoded {
    uint8_t bytes[kSequenceBytes];
    uint64_t maximumPn;
    uint32_t maximumTid;
    uint32_t apiVersion;
};

inline Status encodeCcmp(const uint64_t *perTidPn, size_t tidCount,
                         uint32_t apiVersion, Encoded *output)
{
    if (!perTidPn || !output || tidCount != kTidCount)
        return Status::kInvalidArgument;
    if (apiVersion != 2 && apiVersion != 3)
        return Status::kUnsupportedApi;

    Encoded encoded{};
    encoded.apiVersion = apiVersion;
    for (size_t tid = 0; tid < tidCount; ++tid) {
        const uint64_t pn = perTidPn[tid];
        if ((pn & ~kCcmpPnMask) != 0)
            return Status::kPnOutOfRange;
        if (pn > encoded.maximumPn) {
            encoded.maximumPn = pn;
            encoded.maximumTid = static_cast<uint32_t>(tid);
        }
    }

    const size_t hole = apiVersion >= 3 ? 0 : 2;
    for (size_t byte = 0; byte < 6; ++byte) {
        const size_t destination = byte < 2 ? byte : byte + hole;
        encoded.bytes[destination] = static_cast<uint8_t>(
            encoded.maximumPn >> (byte * 8));
    }
    *output = encoded;
    return Status::kReady;
}

} // namespace IwxStaKeyRxPn

#endif
