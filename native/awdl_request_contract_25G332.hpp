#pragma once

// Offline, read-only request views reconstructed from the 25G332 IO80211 and
// AppleBCMWLANCoreMac call paths. These views do not implement an ioctl or
// imply that Apple's callback accepts a request or returns success.

#include <cstddef>
#include <cstdint>
#include <limits>

namespace ItlAwdlRequestContract25G332 {

static_assert(sizeof(uintptr_t) == 8, "25G332 request pointer ABI is x86_64");

constexpr size_t kSyncRequestBytes = 16;
constexpr size_t kOobRequestPrefixBytes = 56;
constexpr size_t kSyncPrefixBytes = 2;
constexpr size_t kSyncIovarNameBytes = 12; // "awdl_payload"
constexpr size_t kOobHeaderBytes = 38;
constexpr size_t kOobIovarNameBytes = 11; // "awdl_oob_af"

enum class ParseResult : uint8_t {
    kViewOnly,
    kNullRequest,
    kNullOutput,
    kShortRequest,
    kZeroSyncPayload,
    kNullExternalPayload,
    kPrefixWouldTruncate,
    kIndependentCapExceeded,
    kNativeTxLimitExceeded,
    kLengthArithmeticOverflow,
};

struct Limits {
    // Independent copy cap, chosen by the eventual caller from its own buffer
    // policy (for example MCLBYTES minus framing). It is never inferred from
    // Apple's dynamic max-command value.
    size_t independentPayloadCap;

    // Runtime value supplied by the caller if it has actually obtained the
    // native/backend command limit. Zero safely rejects even an empty OOB body.
    size_t nativeMaxCommandTxPayload;
};

struct SyncTemplateView {
    uint32_t payloadLength;
    uintptr_t borrowedPayloadAddress;
    uint16_t nativeLengthPrefix;
};

struct OobRequestView {
    uint32_t unk1;
    uint16_t unk2Low16;
    uint16_t pad1;
    uint32_t unk5;
    uint16_t unk6;
    uint16_t dataLength;
    uintptr_t borrowedDataAddress;
};

// Native callbacks reject total >= getMaxCmdTxPayload(). This helper is
// overflow-safe and deliberately keeps that dynamic transport limit separate
// from the caller's independent buffer cap.
inline ParseResult checkNativeTxBound(size_t payloadBytes, size_t fixedOverhead,
                                     size_t nativeMaxBytes) {
    if (payloadBytes > std::numeric_limits<size_t>::max() - fixedOverhead) {
        return ParseResult::kLengthArithmeticOverflow;
    }
    const size_t total = payloadBytes + fixedOverhead;
    return total < nativeMaxBytes ? ParseResult::kViewOnly
                                  : ParseResult::kNativeTxLimitExceeded;
}

inline uint16_t readLe16(const uint8_t *bytes, size_t offset) {
    return static_cast<uint16_t>(bytes[offset]) |
           static_cast<uint16_t>(static_cast<uint16_t>(bytes[offset + 1]) << 8);
}

inline uint32_t readLe32(const uint8_t *bytes, size_t offset) {
    return static_cast<uint32_t>(bytes[offset]) |
           (static_cast<uint32_t>(bytes[offset + 1]) << 8) |
           (static_cast<uint32_t>(bytes[offset + 2]) << 16) |
           (static_cast<uint32_t>(bytes[offset + 3]) << 24);
}

inline uint64_t readLe64(const uint8_t *bytes, size_t offset) {
    uint64_t value = 0;
    for (size_t i = 0; i < sizeof(value); ++i) {
        value |= static_cast<uint64_t>(bytes[offset + i]) << (i * 8);
    }
    return value;
}

inline ParseResult parseSyncTemplate(const uint8_t *request, size_t requestBytes,
                                     Limits limits, SyncTemplateView *out) {
    if (request == nullptr) return ParseResult::kNullRequest;
    if (out == nullptr) return ParseResult::kNullOutput;
    if (requestBytes < kSyncRequestBytes) return ParseResult::kShortRequest;

    // Version at +0 is deliberately not checked: the 25G332 native callback
    // does not read it. The packed pointer and integers are decoded by bytes.
    const uint32_t length = readLe32(request, 4);
    const uintptr_t payload = static_cast<uintptr_t>(readLe64(request, 8));
    if (length == 0) return ParseResult::kZeroSyncPayload;
    if (length > std::numeric_limits<uint16_t>::max()) {
        return ParseResult::kPrefixWouldTruncate;
    }
    if (payload == 0) return ParseResult::kNullExternalPayload;
    if (static_cast<size_t>(length) > limits.independentPayloadCap) {
        return ParseResult::kIndependentCapExceeded;
    }
    const ParseResult bound = checkNativeTxBound(
        static_cast<size_t>(length), kSyncPrefixBytes + kSyncIovarNameBytes,
        limits.nativeMaxCommandTxPayload);
    if (bound != ParseResult::kViewOnly) return bound;

    const SyncTemplateView candidate = {
        length,
        payload,
        static_cast<uint16_t>(length),
    };
    *out = candidate;
    return ParseResult::kViewOnly;
}

inline ParseResult parseOobRequest(const uint8_t *request, size_t requestBytes,
                                   Limits limits, OobRequestView *out) {
    if (request == nullptr) return ParseResult::kNullRequest;
    if (out == nullptr) return ParseResult::kNullOutput;
    if (requestBytes < kOobRequestPrefixBytes) return ParseResult::kShortRequest;

    // The 25G332 callback reads a pointer-sized value at +48. The current
    // shared header declares an inline array there; this prefix view follows
    // the observed binary read and never dereferences the external address.
    const uint32_t unk1 = readLe32(request, 4);
    const uint16_t unk2Low16 = readLe16(request, 8);
    const uint16_t pad1 = readLe16(request, 20);
    const uint32_t unk5 = readLe32(request, 22);
    const uint16_t unk6 = readLe16(request, 26);
    const uint16_t length = readLe16(request, 40);
    const uintptr_t dataAddress = static_cast<uintptr_t>(readLe64(request, 48));

    if (length != 0 && dataAddress == 0) {
        return ParseResult::kNullExternalPayload;
    }
    if (static_cast<size_t>(length) > limits.independentPayloadCap) {
        return ParseResult::kIndependentCapExceeded;
    }
    const ParseResult bound = checkNativeTxBound(
        static_cast<size_t>(length), kOobHeaderBytes + kOobIovarNameBytes,
        limits.nativeMaxCommandTxPayload);
    if (bound != ParseResult::kViewOnly) return bound;

    const OobRequestView candidate = {
        unk1, unk2Low16, pad1, unk5, unk6, length, dataAddress,
    };
    *out = candidate;
    return ParseResult::kViewOnly;
}

} // namespace ItlAwdlRequestContract25G332
