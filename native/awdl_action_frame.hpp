// SPDX-License-Identifier: GPL-2.0-only
#ifndef NATIVE_AWDL_ACTION_FRAME_HPP
#define NATIVE_AWDL_ACTION_FRAME_HPP

#include <stddef.h>
#include <stdint.h>

namespace NativeAwdl {

// Shared offsets for a complete AWDL action MPDU. Keep producers, parsers,
// and the HAL's bounded identity verifier on the same wire boundaries.
constexpr size_t kActionMacHeaderLength = 24;
constexpr size_t kActionHtControlLength = 4;
constexpr size_t kAwdlActionHeaderLength = 16;

enum class ParseStatus : uint8_t {
    Ok,
    InvalidArgument,
    TruncatedFrame,
    NotManagementAction,
    Invalid80211Header,
    ProtectedAction,
    NotAwdlAction,
    InvalidAwdlHeader,
    InvalidTlv,
    InvalidTlvValue,
    InvalidPadding,
    TooManyTlvs
};

enum class TlvRejectReason : uint8_t {
    None,
    LengthOverrun,
    InvalidValue,
    ArpaInPsf,
    DuplicateRequired, // Stable code; also used for repeated optional type 24.
    RequiredOrder, // Reserved diagnostic code; required TLVs may arrive reordered.
    MissingRequired,
    EmptyList
};

// Bounded numeric detail for a type-12 Data Path State value. Values are
// offsets within the TLV value, not offsets into or copies of any field data.
enum class DataPathRejectStage : uint8_t {
    None = 0,
    Flags = 1,
    CountryCode = 2,
    SocialChannels = 3,
    InfrastructureInfo = 4,
    InfrastructureAddress = 5,
    AwdlAddress = 6,
    Umi = 7,
    OptionsLength = 8,
    OptionsData = 9,
    UnsupportedExtFlags = 10,
    LogTrigger = 11,
    Rlfc = 12,
    ActiveTimeCounters = 13,
    TrailingBytes = 14,
    ExtendedFlags = 15
};

// Numeric-only detail for TLV-related rejects. Offsets are relative to the
// beginning of the MPDU; masks use bit positions from the subtype's
// required-TLV list. requiredMask marks mandatory fields; seenMask can also
// include optional type 24 if present. expectedType identifies the first
// missing mandatory type, independent of wire order. For InvalidValue,
// seenMask includes the current type; for DuplicateRequired, it does not. The
// trace packs the first 16 structurally bounded TLV header types, earliest in
// the low byte;
// traceCount is the number of complete headers scanned before truncation, an
// outer length overrun, or the 128-header ceiling. It is collected before
// semantic parsing, so a semantic rejection retains later bounded types.
// A missing/empty list uses 0xff for tlvType, the first missing required type
// (or 0xff if none) for expectedType, and frame length for tlvOffset. This
// contains no addresses or TLV payload bytes.
struct ParseDiagnostics {
    TlvRejectReason reason;
    uint8_t subtype;
    uint8_t tlvType;
    uint8_t expectedType;
    size_t tlvOffset;
    size_t declaredLen;
    size_t availableLen;
    uint16_t seenMask;
    uint16_t requiredMask;
    uint16_t dataPathFlags;
    uint16_t dataPathExtFlags;
    uint16_t dataPathOptionsLength;
    uint16_t dataPathOffset;
    uint8_t dataPathFlagsPresent;
    uint8_t dataPathExtFlagsPresent;
    uint8_t dataPathOptionsLengthPresent;
    DataPathRejectStage dataPathRejectStage;
    uint64_t tlvTypeTraceLo;
    uint64_t tlvTypeTraceHi;
    uint16_t traceCount;
};

struct ActionFrameInfo {
    uint16_t frameControl;
    uint32_t phyTx;
    uint32_t targetTx;
    uint8_t subtype;
    uint8_t version;
    uint8_t tlvCount;
};

// Parse one complete 802.11 MPDU (no radiotap prefix, no FCS). This validates
// the AWDL PSF/MIF action envelope and bounded TLV layouts. It intentionally
// returns no peer addresses, host names, raw TLV values, or user data.
// Unknown TLV types are skipped by their checked length; unknown AWDL action
// types/subtypes and versions are rejected. No radio or interface is touched.
ParseStatus parseActionFrame(const uint8_t *frame, size_t length,
                             ActionFrameInfo *out,
                             ParseDiagnostics *diagnostics = nullptr);

} // namespace NativeAwdl

#endif
