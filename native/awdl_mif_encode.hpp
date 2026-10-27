// SPDX-License-Identifier: GPL-2.0-only
#ifndef NATIVE_AWDL_MIF_ENCODE_HPP
#define NATIVE_AWDL_MIF_ENCODE_HPP

#include "awdl_action_encode.hpp"

namespace NativeAwdl {

// This encoder accepts one ASCII DNS host label. The fixed compressed suffix
// in the ARPA value supplies `.local`; the caller must not include that suffix.
constexpr size_t kMaximumArpaHostLabelLength = 63;
constexpr size_t kMaximumEncodedMifLength =
    kMaximumEncodedPsfLength + kMaximumArpaHostLabelLength + 7;

enum class MifEncodeStatus : uint8_t {
    Ok,
    InvalidArgument,
    InvalidHostname,
    InvalidSourceAddress,
    InvalidElectionAddress,
    InvalidChannelSequence,
    InvalidSyncFields,
    InvalidElectionFields,
    InvalidHtCapabilities,
    InvalidVersion,
    BufferTooSmall,
    InvalidBaseFrame
};

// All radio/runtime values remain mandatory through the embedded PsfInput.
// hostname is a caller-supplied, uncompressed ASCII hostname label without
// `.local`; hostnameLength is explicit and the input need not be NUL-terminated.
struct MifInput {
    PsfInput psf;
    const char *hostname;
    size_t hostnameLength;
};

// Encode one complete public AWDL MIF Action MPDU. The existing PSF serializer
// supplies all shared fields; this function adds the required ARPA TLV and
// changes the AWDL subtype to MIF. Data Path State remains the PSF serializer's
// empty, zero-flags value. On every failure, *written is zero and output is
// left untouched.
MifEncodeStatus encodeMif(const MifInput *input, uint8_t *output,
                          size_t capacity, size_t *written);

} // namespace NativeAwdl

#endif
