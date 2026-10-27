// SPDX-License-Identifier: GPL-2.0-only
#ifndef NATIVE_AWDL_VIRTUAL_REQUEST_HPP
#define NATIVE_AWDL_VIRTUAL_REQUEST_HPP

#include <stddef.h>
#include <stdint.h>

namespace NativeAwdl {

enum class VirtualRequestStatus : uint8_t {
    Ok,
    InvalidArgument,
    Truncated,
    UnsupportedVersion,
    UnsupportedRole,
    InvalidAddress
};

struct VirtualRequestInfo {
    uint8_t address[6];
    uint32_t role;
};

// Decode the Tahoe apple80211_virt_if_create_data prefix used by the native
// VIRTUAL_IF_CREATE request. This is an offline parser only: it does not
// allocate or register an IO80211VirtualInterface.
VirtualRequestStatus parseAwdlVirtualRequest(const uint8_t *bytes, size_t length,
                                             VirtualRequestInfo *out);

} // namespace NativeAwdl

#endif
