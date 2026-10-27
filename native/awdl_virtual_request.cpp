// SPDX-License-Identifier: GPL-2.0-only
#include "awdl_virtual_request.hpp"

#include <string.h>

namespace NativeAwdl {
namespace {

constexpr size_t kRequestMinimumLength = 32;
constexpr size_t kVersionOffset = 0;
constexpr size_t kAddressOffset = 4;
constexpr size_t kRoleOffset = 12;
constexpr uint32_t kRequestVersion = 1;
constexpr uint32_t kAwdlRole = 6;

uint32_t readLe32(const uint8_t *bytes)
{
    return static_cast<uint32_t>(bytes[0]) |
           (static_cast<uint32_t>(bytes[1]) << 8) |
           (static_cast<uint32_t>(bytes[2]) << 16) |
           (static_cast<uint32_t>(bytes[3]) << 24);
}

bool validUnicastAddress(const uint8_t *address)
{
    uint8_t aggregate = 0;
    for (size_t i = 0; i < 6; ++i)
        aggregate |= address[i];
    return aggregate != 0 && (address[0] & 1) == 0;
}

} // namespace

VirtualRequestStatus parseAwdlVirtualRequest(const uint8_t *bytes, size_t length,
                                             VirtualRequestInfo *out)
{
    if (out == nullptr)
        return VirtualRequestStatus::InvalidArgument;
    memset(out, 0, sizeof(*out));
    if (bytes == nullptr)
        return VirtualRequestStatus::InvalidArgument;
    if (length < kRequestMinimumLength)
        return VirtualRequestStatus::Truncated;
    if (readLe32(bytes + kVersionOffset) != kRequestVersion)
        return VirtualRequestStatus::UnsupportedVersion;

    const uint32_t role = readLe32(bytes + kRoleOffset);
    if (role != kAwdlRole)
        return VirtualRequestStatus::UnsupportedRole;
    if (!validUnicastAddress(bytes + kAddressOffset))
        return VirtualRequestStatus::InvalidAddress;

    memcpy(out->address, bytes + kAddressOffset, sizeof(out->address));
    out->role = role;
    return VirtualRequestStatus::Ok;
}

} // namespace NativeAwdl
