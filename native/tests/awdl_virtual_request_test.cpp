// SPDX-License-Identifier: GPL-2.0-only
#include "../awdl_virtual_request.hpp"

#include <assert.h>
#include <string.h>

namespace {

void writeLe32(uint8_t *bytes, uint32_t value)
{
    bytes[0] = static_cast<uint8_t>(value);
    bytes[1] = static_cast<uint8_t>(value >> 8);
    bytes[2] = static_cast<uint8_t>(value >> 16);
    bytes[3] = static_cast<uint8_t>(value >> 24);
}

void makeRequest(uint8_t *bytes, uint32_t role, const uint8_t *address)
{
    memset(bytes, 0, 32);
    writeLe32(bytes, 1);
    memcpy(bytes + 4, address, 6);
    writeLe32(bytes + 12, role);
    memcpy(bytes + 16, "awdl0", 6);
}

} // namespace

int main()
{
    using NativeAwdl::VirtualRequestInfo;
    using NativeAwdl::VirtualRequestStatus;

    const uint8_t address[6] = {0x02, 0x11, 0x22, 0x33, 0x44, 0x55};
    uint8_t request[32];
    VirtualRequestInfo info;

    makeRequest(request, 6, address);
    assert(NativeAwdl::parseAwdlVirtualRequest(request, sizeof(request), &info) ==
           VirtualRequestStatus::Ok);
    assert(info.role == 6);
    assert(memcmp(info.address, address, sizeof(address)) == 0);

    assert(NativeAwdl::parseAwdlVirtualRequest(request, sizeof(request) - 1, &info) ==
           VirtualRequestStatus::Truncated);
    assert(NativeAwdl::parseAwdlVirtualRequest(nullptr, sizeof(request), &info) ==
           VirtualRequestStatus::InvalidArgument);
    assert(NativeAwdl::parseAwdlVirtualRequest(request, sizeof(request), nullptr) ==
           VirtualRequestStatus::InvalidArgument);

    writeLe32(request, 2);
    assert(NativeAwdl::parseAwdlVirtualRequest(request, sizeof(request), &info) ==
           VirtualRequestStatus::UnsupportedVersion);

    writeLe32(request, 1);
    writeLe32(request + 12, 5); // P2P GO is not the AWDL role.
    assert(NativeAwdl::parseAwdlVirtualRequest(request, sizeof(request), &info) ==
           VirtualRequestStatus::UnsupportedRole);
    writeLe32(request + 12, 7); // Soft AP is also a separate interface role.
    assert(NativeAwdl::parseAwdlVirtualRequest(request, sizeof(request), &info) ==
           VirtualRequestStatus::UnsupportedRole);

    writeLe32(request + 12, 6);
    memset(request + 4, 0, 6);
    assert(NativeAwdl::parseAwdlVirtualRequest(request, sizeof(request), &info) ==
           VirtualRequestStatus::InvalidAddress);
    const uint8_t multicast[6] = {0x01, 0, 0, 0, 0, 1};
    memcpy(request + 4, multicast, 6);
    assert(NativeAwdl::parseAwdlVirtualRequest(request, sizeof(request), &info) ==
           VirtualRequestStatus::InvalidAddress);

    return 0;
}
