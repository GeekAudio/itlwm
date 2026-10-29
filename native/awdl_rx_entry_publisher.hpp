// SPDX-License-Identifier: GPL-2.0-only
#ifndef NATIVE_AWDL_RX_ENTRY_PUBLISHER_HPP
#define NATIVE_AWDL_RX_ENTRY_PUBLISHER_HPP

#include <stdint.h>

namespace NativeAwdlRxEntryPublisher {

constexpr const char *kSnapshotBegin = "NativeP2PRxEntrySnapshotBegin";
constexpr const char *kSnapshotEnd = "NativeP2PRxEntrySnapshotEnd";

inline uint32_t nextAttemptVersion(uint32_t previous)
{
    uint32_t next = previous + 2u;
    if (next == 0 || (next & 1u))
        next = 2u;
    return next;
}

// The caller serializes publication on the main gate. A failed Begin leaves
// the old complete snapshot untouched. Any later failure leaves Begin ahead
// of the old End, so readers reject the partial body. Published state changes
// only after every body property and End have succeeded.
template <typename Snapshot, typename Writer, typename BodyWriter>
bool publish(uint32_t &attemptVersion, uint32_t &publishedVersion,
             bool &publishedOnce, Snapshot &publishedSnapshot,
             const Snapshot &current, Writer &write, BodyWriter body)
{
    const uint32_t version = nextAttemptVersion(attemptVersion);
    attemptVersion = version;
    if (!write(kSnapshotBegin, version))
        return false;
    if (!body())
        return false;
    if (!write(kSnapshotEnd, version))
        return false;

    publishedSnapshot = current;
    publishedVersion = version;
    publishedOnce = true;
    return true;
}

} // namespace NativeAwdlRxEntryPublisher

#endif
