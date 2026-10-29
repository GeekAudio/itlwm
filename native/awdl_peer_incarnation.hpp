// SPDX-License-Identifier: GPL-2.0-only
#ifndef NATIVE_AWDL_PEER_INCARNATION_HPP
#define NATIVE_AWDL_PEER_INCARNATION_HPP

#include <stdint.h>

namespace NativeAwdlPeerIdentity {

// A table-lifetime opaque ID source. It intentionally has no reset operation:
// identity values cannot be reused after entries or epochs are cleared.
class TokenSequence {
public:
    explicit TokenSequence(uint64_t last = 0) : last_(last) {}

    bool allocate(uint64_t *output)
    {
        if (!output || last_ == UINT64_MAX)
            return false;
        const uint64_t next = last_ + 1;
        if (next == 0)
            return false;
        last_ = next;
        *output = next;
        return true;
    }

private:
    uint64_t last_;
};

// Revisions are local to a peer incarnation. Overflow leaves the old value
// intact, so the caller can reject transactionally without damaging the entry.
inline bool advanceRevision(uint64_t *revision)
{
    if (!revision || *revision == UINT64_MAX)
        return false;
    ++*revision;
    return *revision != 0;
}

} // namespace NativeAwdlPeerIdentity

#endif // NATIVE_AWDL_PEER_INCARNATION_HPP
