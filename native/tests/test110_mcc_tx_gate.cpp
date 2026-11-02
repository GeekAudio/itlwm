#include "../iwx_mcc_refresh_policy.hpp"
#include <cassert>
#include <cstdint>
#include <initializer_list>

using IwxMccRefreshPolicy::directedDataChannel6TxAllowed;

int main()
{
    constexpr uint32_t twoGHz = 1u << 0;
    constexpr uint32_t passive = 1u << 9;
    constexpr uint32_t dfs = 1u << 10;
    constexpr uint32_t noIr = 1u << 11;
    constexpr uint32_t active = twoGHz | (1u << 1);

    // IORegistry OSNumber values are 64-bit. Reject high-bit values before
    // any narrowing; their low 32 bits must not alias a valid status/profile.
    constexpr uint64_t highStatusAlias = (uint64_t{1} << 32) + 1U;
    constexpr uint64_t highCountAlias = (uint64_t{1} << 32) + 51U;
    assert(!IwxMccRefreshPolicy::mccTxPropertyValuesFitUint32(
        highStatusAlias, 51));
    assert(!IwxMccRefreshPolicy::mccTxPropertyValuesFitUint32(
        1, highCountAlias));
    assert(IwxMccRefreshPolicy::mccTxPropertyValuesFitUint32(1, 51));

    // NEW and SAME are valid only with a complete returned profile.
    assert(directedDataChannel6TxAllowed(0, 51, 6, 2437, active,
        twoGHz, passive, dfs, noIr));
    assert(directedDataChannel6TxAllowed(1, 51, 6, 2437, active,
        twoGHz, passive, dfs, noIr));
    assert(!directedDataChannel6TxAllowed(1, 0, 6, 2437, active,
        twoGHz, passive, dfs, noIr));
    assert(!directedDataChannel6TxAllowed(0, 50, 6, 2437, active,
        twoGHz, passive, dfs, noIr));
    assert(!directedDataChannel6TxAllowed(1, 1, 6, 2437, active,
        twoGHz, passive, dfs, noIr));

    // INVALID, NVM_DISABLED, ILLEGAL and unknown statuses remain fail-closed.
    for (uint32_t status : {2u, 3u, 4u, 5u, UINT32_MAX})
        assert(!directedDataChannel6TxAllowed(status, 51, 6, 2437, active,
            twoGHz, passive, dfs, noIr));

    // A valid SAME status cannot override any live channel transmit block.
    assert(!directedDataChannel6TxAllowed(1, 51, 6, 2437, active | passive,
        twoGHz, passive, dfs, noIr));
    assert(!directedDataChannel6TxAllowed(1, 51, 6, 2437, active | dfs,
        twoGHz, passive, dfs, noIr));
    assert(!directedDataChannel6TxAllowed(1, 51, 6, 2437, active | noIr,
        twoGHz, passive, dfs, noIr));
    assert(!directedDataChannel6TxAllowed(1, 51, 11, 2462, active,
        twoGHz, passive, dfs, noIr));
    assert(!directedDataChannel6TxAllowed(1, 51, 6, 2437, 0,
        twoGHz, passive, dfs, noIr));
}
