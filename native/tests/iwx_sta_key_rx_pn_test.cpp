#include "../iwx_sta_key_rx_pn.hpp"

#include <cassert>
#include <cstdio>
#include <cstring>

using IwxStaKeyRxPn::Encoded;
using IwxStaKeyRxPn::Status;

static void testV3ContiguousAndMaxTid()
{
    uint64_t pn[16] = {};
    pn[0] = 0x010203040506ULL;
    pn[6] = 0x010203040507ULL;
    pn[15] = 0x010203040506ULL;
    Encoded out{};
    assert(IwxStaKeyRxPn::encodeCcmp(pn, 16, 3, &out) == Status::kReady);
    assert(out.maximumPn == pn[6] && out.maximumTid == 6 && out.apiVersion == 3);
    const uint8_t expected[16] = {7, 5, 4, 3, 2, 1};
    assert(std::memcmp(out.bytes, expected, sizeof(expected)) == 0);
}

static void testV2HoleAndZeroFill()
{
    uint64_t pn[16] = {};
    pn[9] = 0x060504030201ULL;
    Encoded out{};
    assert(IwxStaKeyRxPn::encodeCcmp(pn, 16, 2, &out) == Status::kReady);
    assert(out.maximumPn == pn[9] && out.maximumTid == 9 && out.apiVersion == 2);
    const uint8_t expected[16] = {1, 2, 0, 0, 3, 4, 5, 6};
    assert(std::memcmp(out.bytes, expected, sizeof(expected)) == 0);
}

static void testZeroAndRejectedInputs()
{
    uint64_t pn[16] = {};
    Encoded out{};
    assert(IwxStaKeyRxPn::encodeCcmp(pn, 16, 3, &out) == Status::kReady);
    assert(out.maximumPn == 0 && out.maximumTid == 0);
    for (uint8_t byte : out.bytes) assert(byte == 0);
    assert(IwxStaKeyRxPn::encodeCcmp(pn, 16, 99, &out) ==
           Status::kUnsupportedApi);
    assert(IwxStaKeyRxPn::encodeCcmp(pn, 15, 3, &out) ==
           Status::kInvalidArgument);
    assert(IwxStaKeyRxPn::encodeCcmp(nullptr, 16, 3, &out) ==
           Status::kInvalidArgument);
    assert(IwxStaKeyRxPn::encodeCcmp(pn, 16, 3, nullptr) ==
           Status::kInvalidArgument);
    pn[4] = IwxStaKeyRxPn::kCcmpPnMask + 1;
    assert(IwxStaKeyRxPn::encodeCcmp(pn, 16, 3, &out) ==
           Status::kPnOutOfRange);
}

int main()
{
    testV3ContiguousAndMaxTid();
    testV2HoleAndZeroFill();
    testZeroAndRejectedInputs();
    std::puts("ADD_STA_KEY CCMP RX sequence encoding tests PASS");
}
